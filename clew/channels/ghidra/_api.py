"""Low-level PyGhidra helpers shared by the enumeration and dataflow stages.

Everything that touches the Ghidra/Java API and is needed by *both* stages
lives here, so the two stages cannot drift on how a program is opened, how the
decompiler is configured, or how a string is read out of memory.

The JVM boot (`pyghidra.start()`) is process-wide and one-shot; `start()` below
is idempotent so any entry point can call it without caring who ran first.

Java-interop notes that the rest of the package relies on:
  * Ghidra objects are JPype proxies. Java getters are methods
    (`f.getName()`), not attributes, and Java `null` arrives as Python `None`.
  * Java iterators are exposed through `iter_java`, which tolerates both the
    `hasNext()/next()` protocol and the Python-iterable wrappers JPype
    sometimes provides for the same type.
  * Addresses are Java objects; `.getOffset()` is the integer VA. VAs are kept
    as plain ints everywhere above this module.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from clew.channels import BackendUnavailable

# Validated against this Ghidra release. Companion to callsites.BN_PINS on the
# Binary Ninja side; bump when re-validating against a new Ghidra.
GHIDRA_VALIDATED_VERSION = "12.1.2"

# Decompiler timeout per function, in seconds. A hostile or merely huge function
# can wedge the decompiler; on timeout Ghidra returns a result whose
# decompileCompleted() is False and whose HighFunction is None, which the
# callers treat as "this function yields no call sites" rather than as an error.
DECOMPILE_TIMEOUT = 60

# Raw bytes read when falling back to a manual string sniff.
_STRING_READ_BYTES = 512

_started = False


class GhidraStartupError(BackendUnavailable):
    """The JVM or the Ghidra install could not be brought up."""


def preflight() -> None:
    """Check the backend *could* run, without booting anything.

    Split out of `start()` so the pipeline can validate the backend before it
    spends minutes on capa and FLOSS. Cheap: an import check and two path
    checks, no JVM.
    """
    try:
        import pyghidra  # noqa: F401
    except Exception as exc:  # noqa: BLE001 - surface any import/link failure
        raise GhidraStartupError(
            "Could not import pyghidra. Install it into this venv "
            "(pip install pyghidra) -- see docs/ghidra_headless_setup.md."
        ) from exc

    install = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install:
        raise GhidraStartupError(
            "GHIDRA_INSTALL_DIR is not set. Point it at a Ghidra 12.0+ install "
            "-- see docs/ghidra_headless_setup.md."
        )
    if not Path(install, "support", "analyzeHeadless").exists():
        raise GhidraStartupError(
            f"GHIDRA_INSTALL_DIR={install} does not look like a Ghidra install "
            f"(no support/analyzeHeadless)."
        )


def start() -> None:
    """Boot the JVM and Ghidra once per process (idempotent).

    Requires GHIDRA_INSTALL_DIR, and a real JDK (not a JRE) on JAVA_HOME or
    PATH -- Ghidra's own launcher rejects a JRE, and the failure it reports
    ("returned non-zero exit status 1") names neither cause, so both are
    checked here where a useful message can still be produced.
    """
    global _started
    if _started:
        return
    preflight()
    import pyghidra

    try:
        pyghidra.start()
    except Exception as exc:  # noqa: BLE001
        raise GhidraStartupError(
            f"Ghidra failed to launch: {exc}. Ghidra needs a full JDK 21+; a JRE "
            f"is not enough (its launcher exits non-zero without saying so). "
            f"Set JAVA_HOME to a JDK -- see docs/ghidra_headless_setup.md."
        ) from exc
    _started = True


def ghidra_version() -> str:
    """The running Ghidra's version string, for provenance."""
    try:
        from ghidra.framework import Application

        return str(Application.getApplicationVersion())
    except Exception:  # noqa: BLE001
        return "unknown"


def iter_java(it):
    """Iterate a Java iterator/iterable uniformly.

    JPype exposes some Ghidra collections as Python iterables and others only
    through hasNext()/next(); accepting both keeps call sites free of the
    distinction.
    """
    if it is None:
        return
    if hasattr(it, "hasNext"):
        while it.hasNext():
            yield it.next()
        return
    yield from it


class Decompiler:
    """A per-program DecompInterface with a HighFunction cache.

    One caller function usually holds several call sites of interest, so
    decompiling per call site is the classic performance mistake here; results
    are cached by function entry point. `openProgram` is expensive and is done
    once. Callers must `close()` (the decompiler is a separate native process).

    The "decompile" simplification style is required: the cheaper "normalize"
    and "register" styles skip the analysis that recovers CALL parameters, and
    parameters are the entire point of the dataflow bridge.
    """

    def __init__(self, program, timeout: int = DECOMPILE_TIMEOUT):
        from ghidra.app.decompiler import DecompileOptions, DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        self._timeout = timeout
        self._monitor = ConsoleTaskMonitor()
        self._ifc = DecompInterface()
        self._ifc.setOptions(DecompileOptions())
        self._ifc.setSimplificationStyle("decompile")
        if not self._ifc.openProgram(program):
            raise GhidraStartupError(
                f"Ghidra decompiler failed to open the program: {self._ifc.getLastMessage()}"
            )
        self._cache: dict[int, object] = {}

    def high_function(self, func):
        """The decompiled HighFunction for `func`, or None.

        None covers both "the decompiler timed out" and "it failed", which the
        callers treat identically: the function contributes nothing. Checking
        decompileCompleted() matters -- without it a timeout is indistinguishable
        from a function that genuinely has no calls, and call sites vanish
        silently.
        """
        key = func.getEntryPoint().getOffset()
        if key in self._cache:
            return self._cache[key]
        high = None
        try:
            res = self._ifc.decompileFunction(func, self._timeout, self._monitor)
            if res is not None and res.decompileCompleted():
                high = res.getHighFunction()
        except Exception:  # noqa: BLE001 - one bad function must not sink the run
            high = None
        self._cache[key] = high
        return high

    def close(self) -> None:
        try:
            self._ifc.dispose()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self) -> "Decompiler":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def call_ops():
    """The P-Code opcodes that represent a call.

    CALL is a direct call, CALLIND an indirect one (the GetProcAddress-resolved
    shape). CALLOTHER is Ghidra's escape hatch for processor-specific
    operations and carries no argument list, so it is deliberately excluded.
    """
    from ghidra.program.model.pcode import PcodeOp

    return (PcodeOp.CALL, PcodeOp.CALLIND)


def find_call_op(high_function, addr):
    """The CALL/CALLIND PcodeOp at `addr`, or None.

    Ghidra indexes P-Code by address, so this is a lookup rather than the
    linear scan over every SSA instruction the Binary Ninja backend needs. One
    address can carry several ops; only the call is wanted.
    """
    if high_function is None:
        return None
    ops = call_ops()
    try:
        for op in iter_java(high_function.getPcodeOps(addr)):
            if op.getOpcode() in ops:
                return op
    except Exception:  # noqa: BLE001
        return None
    return None


def call_argument(op, parameter_index: int):
    """The varnode for `parameter_index` of a call op, or None.

    Input 0 of a CALL is the call *target*, so arguments start at 1. Returning
    None when the decompiler recovered fewer arguments than asked for is the
    conservative branch: it means Ghidra has no prototype for the callee, and
    guessing an index there is how a silently-wrong value gets emitted.
    """
    if op is None:
        return None
    if parameter_index + 1 >= op.getNumInputs():
        return None
    return op.getInput(parameter_index + 1)


def argument_count(op) -> int:
    """How many arguments the decompiler recovered for this call."""
    return 0 if op is None else max(0, op.getNumInputs() - 1)


def to_address(program, offset: int):
    """An int VA as a Ghidra Address in the default space, or None."""
    try:
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
    except Exception:  # noqa: BLE001
        return None


# Shortest run the byte-sniffing tiers will accept as a string. Below this,
# an arbitrary pointer's bytes decode as a "valid" short string far too often.
_MIN_SNIFFED_LENGTH = 4


def read_string_at(program, offset: int) -> Optional[tuple[str, str]]:
    """Read a string at VA `offset`. Returns (value, encoding) or None.

    Three tiers, mirroring the Binary Ninja backend's _read_string_at:
      1. a string Ghidra's analysis already defined here (best: it respects
         what the string analyzer decided),
      2. a raw read decoded as NUL-terminated ASCII,
      3. the same bytes decoded UTF-16LE.
    Tiers 2 and 3 exist because malware routinely keeps strings in sections the
    string analyzer skipped. Each tier is guarded separately: a bad address
    must yield None, never raise into the bridge.

    The byte-sniffing tiers are deliberately stricter than tier 1. Many
    arguments are pointers to code or to a heap object rather than to text
    (a vectored exception handler, a window handle), and decoding those bytes
    UTF-16LE with errors="ignore" yields a run of CJK codepoints that passes
    `str.isprintable()` -- producing confident nonsense like a handler address
    "recovered" as a string. So tiers 2 and 3 accept printable *ASCII* only and
    require a minimum length, and neither runs against executable memory.
    Exotic encodings are still recovered, but only via tier 1, where Ghidra's
    string analyzer vouched for them.
    """
    from ghidra.program.model.data import StringDataInstance

    addr = to_address(program, offset)
    if addr is None:
        return None

    try:
        data = program.getListing().getDataContaining(addr)
        if data is not None and StringDataInstance.isString(data):
            value = StringDataInstance.getStringDataInstance(data).getStringValue()
            if value:
                text = str(value)
                name = str(data.getDataType().getName()).lower()
                return (text, "utf16" if "unicode" in name else "ascii")
    except Exception:  # noqa: BLE001
        pass

    if _is_executable(program, addr):
        # A pointer into code is a function pointer, not a string.
        return None

    raw = _read_bytes(program, addr, _STRING_READ_BYTES)
    if not raw:
        return None

    end = raw.find(b"\x00")
    if end >= _MIN_SNIFFED_LENGTH:
        text = _printable_ascii(raw[:end])
        if text:
            return (text, "ascii")

    wide_end = raw.find(b"\x00\x00")
    chunk = raw[: wide_end if wide_end != -1 else len(raw)]
    if len(chunk) >= _MIN_SNIFFED_LENGTH * 2:
        # UTF-16LE text whose code units are all ASCII has a zero in every odd
        # byte; requiring that is what separates real wide strings from
        # arbitrary bytes that merely decode without raising.
        if all(b == 0 for b in chunk[1::2]):
            text = _printable_ascii(chunk[0::2])
            if text:
                return (text, "utf16")
    return None


def _printable_ascii(raw: bytes) -> Optional[str]:
    """`raw` as a printable-ASCII string, or None if it is not one."""
    if len(raw) < _MIN_SNIFFED_LENGTH:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not text.isprintable():
        return None
    return text


def _is_executable(program, addr) -> bool:
    """Whether `addr` falls in an executable memory block."""
    try:
        block = program.getMemory().getBlock(addr)
        return bool(block is not None and block.isExecute())
    except Exception:  # noqa: BLE001
        return False


def _read_bytes(program, addr, count: int) -> bytes:
    """`count` bytes at `addr`, truncated at the end of the mapped block."""
    try:
        import jpype

        buf = jpype.JArray(jpype.JByte)(count)
        read = program.getMemory().getBytes(addr, buf)
        # Java bytes are signed; mask back to 0..255.
        return bytes((b & 0xFF) for b in buf[:read])
    except Exception:  # noqa: BLE001 - unmapped/partial reads are expected
        return b""


def pointer_size(program) -> int:
    """Pointer stride for walking an array of pointers."""
    try:
        return int(program.getDefaultPointerSize())
    except Exception:  # noqa: BLE001
        return 4  # PE32

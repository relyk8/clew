"""Channel 2: Ghidra call-site enumeration.

The Ghidra counterpart to `clew.channels.binaryninja.callsites`, emitting the
same `CallSite` / `BNCallSites` intermediate artifact so the rest of the
pipeline cannot tell which backend ran.

Enumeration strategy (validated against al-khaser on Ghidra 12.1.2, diffed
against the Binary Ninja 4.2.6455 fixture): a PE import in Ghidra can be
reached through up to three distinct addresses, and a call reference may land
on any of them --

    1. the external function in the <EXTERNAL> namespace,
    2. the external location's linkage address (the IAT slot),
    3. a thunk function in .text (the `jmp [IAT]` stub).

so all three are gathered as call targets and references to each are followed.
This is the Ghidra analogue of the Binary Ninja backend's hard-won lesson that
the ImportAddressSymbol, not the ImportedFunctionSymbol, carries the xrefs.

Two things are simpler here than on the Binary Ninja side. Ghidra's PE loader
identifies import thunks structurally, so `Function.isThunk()` replaces that
backend's basic-block-counting heuristic. And ordinal imports arrive already
labelled `Ordinal_<n>`, which maps straight onto the schema's `ordinal`
resolution.

One thing is deliberately *less* resolved than Binary Ninja: for an ordinal
import BN substitutes the well-known export name (WS2_32 Ordinal_115 ->
WSAStartup) from a built-in table. Ghidra ships no such table, so this backend
records `api_resolution == "ordinal"` with the ordinal number and keeps the
`Ordinal_<n>` label as the name. That is what the schema's `ordinal` value is
for, and it is honest about what was actually recovered; a name table can be
layered on later without changing the artifact shape.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import tempfile
from pathlib import Path
from typing import Optional

from clew.channels.binaryninja.callsites import (
    RESOLUTION_GETPROCADDRESS,
    RESOLUTION_IMPORT,
    RESOLUTION_ORDINAL,
    BNCallSites,
    CallSite,
)
from clew.channels.ghidra import _api

# Validated against this Ghidra release; companion to the BN backend's BN_PINS.
GHIDRA_PINS: dict[str, str] = {
    "version": _api.GHIDRA_VALIDATED_VERSION,
    "backend": "pyghidra",
}

# Ghidra's label for an import that carries no name, only an ordinal.
_ORDINAL_RE = re.compile(r"^Ordinal_(\d+)$")

# Names that are Ghidra bookkeeping rather than real call targets.
_SKIP_PREFIXES = ("switchD", "case_", "__imp_switch")


class GhidraError(Exception):
    """Base error for the Ghidra backend."""


class GhidraNotAvailableError(GhidraError):
    """Ghidra/PyGhidra could not be started. See docs/ghidra_headless_setup.md."""


class GhidraAnalysisError(GhidraError):
    """Ghidra opened the sample but analysis or enumeration failed."""


@contextlib.contextmanager
def open_program(sample: str | Path, *, analyze: bool = True):
    """Open `sample` in a throwaway Ghidra project, analysed, as a Program.

    The project is created under a temporary directory and discarded on exit:
    clew treats every run as a fresh analysis, and a persistent project would
    make results depend on what a previous run happened to leave behind. This
    is the Ghidra equivalent of `binaryninja.load()` +
    `update_analysis_and_wait()`, and like that pair it is paid once and shared
    by both stages.
    """
    import pyghidra

    _api.start()
    sample = Path(sample)
    if not sample.exists():
        raise GhidraAnalysisError(f"sample not found: {sample}")

    with tempfile.TemporaryDirectory(prefix="clew_ghidra_") as project_dir:
        try:
            project = pyghidra.open_project(project_dir, "clew", create=True)
        except Exception as exc:  # noqa: BLE001
            raise GhidraAnalysisError(f"could not create a Ghidra project: {exc}") from exc
        try:
            loader = pyghidra.program_loader().project(project).source(str(sample))
            with loader.load() as loaded:
                program = loaded.getPrimaryDomainObject()
                if analyze:
                    try:
                        pyghidra.analyze(program)
                    except Exception as exc:  # noqa: BLE001
                        raise GhidraAnalysisError(
                            f"Ghidra analysis failed for {sample}: {exc}"
                        ) from exc
                yield program
        except GhidraError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise GhidraAnalysisError(f"Ghidra failed to load {sample}: {exc}") from exc
        finally:
            with contextlib.suppress(Exception):
                project.close()


def run_ghidra_callsites(sample: str | Path) -> BNCallSites:
    """Open `sample` with Ghidra and enumerate API call sites (standalone path).

    The orchestrator should prefer `enumerate_with_program` against a program it
    already opened, so analysis is paid once for both stages.
    """
    sample = Path(sample)
    with open_program(sample) as program:
        return enumerate_with_program(
            program, sample_path=str(sample), sample_sha256=_sha256(sample)
        )


def enumerate_with_program(
    program,
    *,
    sample_path: str = "",
    sample_sha256: Optional[str] = None,
    decompiler: Optional[_api.Decompiler] = None,
) -> BNCallSites:
    """Enumerate call sites in an already-open, already-analysed Program.

    Mirrors `binaryninja.callsites.enumerate_with_view`. `program` MUST already
    be analysed; this neither opens the sample nor analyses it (the caller owns
    both). `decompiler` is optional and only used for GetProcAddress pairing --
    pass the orchestrator's shared instance so its HighFunction cache is reused
    by the dataflow stage rather than rebuilt.
    """
    sites = _collect_call_sites(program, decompiler)
    return BNCallSites(
        sample_path=sample_path,
        sample_sha256=sample_sha256,
        # The artifact field is named for the BN backend that defined it; it
        # carries whichever analyzer produced the record.
        bn_core_version=f"ghidra {_api.ghidra_version()}",
        call_sites=sites,
    )


# --- enumeration internals ---------------------------------------------------


def _collect_call_sites(program, decompiler) -> list[CallSite]:
    by_key: dict[tuple, CallSite] = {}

    function_manager = program.getFunctionManager()
    reference_manager = program.getReferenceManager()

    for address, name in _import_targets(program).items():
        api_name, resolution, ordinal = _classify(name)
        if not api_name:
            continue
        for ref in _api.iter_java(reference_manager.getReferencesTo(address)):
            call_site_va = _caller_reference(ref, function_manager)
            if call_site_va is None:
                continue
            va, caller = call_site_va
            key = (va, api_name)
            if key in by_key:
                continue
            by_key[key] = CallSite(
                api_name=api_name,
                call_site_va=va,
                function_va=caller.getEntryPoint().getOffset(),
                api_resolution=resolution,
                calling_convention=_calling_convention(caller),
                ordinal=ordinal,
            )

    for site in _getprocaddress_call_sites(program, decompiler):
        by_key.setdefault((site.call_site_va, site.api_name), site)

    return list(by_key.values())


def _import_targets(program) -> dict:
    """Every address a call to an imported API might target -> the API name.

    Covers all three shapes a PE import takes in Ghidra (external function,
    IAT/linkage address, thunk), because a call reference may land on any one
    of them and which one it is varies by how the compiler emitted the call.
    """
    targets = {}
    external_manager = program.getExternalManager()
    function_manager = program.getFunctionManager()

    for library in _api.iter_java(external_manager.getExternalLibraryNames()):
        for location in _api.iter_java(external_manager.getExternalLocations(library)):
            name = location.getLabel()
            if not name:
                continue
            function = location.getFunction()
            if function is not None:
                targets.setdefault(function.getEntryPoint(), name)
            linkage = location.getAddress()
            if linkage is not None:
                targets.setdefault(linkage, name)

    for function in _api.iter_java(function_manager.getFunctions(True)):
        if not function.isThunk():
            continue
        thunked = function.getThunkedFunction(True)
        if thunked is not None and thunked.isExternal():
            targets.setdefault(function.getEntryPoint(), thunked.getName())

    return targets


def _caller_reference(ref, function_manager):
    """(call_site_va, caller_function) for a call reference, or None.

    Filters out non-call references and references originating inside an import
    thunk -- the stub's own forwarding jump is not caller code, and counting it
    would attribute every call to the thunk instead of to the real caller.
    """
    try:
        ref_type = ref.getReferenceType()
        if not (ref_type.isCall() or ref_type.isIndirect()):
            return None
        from_address = ref.getFromAddress()
        caller = function_manager.getFunctionContaining(from_address)
    except Exception:  # noqa: BLE001
        return None
    if caller is None or caller.isThunk():
        return None
    return (from_address.getOffset(), caller)


def _classify(raw_name: str):
    """(api_name, resolution, ordinal|None) for an import label."""
    raw = str(raw_name or "").strip()
    name = _clean_name(raw)
    # The skip list is tested against the raw label as well as the cleaned one:
    # for a switch-table label the marker lives in the namespace
    # (switchD_004010a0::caseD_1), which _clean_name strips off on its way to
    # turning KERNEL32.DLL::CreateFileW into CreateFileW.
    if not name or name.startswith(_SKIP_PREFIXES) or raw.startswith(_SKIP_PREFIXES):
        return (None, None, None)
    match = _ORDINAL_RE.match(name)
    if match:
        return (name, RESOLUTION_ORDINAL, int(match.group(1)))
    return (name, RESOLUTION_IMPORT, None)


def _clean_name(raw) -> str:
    """Strip Ghidra's import decorations from a symbol label.

    Ghidra prefixes thunk labels with `thunk_` and may qualify a name with its
    library (`KERNEL32.DLL::CreateFileW`); neither belongs in the artifact.
    """
    name = str(raw or "").strip()
    if "::" in name:
        name = name.rsplit("::", 1)[-1]
    for prefix in ("thunk_", "__imp_", "_imp_"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
    return name


def _calling_convention(function) -> Optional[str]:
    try:
        return str(function.getCallingConventionName())
    except Exception:  # noqa: BLE001
        return None


def _getprocaddress_call_sites(program, decompiler) -> list[CallSite]:
    """Name the indirect calls that consume a GetProcAddress result.

    Same shallow strategy as the Binary Ninja backend: within one function,
    read the name argument of each GetProcAddress call, then attribute each
    later indirect call to the most recent preceding name. It names the call
    site; it does not trace the function pointer. Without a decompiler (the
    caller did not supply one) this contributes nothing rather than guessing.
    """
    if decompiler is None:
        return []

    function_manager = program.getFunctionManager()
    reference_manager = program.getReferenceManager()

    resolver_addresses = {
        address
        for address, name in _import_targets(program).items()
        if "GetProcAddress" in str(name or "")
    }
    if not resolver_addresses:
        return []

    callers = set()
    for address in resolver_addresses:
        for ref in _api.iter_java(reference_manager.getReferencesTo(address)):
            found = _caller_reference(ref, function_manager)
            if found is not None:
                callers.add(found[1].getEntryPoint().getOffset())

    sites: list[CallSite] = []
    for entry in callers:
        function = function_manager.getFunctionAt(_api.to_address(program, entry))
        if function is None:
            continue
        sites.extend(
            _pair_resolver_calls(program, function, resolver_addresses, decompiler)
        )
    return sites


def _pair_resolver_calls(program, function, resolver_addresses, decompiler) -> list[CallSite]:
    from ghidra.program.model.pcode import PcodeOp

    high = decompiler.high_function(function)
    if high is None:
        return []

    resolver_offsets = {a.getOffset() for a in resolver_addresses}
    # (address, is_resolver, name_or_None) in address order, so "most recent
    # preceding GetProcAddress" is a single forward pass.
    events = []
    for op in _api.iter_java(high.getPcodeOps()):
        opcode = op.getOpcode()
        if opcode not in (PcodeOp.CALL, PcodeOp.CALLIND):
            continue
        address = op.getSeqnum().getTarget().getOffset()
        target = op.getInput(0)
        is_resolver = False
        try:
            if target is not None and target.isAddress():
                is_resolver = target.getAddress().getOffset() in resolver_offsets
        except Exception:  # noqa: BLE001
            is_resolver = False
        if is_resolver:
            events.append((address, True, _resolver_name(program, op)))
        elif opcode == PcodeOp.CALLIND:
            events.append((address, False, None))

    sites = []
    pending: Optional[str] = None
    for address, is_resolver, name in sorted(events):
        if is_resolver:
            pending = name
            continue
        if pending:
            sites.append(
                CallSite(
                    api_name=pending,
                    call_site_va=address,
                    function_va=function.getEntryPoint().getOffset(),
                    api_resolution=RESOLUTION_GETPROCADDRESS,
                    calling_convention=_calling_convention(function),
                )
            )
    return sites


def _resolver_name(program, op) -> Optional[str]:
    """The lpProcName argument (index 1) of a GetProcAddress call, as a string."""
    from clew.channels.ghidra.dataflow import resolve_constants

    argument = _api.call_argument(op, 1)
    if argument is None:
        return None
    for value in resolve_constants(program, argument):
        found = _api.read_string_at(program, value)
        if found:
            return found[0]
    return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

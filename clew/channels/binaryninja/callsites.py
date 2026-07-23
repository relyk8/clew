"""Channel 2: Binary Ninja call-site enumeration.

Wraps headless Binary Ninja (called in-process via the `binaryninja` API,
not via subprocess) and enumerates every Windows-API call site in a PE32
sample. Channel 2 is the *call-site* channel: it contributes the
`evidence.channels == ["bn_xref"]` half of a clew record — *where* an API
is called and *how* it was resolved — never the string values that flow
into those calls (that is Channel 1 / FLOSS) and never the dataflow that
joins the two (that is Unit 4, `clew/channels/binaryninja/dataflow.py`).

Resolution modes detected in v1 (maps onto the schema `api_resolution`
enum):

    import          -> statically imported via the IAT
    getprocaddress  -> resolved at runtime via GetProcAddress (named arg
                       recovered) or an equivalent named resolver
    ordinal         -> imported / resolved by ordinal rather than name

The schema's fourth value, `hashed` (FormBook / Carbanak-style API-name
hashing), is deliberately NOT detected here. v1 reserves the enum value
but Channel 2 produces no records with it; hash-based resolution is a v2
item. A call we can see structurally but cannot name (an indirect call
through a register with no recoverable name) is recorded with
resolution `unknown` in the intermediate JSON and dropped before any
schema mapping, rather than guessed at.

Output: this module produces an *intermediate* artifact (BNCallSites ->
JSON), NOT finished clew schema records. It has no values, no dataflow,
no comparison operators — those fields get filled by later units once
FLOSS values and MLIL dataflow exist to fill them. The intermediate JSON
is independently testable and is the clean input to Unit 4's bridge.
A thin `to_partial_candidates()` helper is provided for the eventual
schema mapping, but it emits call-site stubs only and is not the
module's primary product.

Orchestration note: load() opens the view with analysis enabled and
waits for it to finish (update_analysis_and_wait) before enumeration;
MLIL is required to classify call sites and is not available until
analysis completes. The Enterprise floating-license checkout is handled
by the caller (or by run_bn_callsites when run_license_checkout=True) via
binaryninja.enterprise.LicenseCheckout; see
docs/binary_ninja_headless_setup.md.

Version pinning: BN's analysis output can shift across releases; BN_PINS
records the currently-validated core version. Bump when re-validating.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Validated against a headless Binary Ninja 4.2.6455 Ultimate install.
# Bump when re-validating against a new BN release.
BN_PINS: dict[str, str] = {
    "core_version": "4.2.6455",
    "edition": "Ultimate",
}

# The schema api_resolution values this channel can emit in v1.
# "hashed" is reserved by the schema but never produced here (v2 item).
RESOLUTION_IMPORT = "import"
RESOLUTION_GETPROCADDRESS = "getprocaddress"
RESOLUTION_ORDINAL = "ordinal"
RESOLUTION_UNKNOWN = "unknown"  # intermediate-only; dropped before schema mapping

V1_SCHEMA_RESOLUTIONS = frozenset(
    {RESOLUTION_IMPORT, RESOLUTION_GETPROCADDRESS, RESOLUTION_ORDINAL}
)


# --- errors (mirror capa.py / floss.py hierarchy) ----------------------------


class BNError(Exception):
    """Base error for Channel 2."""


class BNNotAvailableError(BNError):
    """The `binaryninja` module could not be imported, or no license could
    be checked out. See docs/binary_ninja_headless_setup.md."""


class BNAnalysisError(BNError):
    """BN opened the file but analysis or enumeration failed."""


# --- typed result objects (mirror FlossString / FlossResult) -----------------


@dataclass(frozen=True)
class CallSite:
    """One enumerated API call site. Structural only — no values, no
    dataflow, no comparison semantics (those belong to later units)."""

    api_name: str
    call_site_va: int  # VA of the call instruction
    function_va: int  # VA of the containing function
    api_resolution: str  # one of the RESOLUTION_* constants
    calling_convention: Optional[str]  # None when BN can't determine it
    ordinal: Optional[int] = None  # populated when api_resolution == ordinal

    def to_dict(self) -> dict:
        """Intermediate-JSON form. VAs as 0x-prefixed lowercase hex strings,
        matching the schema's call_site_va / function_va convention."""
        d = {
            "api_name": self.api_name,
            "call_site_va": f"0x{self.call_site_va:08x}",
            "function_va": f"0x{self.function_va:08x}",
            "api_resolution": self.api_resolution,
            "calling_convention": self.calling_convention,
        }
        if self.ordinal is not None:
            d["ordinal"] = self.ordinal
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CallSite":
        return cls(
            api_name=d["api_name"],
            call_site_va=int(d["call_site_va"], 16),
            function_va=int(d["function_va"], 16),
            api_resolution=d["api_resolution"],
            calling_convention=d.get("calling_convention"),
            ordinal=d.get("ordinal"),
        )


@dataclass
class BNCallSites:
    """All call sites enumerated from one sample, plus provenance."""

    sample_path: str
    sample_sha256: Optional[str]
    bn_core_version: str
    call_sites: list[CallSite] = field(default_factory=list)

    # --- convenience accessors (mirror FlossResult.values()/all_strings()) ---

    def api_names(self) -> set[str]:
        """The distinct API names called anywhere in the sample."""
        return {cs.api_name for cs in self.call_sites}

    def for_api(self, name: str) -> list[CallSite]:
        """All call sites targeting a given API name."""
        return [cs for cs in self.call_sites if cs.api_name == name]

    def by_resolution(self, resolution: str) -> list[CallSite]:
        return [cs for cs in self.call_sites if cs.api_resolution == resolution]

    def schema_emittable(self) -> list[CallSite]:
        """Call sites whose resolution maps onto a v1 schema enum value
        (drops `unknown` indirect calls)."""
        return [cs for cs in self.call_sites if cs.api_resolution in V1_SCHEMA_RESOLUTIONS]

    # --- serialization -------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "sample_path": self.sample_path,
            "sample_sha256": self.sample_sha256,
            "bn_core_version": self.bn_core_version,
            "call_sites": [cs.to_dict() for cs in self.call_sites],
        }

    def write_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    def to_partial_candidates(self) -> list[dict]:
        """Emit call-site *stubs* in the shape of schema candidate records,
        with value/dataflow/comparison fields left for later units to fill.

        NOT the module's primary output. This exists so Unit 4 can attach
        FLOSS values and dataflow paths to a ready-made skeleton rather
        than rebuilding it. Only schema-emittable resolutions are included.
        """
        stubs = []
        for cs in self.schema_emittable():
            stubs.append(
                {
                    "call_site_va": f"0x{cs.call_site_va:08x}",
                    "function_va": f"0x{cs.function_va:08x}",
                    "api_name": cs.api_name,
                    "api_resolution": cs.api_resolution,
                    # everything below is a placeholder filled by Unit 4+:
                    "parameter_index": None,
                    "comparison_operator": "unknown",
                    "evidence": {
                        "channels": ["bn_xref"],
                        "string_source": None,
                        "string_va": None,
                        "string_function_va": None,
                        "dataflow_path": [],
                        "cmp_operand_a": None,
                        "cmp_operand_b": None,
                    },
                }
            )
        return stubs


# --- offline loader (mirror load_floss_results) ------------------------------


def load_bn_results(path: str | Path) -> BNCallSites:
    """Load a previously-saved intermediate JSON (the offline-test path —
    no BN, no license needed)."""
    data = json.loads(Path(path).read_text())
    return BNCallSites(
        sample_path=data["sample_path"],
        sample_sha256=data.get("sample_sha256"),
        bn_core_version=data["bn_core_version"],
        call_sites=[CallSite.from_dict(d) for d in data["call_sites"]],
    )


# --- the real run (mirror run_floss) -----------------------------------------


def run_bn_callsites(
    sample: str | Path,
    *,
    run_license_checkout: bool = True,
) -> BNCallSites:
    """Run headless BN against `sample` and enumerate API call sites.

    Imports `binaryninja` lazily so the module (and its offline tests) load
    without BN present. When run_license_checkout is True, wraps analysis in
    an Enterprise LicenseCheckout; set False if the caller already holds a
    checked-out license for the process.
    """
    try:
        import binaryninja
        from binaryninja import MediumLevelILOperation
    except Exception as exc:  # noqa: BLE001 - surface any import/link failure
        raise BNNotAvailableError(
            "Could not import the binaryninja API. Ensure install_api.py has "
            "been run against this venv (see docs/binary_ninja_headless_setup.md)."
        ) from exc

    sample = Path(sample)
    if not sample.exists():
        raise BNAnalysisError(f"sample not found: {sample}")

    def _enumerate() -> BNCallSites:
        try:
            bv = binaryninja.load(str(sample))
        except Exception as exc:  # noqa: BLE001
            raise BNAnalysisError(f"BN failed to load {sample}: {exc}") from exc
        if bv is None:
            raise BNAnalysisError(f"BN returned no view for {sample}")

        bv.update_analysis_and_wait()
        sites = _collect_call_sites(bv, MediumLevelILOperation)
        sha = _sha256(sample)
        return BNCallSites(
            sample_path=str(sample),
            sample_sha256=sha,
            bn_core_version=binaryninja.core_version(),
            call_sites=sites,
        )

    if run_license_checkout:
        try:
            from binaryninja.enterprise import LicenseCheckout
        except Exception as exc:  # noqa: BLE001
            raise BNNotAvailableError(
                "Could not import binaryninja.enterprise for license checkout."
            ) from exc
        try:
            with LicenseCheckout():
                return _enumerate()
        except BNError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BNNotAvailableError(
                f"Enterprise license checkout failed: {exc}. "
                "Did you source bn_env.sh? See the setup doc."
            ) from exc
    else:
        return _enumerate()


def enumerate_with_view(
    bv,
    *,
    sample_path: str = "",
    sample_sha256: Optional[str] = None,
) -> BNCallSites:
    """Unit 3 against an already-open, already-analysed BinaryView.

    The single-analysis orchestrator entry point, mirroring
    clew.channels.binaryninja.dataflow.bridge_with_view. The orchestrator opens the view
    once (one update_analysis_and_wait, inside one LicenseCheckout), calls this
    to enumerate call sites, then bridge_with_view() to trace them -- avoiding a
    second full analysis. `bv` MUST already be analysed; unlike run_bn_callsites
    this neither loads the sample nor checks out a license (the caller owns
    both). sample_path/sample_sha256 are provenance the caller supplies since
    they aren't recoverable from the view alone.
    """
    import binaryninja
    from binaryninja import MediumLevelILOperation

    sites = _collect_call_sites(bv, MediumLevelILOperation)
    return BNCallSites(
        sample_path=sample_path,
        sample_sha256=sample_sha256,
        bn_core_version=binaryninja.core_version(),
        call_sites=sites,
    )


# --- enumeration internals ---------------------------------------------------


def _collect_call_sites(bv, MediumLevelILOperation) -> list[CallSite]:
    """Enumerate API call sites by walking import symbols and their code
    refs, NOT by classifying every MLIL call target.

    Why this strategy (validated against al-khaser on BN 4.2.6455):
      - Imported APIs are reached through the IAT. The symbol that actually
        carries the call cross-references is the ImportAddressSymbol (the
        IAT slot), e.g. OutputDebugStringW's IAT slot had 30 code refs while
        its ImportedFunctionSymbol had 1. Classifying MLIL targets by name
        missed these entirely.
      - Internal functions (sub_*, j_sub_*) carry NO symbol, so a
        name-based "is there a symbol here? call it import" heuristic
        mislabeled internal calls as imports. Keying off symbol *type*
        instead (ImportAddressSymbol / ImportedFunctionSymbol) excludes
        internal code cleanly.
      - get_code_refs naturally yields one ref per call site, and we dedup
        on (call_site_va, api_name) to absorb BN's occasional duplicate
        MLIL expression at one address.

    For each import symbol we take its code refs; each ref gives the calling
    function and the exact call-site VA. Resolution is `import` (or `ordinal`
    when the symbol is an ordinal import). GetProcAddress-resolved names are
    handled separately by walking GetProcAddress call sites.
    """
    from binaryninja import SymbolType

    by_key: dict[tuple, CallSite] = {}

    # 1) Static imports: enumerate IAT + imported-function symbols, follow refs.
    import_syms = _import_symbols(bv, SymbolType)
    for sym in import_syms:
        api_name, resolution, ordinal = _classify_import_symbol(sym, SymbolType)
        if not api_name:
            continue
        for ref in bv.get_code_refs(sym.address):
            ref_func = ref.function
            if ref_func is None:
                continue
            # Skip refs that originate inside an import thunk (the stub's own
            # forwarding jump), not real caller code. The symbol-based filter
            # alone misses thunks whose import symbol lives at the IAT address
            # rather than at the thunk's start, so we add a structural guard:
            # a forwarder thunk is a tiny function whose ONLY instruction is
            # the call/jump at its start. We require BOTH "ref is at func
            # start" AND "func is a tiny forwarder" so we never discard a
            # legitimate call that merely happens to be a function's first
            # instruction (hand-written asm, tail calls).
            if ref.address == ref_func.start and _is_forwarder_thunk(ref_func):
                continue
            if _is_import_thunk(bv, ref_func, SymbolType):
                continue
            key = (ref.address, api_name)
            if key in by_key:
                continue
            by_key[key] = CallSite(
                api_name=api_name,
                call_site_va=ref.address,
                function_va=ref_func.start,
                api_resolution=resolution,
                calling_convention=_calling_convention_name(ref_func),
                ordinal=ordinal,
            )

    # 2) GetProcAddress-resolved calls: recover the requested name and emit
    #    the indirect call site that consumes the resolved pointer.
    for site in _getprocaddress_call_sites(bv, MediumLevelILOperation, SymbolType):
        key = (site.call_site_va, site.api_name)
        by_key.setdefault(key, site)

    return list(by_key.values())


def _import_symbols(bv, SymbolType) -> list:
    """All symbols that represent an imported API: the IAT slots
    (ImportAddressSymbol, which carry the call refs) and the imported
    function symbols. Not deduped here; dedup on (call_site_va, api_name)
    happens downstream in _collect_call_sites."""
    syms = []
    syms.extend(bv.get_symbols_of_type(SymbolType.ImportAddressSymbol))
    syms.extend(bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol))
    return syms


def _classify_import_symbol(sym, SymbolType):
    """Return (api_name, resolution, ordinal|None) for an import symbol.

    Strips BN's IAT decorations from the name. Detects ordinal imports
    (no usable name, ordinal present)."""
    raw = sym.name or ""
    clean = _clean_symbol_name(raw)
    ordinal = getattr(sym, "ordinal", 0) or None

    # Drop the IAT bookkeeping symbols that aren't actual call targets:
    # __import_lookup_table_*, __export_name_ptr_table_*, __import_name_*.
    # These had 0 code refs in testing but guard against name pollution.
    if clean.startswith(
        (
            "__import_lookup_table",
            "__export_name_ptr_table",
            "__import_name",
            "__import_address_table",
        )
    ):
        return ("", RESOLUTION_IMPORT, None)

    if ordinal is not None and (not clean or clean.lower().startswith("ordinal")):
        return (clean or f"ordinal_{ordinal}", RESOLUTION_ORDINAL, ordinal)

    return (clean, RESOLUTION_IMPORT, None)


def _getprocaddress_call_sites(bv, MediumLevelILOperation, SymbolType) -> list:
    """Find indirect call sites whose target was resolved by GetProcAddress,
    naming each from the GetProcAddress string argument.

    v1 scope: shallow, same-function association (a GetProcAddress whose
    constant string arg precedes an indirect call in the same function).
    Deep SSA tracing of the resolved pointer to its exact use is Unit 4's
    job; here we only recover enough to NAME the call.
    """
    sites: list[CallSite] = []

    # Locate GetProcAddress's IAT/import symbol address(es).
    gpa_addrs = set()
    for sym in _import_symbols(bv, SymbolType):
        if "GetProcAddress" in (sym.name or ""):
            gpa_addrs.add(sym.address)
    if not gpa_addrs:
        return sites

    for func in bv.functions:
        if _is_import_thunk(bv, func, SymbolType):
            continue
        mlil = func.mlil_if_available  # func.mlil raises ILException when MLIL was skipped
        if mlil is None:
            continue

        # Collect (address, resolved_name) for GetProcAddress calls in func,
        # and the indirect call sites, then pair them by order within func.
        gpa_names: list[tuple[int, str]] = []
        indirect_calls: list = []
        for block in mlil:
            for insn in block:
                if insn.operation not in (
                    MediumLevelILOperation.MLIL_CALL,
                    MediumLevelILOperation.MLIL_TAILCALL,
                ):
                    continue
                name = _string_arg_if_getprocaddress(bv, insn, gpa_addrs)
                if name is not None:
                    gpa_names.append((insn.address, name))
                    continue
                # An indirect call (no constant import target) is a candidate
                # consumer of a GetProcAddress result.
                dest = insn.dest
                if getattr(dest, "constant", None) is None:
                    indirect_calls.append(insn)

        if not gpa_names or not indirect_calls:
            continue

        # Shallow pairing: each indirect call takes the most recent preceding
        # GetProcAddress name in the same function.
        for call in indirect_calls:
            preceding = [n for (a, n) in gpa_names if a < call.address]
            if not preceding:
                continue
            api_name = preceding[-1]
            sites.append(
                CallSite(
                    api_name=api_name,
                    call_site_va=call.address,
                    function_va=func.start,
                    api_resolution=RESOLUTION_GETPROCADDRESS,
                    calling_convention=_calling_convention_name(func),
                    ordinal=None,
                )
            )

    return sites


def _is_forwarder_thunk(func) -> bool:
    """True if `func` is a tiny forwarder stub — a single basic block whose
    whole body is the forwarding jump/call (BN's `jmp [IAT_slot]` import
    thunks). Used to safely drop the thunk's own outgoing ref without
    discarding legitimate calls that merely sit at a real function's start.

    Heuristic: one basic block, and at most a couple of instructions. Import
    thunks are exactly one instruction; we allow 2 for tolerance.
    """
    try:
        blocks = list(func.basic_blocks)
    except Exception:  # noqa: BLE001
        return False
    if len(blocks) != 1:
        return False
    # instruction_count is available per basic block; fall back to length.
    bb = blocks[0]
    count = getattr(bb, "instruction_count", None)
    if count is None:
        return (bb.end - bb.start) <= 8  # ~one x86 jmp [mem] is 6 bytes
    return count <= 2


def _is_import_thunk(bv, func, SymbolType) -> bool:
    """True if `func` is an imported-API stub rather than real code.

    Detected two ways (either is sufficient):
      1. The function's start carries an import symbol — BN names the thunk
         after the API it forwards to (ImportedFunctionSymbol /
         ImportAddressSymbol at func.start).
      2. The function has the symbol-type marker BN uses for import stubs.

    Import thunks are IAT plumbing; their single forwarding jump must not be
    enumerated as a genuine API call site.
    """
    sym = bv.get_symbol_at(func.start)
    if sym is not None and sym.type in (
        SymbolType.ImportedFunctionSymbol,
        SymbolType.ImportAddressSymbol,
    ):
        return True

    # Some BN versions expose a dedicated flag for import stubs; use it if
    # present without hard-depending on it.
    if getattr(func, "is_thunk", False):
        return True

    return False


def _string_arg_if_getprocaddress(bv, insn, gpa_addrs) -> Optional[str]:
    """If insn is a call to GetProcAddress (its target address is in the
    pre-computed gpa_addrs set) with a constant-string 2nd arg, return that
    string. Else None.

    Recovering by target *address* (not name match) is what the diagnostics
    showed is reliable: GetProcAddress is reached through its IAT slot.
    """
    from binaryninja import MediumLevelILOperation

    if insn.operation not in (
        MediumLevelILOperation.MLIL_CALL,
        MediumLevelILOperation.MLIL_TAILCALL,
    ):
        return None
    dest = insn.dest
    target = getattr(dest, "constant", None)
    if target is None or target not in gpa_addrs:
        return None

    params = getattr(insn, "params", None) or []
    if len(params) < 2:
        return None
    name_arg = params[1]
    str_addr = getattr(name_arg, "constant", None)
    if str_addr is None:
        return None
    # Try ASCII then wide; GetProcAddress takes ANSI names but be tolerant.
    s = bv.get_ascii_string_at(str_addr, min_length=1)
    if s is None:
        return None
    return s.value


def _calling_convention_name(func) -> Optional[str]:
    cc = getattr(func, "calling_convention", None)
    if cc is None:
        return None
    return getattr(cc, "name", None) or str(cc)


def _clean_symbol_name(name: str) -> str:
    """Strip BN import decorations: a leading IAT marker and any
    module-qualified prefix, leaving the bare API name where possible."""
    n = name
    for prefix in ("__imp_", "_imp_"):
        if n.startswith(prefix):
            n = n[len(prefix) :]
    # Module-qualified forms like "KERNEL32!IsDebuggerPresent"
    if "!" in n:
        n = n.split("!", 1)[1]
    return n


def _sha256(path: Path) -> Optional[str]:
    import hashlib

    try:
        h = hashlib.sha256()
        h.update(path.read_bytes())
        return h.hexdigest()
    except Exception:  # noqa: BLE001
        return None

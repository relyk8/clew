"""Channel 2 / Unit 4: the MLIL-SSA dataflow bridge.

This is the *bridge* that joins the two halves clew already has:

    Unit 2 (Channel 1 / FLOSS)  -> string *values*, but not where used
    Unit 3 (Channel 2 / bn_xref) -> API *call sites*, but not the values

For every call site Unit 3 enumerated, this unit traces the arguments of
that call backward through Binary Ninja's Medium-Level IL in SSA form to
whatever flows into them. When an argument resolves to a string constant
(static, or an obfuscated stack/tight/decoded string FLOSS recovered), the
bridge attaches the value, the dataflow path, and the string's provenance
to the call-site stub -- turning `evidence.channels == ["bn_xref"]` into
`["bn_xref", "floss"]` and producing a candidate with a value on it.

Scope (v1) -- what the bridge DOES:
    * locate the MLIL-SSA call at each Unit-3 call_site_va
    * for each parameter, walk the def-use chain (through phi nodes) to a
      source, recording every instruction VA on the path
    * recover static string constants directly from the BinaryView
    * recover pointers spilled to a stack slot and reloaded, via BN's own
      constant-folded value for the expression (the `.value` fast path)
    * enumerate statically-initialised indicator arrays -- the
      GetModuleHandleW(names[i]) loop over a local array of module-name
      pointers -- emitting one candidate with one value per array element
    * recover obfuscated strings by shallow association with FLOSS
      stack/tight/decoded output in the same function
    * cross-reference recovered values against FLOSS to raise confidence
      and set source_channels

Scope (v1) -- what the bridge deliberately does NOT do (the boundaries the
earlier scoping flagged):
    * comparison semantics (comparison_operator / cmp_operand_a / _b) --
      that is Channel 3 (DynamoRIO cmp-logging), left null here.
    * semantic classification (represents / retarget_to / evasion_tier)
      and derivation_status -- that is the derivation stage (Person B).
      The bridge emits `represents == "unknown"` and no evasion_tier.
    * `hashed` API-name resolution -- a v2 item, same as Unit 3. The bridge
      only ever consumes the schema-emittable call sites Unit 3 produced.
    * deep inter-procedural tracing. A value flowing in from a *caller*
      (parameter of the containing function) or out of another API's return
      is reported as *unresolved* -- evidence that this call needs Channel 3,
      not a guessed value.

Output: like Unit 3, this is an *intermediate* artifact (BNDataflow ->
JSON), NOT finished clew schema records. `to_partial_candidates()` emits
enriched candidate dicts (parameter_index + candidate_values + evidence
dataflow fields filled) that are one derivation pass short of a schema
`Candidate`; they are the clean input to that pass.

Orchestration note: bridging needs the *same* analysed BinaryView Unit 3
used. The orchestrator should open the view once, run Unit 3 enumeration,
then call `bridge_with_view(bv, call_sites, floss_index)` to avoid a second
`update_analysis_and_wait`. `run_bn_dataflow()` is the standalone path that
re-opens the sample (offline tests use `load_dataflow_results` and never
touch BN at all).

BN API surface used (re-validate on BN bumps; companions BN_PINS in
callsites.py):
    func.mlil.ssa_form ; block/insn iteration ; insn.operation/.address
    MLIL_CALL_SSA / MLIL_TAILCALL_SSA / *_UNTYPED_SSA / MLIL_SYSCALL_SSA
    call.params ; MLIL_VAR_SSA.src ; MLIL_VAR_PHI.src/.dest
    MLIL_CONST(_PTR)/MLIL_IMPORT.constant ; MLIL_ADDRESS_OF.src (stack var)
    mlil.ssa_form.get_ssa_var_definition(var)
    bv.get_string_at / bv.get_ascii_string_at / bv.read
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple, Optional

# Reuse Unit 3's types and error hierarchy so the channel stays one family
# (mirrors capa.py / floss.py). Dual import: package layout in the repo (the
# sibling `callsites` module), flat layout for standalone tests.
try:  # pragma: no cover - trivial import shim
    from clew.channels.binaryninja.callsites import (
        BNAnalysisError,
        BNCallSites,
        BNError,
        BNNotAvailableError,
        CallSite,
    )
except ImportError:  # pragma: no cover
    from callsites import (  # type: ignore
        BNAnalysisError,
        BNCallSites,
        BNError,
        BNNotAvailableError,
        CallSite,
    )


# --- constants ---------------------------------------------------------------

CHANNEL_BN = "bn_xref"
CHANNEL_FLOSS = "floss"

# Schema StringSource enum values (schema/clew_record.schema.json $defs.StringSource).
SOURCE_STATIC = "static"
SOURCE_STACKSTRING = "stackstring"
SOURCE_TIGHTSTRING = "tightstring"
SOURCE_DECODED = "decoded"

# FLOSS obfuscated categories the bridge associates by function. FLOSS's own
# category names are normalised to these on the way into FlossIndex.
FLOSS_OBFUSCATED_SOURCES = frozenset({SOURCE_STACKSTRING, SOURCE_TIGHTSTRING, SOURCE_DECODED})

# Confidence heuristics. Not calibrated probabilities -- comparable within a
# single run only, per docs/schema.md. Centralised so tuning is one edit.
CONF_STATIC_CORROBORATED = 0.9  # BN dataflow + FLOSS agree on a static string
CONF_STATIC_BN_ONLY = 0.7  # BN read the string; FLOSS did not report it
CONF_OBFUSCATED_ASSOC = 0.6  # BN saw a stack ptr; FLOSS supplied the value
CONF_UNRESOLVED = 0.0  # call located, argument not statically recoverable

# Guard against pathological SSA graphs / cycles, and against a runaway array.
MAX_TRACE_DEPTH = 64
MAX_ARRAY_ELEMENTS = 256

# MLIL-SSA operation-name groups (compared by .name so we never hard-depend on
# a specific enum object across BN builds).
_CONST_OPS = frozenset({"MLIL_CONST_PTR", "MLIL_CONST", "MLIL_IMPORT"})
_SET_OPS = frozenset({"MLIL_SET_VAR_SSA", "MLIL_SET_VAR_ALIASED", "MLIL_SET_VAR"})
_LOAD_OPS = frozenset({"MLIL_LOAD_SSA", "MLIL_LOAD"})


class _Finding(NamedTuple):
    """One recovered value for a single argument. An argument yields a list of
    these: one for a plain string, N for an indicator array."""

    value: object
    string_source: Optional[str]
    string_va: Optional[int]
    string_function_va: Optional[int]
    channels: tuple
    confidence: float


# --- errors ------------------------------------------------------------------


class DataflowError(BNError):
    """The bridge located a call but tracing failed structurally."""


# --- FLOSS side: a lookup the bridge consults, decoupled from floss.py -------


@dataclass
class FlossIndex:
    """The slice of FLOSS output the bridge needs, in a shape it controls.

    Two lookups:
      * `static_values`  -- every static string FLOSS reported, for
        corroborating a value BN already read out of .rdata/.data.
      * `obfuscated_by_function` -- function_va -> [(value, source)], where
        source is one of FLOSS_OBFUSCATED_SOURCES. Used when BN sees a stack
        buffer flow into an argument but no literal string: FLOSS is the only
        channel that recovered the value, so we associate by function.

    Building one from a real FlossResult lives in `from_floss_result`, which
    is the SINGLE place to reconcile with floss.py's actual API. Everything
    else (and every test) constructs FlossIndex from primitives, so the bridge
    has no hard dependency on FLOSS internals.
    """

    static_values: set[str] = field(default_factory=set)
    obfuscated_by_function: dict[int, list[tuple[str, str]]] = field(default_factory=dict)

    def has_static(self, value: str) -> bool:
        return value in self.static_values

    def obfuscated_for_function(self, function_va: int) -> list[tuple[str, str]]:
        return self.obfuscated_by_function.get(function_va, [])

    @classmethod
    def empty(cls) -> "FlossIndex":
        return cls()

    @classmethod
    def from_floss_result(cls, floss_result) -> "FlossIndex":
        """Adapter over Unit 2's `FlossResult` (any object exposing
        `all_strings()`/`values()`, or an iterable of `FlossString`).

        Reads `FlossString`'s real fields: `value`; `source` (already a schema
        `string_source` value); `function` (stack/tight locus); and
        `decoding_routine` (decoded locus -- decoded strings have no `function`).
        A stack/tight/decoded string with no usable VA still corroborates by
        value, so it falls back into `static_values`. Kept in lock-step with
        `from_floss_json`, which handles the same categories from raw json.
        """
        static: set[str] = set()
        by_func: dict[int, list[tuple[str, str]]] = {}

        for s in _floss_iter(floss_result):
            value = getattr(s, "value", None)
            if value is None:
                continue
            source = _normalise_floss_source(getattr(s, "source", None))
            if source == SOURCE_STATIC:
                static.add(value)
                continue
            # stack/tight use `function`; decoded uses `decoding_routine`.
            fva = getattr(s, "function", None)
            if fva is None:
                fva = getattr(s, "decoding_routine", None)
            if isinstance(fva, str):
                try:
                    fva = int(fva, 16)
                except ValueError:
                    fva = None
            if not isinstance(fva, int):
                static.add(value)  # no locus -> corroborate by value only
                continue
            by_func.setdefault(fva, []).append((value, source))

        return cls(static_values=static, obfuscated_by_function=by_func)

    @classmethod
    def from_floss_json(cls, data) -> "FlossIndex":
        """Build from FLOSS 3.x `--json` output (a dict, or a path to one).

        Reads `data["strings"]` with the real per-category fields:
          static_strings : {"string"}                       -> static_values
          stack_strings  : {"string", "function": int VA}   -> obfuscated (stackstring)
          tight_strings  : {"string", "function": int VA}   -> obfuscated (tightstring)
          decoded_strings: {"string", "decoding_routine": int VA}
                                                             -> obfuscated (decoded)
        Decoded strings have no `function`; their locus is the decoding routine,
        so we key them by `decoding_routine`. VAs are integers in FLOSS json.
        A stack/tight/decoded string with no usable VA still corroborates by
        value, so it falls back into static_values.
        """
        if isinstance(data, (str, Path)):
            data = json.loads(Path(data).read_text())
        strings = (data or {}).get("strings", {}) or {}

        static: set[str] = set()
        by_func: dict[int, list[tuple[str, str]]] = {}

        for value in _floss_json_values(strings.get("static_strings")):
            static.add(value)

        for cat_key, source in (
            ("stack_strings", SOURCE_STACKSTRING),
            ("tight_strings", SOURCE_TIGHTSTRING),
            ("decoded_strings", SOURCE_DECODED),
        ):
            for entry in strings.get(cat_key) or []:
                if not isinstance(entry, dict):
                    continue
                value = entry.get("string")
                if value is None:
                    continue
                # decoded strings key off the decoder; stack/tight off `function`
                fva = entry.get("function")
                if fva is None:
                    fva = entry.get("decoding_routine")
                if not isinstance(fva, int):
                    static.add(value)  # no locus -> corroborate by value only
                    continue
                by_func.setdefault(fva, []).append((value, source))

        return cls(static_values=static, obfuscated_by_function=by_func)

    # dict round-trip for the intermediate JSON / offline tests
    def to_dict(self) -> dict:
        return {
            "static_values": sorted(self.static_values),
            "obfuscated_by_function": {
                f"0x{fva:08x}": vals for fva, vals in sorted(self.obfuscated_by_function.items())
            },
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FlossIndex":
        return cls(
            static_values=set(d.get("static_values", [])),
            obfuscated_by_function={
                int(k, 16): [tuple(v) for v in vals]
                for k, vals in d.get("obfuscated_by_function", {}).items()
            },
        )


def _floss_json_values(entries):
    """Yield the `string` field from a FLOSS json category list, tolerating
    either list-of-dicts (real FLOSS output) or list-of-strings."""
    for entry in entries or []:
        if isinstance(entry, dict):
            v = entry.get("string")
            if v is not None:
                yield v
        elif isinstance(entry, str):
            yield entry


def _floss_iter(floss_result):
    """Best-effort iteration over a FlossResult's strings. RECONCILE point."""
    for accessor in ("all_strings", "values", "strings"):
        fn = getattr(floss_result, accessor, None)
        if callable(fn):
            return list(fn())
    if isinstance(floss_result, (list, tuple)):
        return list(floss_result)
    # Last resort: iterate the object itself.
    try:
        return list(floss_result)
    except TypeError:
        return []


def _normalise_floss_source(raw) -> str:
    if raw is None:
        return SOURCE_STATIC
    r = str(raw).lower()
    if "tight" in r:
        return SOURCE_TIGHTSTRING
    if "stack" in r:
        return SOURCE_STACKSTRING
    if "decod" in r or "decode" in r:
        return SOURCE_DECODED
    return SOURCE_STATIC


# --- typed result objects (mirror CallSite / BNCallSites) --------------------


@dataclass(frozen=True)
class BridgedCallSite:
    """One (call site, parameter) after tracing. Structural + value, still
    no comparison semantics and no semantic classification (later stages)."""

    api_name: str
    call_site_va: int
    function_va: int
    api_resolution: str  # carried through from the Unit-3 CallSite
    parameter_index: int  # >= 0; the argument that was traced
    value: object  # str | int | bool | None (the recovered value)
    string_source: Optional[str]  # StringSource enum, or None for non-strings
    string_va: Optional[int]  # where the static string lives; None if on stack
    string_function_va: Optional[int]  # function the string was built in (obfuscated)
    dataflow_path: tuple[int, ...]  # VAs from source def down to the call site
    source_channels: tuple[str, ...]
    confidence: float
    resolved: bool  # False => arg not statically recoverable (-> Channel 3)

    def to_dict(self) -> dict:
        return {
            "api_name": self.api_name,
            "call_site_va": f"0x{self.call_site_va:08x}",
            "function_va": f"0x{self.function_va:08x}",
            "api_resolution": self.api_resolution,
            "parameter_index": self.parameter_index,
            "value": self.value,
            "string_source": self.string_source,
            "string_va": None if self.string_va is None else f"0x{self.string_va:08x}",
            "string_function_va": (
                None if self.string_function_va is None else f"0x{self.string_function_va:08x}"
            ),
            "dataflow_path": [f"0x{va:08x}" for va in self.dataflow_path],
            "source_channels": list(self.source_channels),
            "confidence": self.confidence,
            "resolved": self.resolved,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BridgedCallSite":
        return cls(
            api_name=d["api_name"],
            call_site_va=int(d["call_site_va"], 16),
            function_va=int(d["function_va"], 16),
            api_resolution=d["api_resolution"],
            parameter_index=d["parameter_index"],
            value=d["value"],
            string_source=d.get("string_source"),
            string_va=None if d.get("string_va") is None else int(d["string_va"], 16),
            string_function_va=(
                None if d.get("string_function_va") is None else int(d["string_function_va"], 16)
            ),
            dataflow_path=tuple(int(v, 16) for v in d.get("dataflow_path", [])),
            source_channels=tuple(d.get("source_channels", [])),
            confidence=d.get("confidence", 0.0),
            resolved=d.get("resolved", False),
        )


@dataclass
class BNDataflow:
    """All bridged call sites for one sample, plus provenance (mirror BNCallSites)."""

    sample_path: str
    sample_sha256: Optional[str]
    bn_core_version: str
    bridged: list[BridgedCallSite] = field(default_factory=list)

    # --- accessors -----------------------------------------------------------

    def resolved(self) -> list[BridgedCallSite]:
        return [b for b in self.bridged if b.resolved]

    def unresolved(self) -> list[BridgedCallSite]:
        """Located calls whose arguments need Channel 3. Not noise -- these
        tell the dynamic stage exactly which call sites to instrument."""
        return [b for b in self.bridged if not b.resolved]

    def for_api(self, name: str) -> list[BridgedCallSite]:
        return [b for b in self.bridged if b.api_name == name]

    def for_call_site(self, call_site_va: int) -> list[BridgedCallSite]:
        return [b for b in self.bridged if b.call_site_va == call_site_va]

    # --- serialization -------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "sample_path": self.sample_path,
            "sample_sha256": self.sample_sha256,
            "bn_core_version": self.bn_core_version,
            "bridged": [b.to_dict() for b in self.bridged],
        }

    def write_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    def to_partial_candidates(self, *, include_unresolved: bool = False) -> list[dict]:
        """Enrich Unit 3's stubs into intermediate candidate dicts.

        Fills parameter_index, candidate_values (value + source_channels +
        confidence), and the evidence dataflow fields. Intentionally leaves
        `represents` == "unknown", `retarget_to` == null, `comparison_operator`
        == "unknown", cmp operands null, and NO `evasion_tier` -- so this is an
        *intermediate* candidate, one derivation pass short of a schema
        Candidate. See module docstring, "Scope (v1)".

        One candidate per (call_site_va, parameter_index): records that share a
        call site and argument are collapsed into a single candidate whose
        `candidate_values` holds one entry per distinct value. That is how an
        indicator array -- GetModuleHandleW(names[i]) looped over N module names
        -- lands in the schema: one candidate, N values. A plain single-string
        argument is just the degenerate group of one.
        """
        groups: dict[tuple, list[BridgedCallSite]] = {}
        order: list[tuple] = []
        for b in self.bridged:
            if not b.resolved and not include_unresolved:
                continue
            key = (b.call_site_va, b.parameter_index)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(b)

        out: list[dict] = []
        for key in order:
            recs = groups[key]
            rep = max(recs, key=lambda r: r.confidence)  # representative
            group_channels = _channels_union(tuple(ch for r in recs for ch in r.source_channels))

            candidate_values = []
            seen = set()
            for r in recs:
                if r.value in seen:
                    continue
                seen.add(r.value)
                candidate_values.append(
                    {
                        "value": r.value,
                        "represents": "unknown",  # derivation refines
                        "retarget_to": None,  # derivation refines
                        "confidence": r.confidence,
                        "source_channels": list(_channels_union(r.source_channels)),
                    }
                )

            multi = len(candidate_values) > 1
            # A multi-value (array) candidate has no single string_va; the per-
            # element addresses have no schema home and live only in the typed
            # artifact. dataflow_path is the union across the group's records.
            string_va = None if multi else rep.string_va
            path = sorted({va for r in recs for va in r.dataflow_path})

            out.append(
                {
                    "call_site_va": f"0x{rep.call_site_va:08x}",
                    "function_va": f"0x{rep.function_va:08x}",
                    "api_name": rep.api_name,
                    "api_resolution": rep.api_resolution,
                    "parameter_index": rep.parameter_index,
                    "comparison_operator": "unknown",  # Channel 3 fills
                    "candidate_values": candidate_values,
                    "evidence": {
                        "channels": list(group_channels),
                        "string_source": rep.string_source,
                        "string_va": None if string_va is None else f"0x{string_va:08x}",
                        "string_function_va": (
                            None
                            if rep.string_function_va is None
                            else f"0x{rep.string_function_va:08x}"
                        ),
                        "dataflow_path": [f"0x{va:08x}" for va in path],
                        "cmp_operand_a": None,  # Channel 3 fills
                        "cmp_operand_b": None,
                    },
                }
            )
        return out


def load_dataflow_results(path: str | Path) -> BNDataflow:
    """Load a previously-saved intermediate JSON (offline path -- no BN)."""
    data = json.loads(Path(path).read_text())
    return BNDataflow(
        sample_path=data["sample_path"],
        sample_sha256=data.get("sample_sha256"),
        bn_core_version=data["bn_core_version"],
        bridged=[BridgedCallSite.from_dict(d) for d in data.get("bridged", [])],
    )


# --- pure decision helpers (BN-free, directly unit-testable) -----------------


def _channels_union(source_channels) -> tuple[str, ...]:
    """bn_xref is always present (the bridge is BN-driven); order stable."""
    s = set(source_channels)
    s.add(CHANNEL_BN)
    ordered = [CHANNEL_BN] + sorted(c for c in s if c != CHANNEL_BN)
    return tuple(ordered)


def _score_static(value: str, floss: FlossIndex) -> tuple[tuple[str, ...], float]:
    """Channels + confidence for a static string BN read directly."""
    if floss.has_static(value):
        return ((CHANNEL_BN, CHANNEL_FLOSS), CONF_STATIC_CORROBORATED)
    return ((CHANNEL_BN,), CONF_STATIC_BN_ONLY)


def _match_obfuscated(function_va: int, floss: FlossIndex) -> Optional[tuple[str, str]]:
    """Shallow association: if BN saw a stack buffer flow into the arg and
    FLOSS reported exactly one obfuscated string in this function, use it.

    Ambiguity (more than one) is left unresolved rather than guessed -- same
    conservatism as Unit 3's GetProcAddress pairing. Returns (value, source).
    """
    candidates = floss.obfuscated_for_function(function_va)
    if len(candidates) == 1:
        return candidates[0]
    return None


# --- BN-driven bridging ------------------------------------------------------


def run_bn_dataflow(
    call_sites: BNCallSites,
    sample: str | Path,
    *,
    floss_index: Optional[FlossIndex] = None,
    run_license_checkout: bool = True,
) -> BNDataflow:
    """Standalone path: re-open `sample` in headless BN and bridge every
    schema-emittable call site in `call_sites`.

    Prefer `bridge_with_view` from the orchestrator, which reuses the view
    Unit 3 already analysed instead of paying `update_analysis_and_wait`
    twice. Imports binaryninja lazily so offline tests never need it.
    """
    try:
        import binaryninja
        from binaryninja import MediumLevelILOperation
    except Exception as exc:  # noqa: BLE001
        raise BNNotAvailableError(
            "Could not import the binaryninja API. Ensure install_api.py has "
            "been run against this venv (see docs/binary_ninja_headless_setup.md)."
        ) from exc

    sample = Path(sample)
    if not sample.exists():
        raise BNAnalysisError(f"sample not found: {sample}")

    def _run() -> BNDataflow:
        try:
            bv = binaryninja.load(str(sample))
        except Exception as exc:  # noqa: BLE001
            raise BNAnalysisError(f"BN failed to load {sample}: {exc}") from exc
        if bv is None:
            raise BNAnalysisError(f"BN returned no view for {sample}")
        bv.update_analysis_and_wait()
        bridged = _bridge(bv, call_sites, floss_index or FlossIndex.empty(), MediumLevelILOperation)
        return BNDataflow(
            sample_path=str(sample),
            sample_sha256=call_sites.sample_sha256,
            bn_core_version=binaryninja.core_version(),
            bridged=bridged,
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
                return _run()
        except BNError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BNNotAvailableError(
                f"Enterprise license checkout failed: {exc}. "
                "Did you source bn_env.sh? See the setup doc."
            ) from exc
    return _run()


def bridge_with_view(
    bv,
    call_sites: BNCallSites,
    floss_index: Optional[FlossIndex] = None,
) -> list[BridgedCallSite]:
    """Bridge against an already-open, already-analysed BinaryView.

    This is the orchestrator entry point: one `binaryninja.load` +
    `update_analysis_and_wait` shared with Unit 3.
    """
    from binaryninja import MediumLevelILOperation

    return _bridge(bv, call_sites, floss_index or FlossIndex.empty(), MediumLevelILOperation)


def _bridge(bv, call_sites: BNCallSites, floss: FlossIndex, MLILOps) -> list[BridgedCallSite]:
    bridged: list[BridgedCallSite] = []
    for cs in call_sites.schema_emittable():
        try:
            bridged.extend(_bridge_call_site(bv, cs, floss, MLILOps))
        except Exception as exc:  # noqa: BLE001 - one bad call site must not sink the run
            # Record the located-but-unbridged call so nothing silently vanishes.
            bridged.append(_unresolved(cs, parameter_index=-1))
            _warn(f"bridge failed at {cs.api_name}@0x{cs.call_site_va:08x}: {exc}")
    return bridged


def _bridge_call_site(bv, cs: CallSite, floss: FlossIndex, MLILOps) -> list[BridgedCallSite]:
    func = bv.get_function_at(cs.function_va)
    if func is None:
        return [_unresolved(cs, parameter_index=-1)]
    ssa = getattr(func.mlil_if_available, "ssa_form", None)  # non-raising: skip funcs w/o MLIL
    if ssa is None:
        return [_unresolved(cs, parameter_index=-1)]

    call = _find_ssa_call(ssa, cs.call_site_va, MLILOps)
    if call is None:
        return [_unresolved(cs, parameter_index=-1)]

    params = list(getattr(call, "params", None) or [])
    if not params:
        return [_unresolved(cs, parameter_index=-1)]

    results: list[BridgedCallSite] = []
    for idx, param in enumerate(params):
        traced = _trace_arg(bv, ssa, param, floss, cs.function_va, MLILOps)
        if not traced:
            continue  # this argument had nothing statically recoverable
        path, findings = traced
        path_vas = tuple(sorted(set(path) | {cs.call_site_va}))
        for f in findings:
            results.append(
                BridgedCallSite(
                    api_name=cs.api_name,
                    call_site_va=cs.call_site_va,
                    function_va=cs.function_va,
                    api_resolution=cs.api_resolution,
                    parameter_index=idx,
                    value=f.value,
                    string_source=f.string_source,
                    string_va=f.string_va,
                    string_function_va=f.string_function_va,
                    dataflow_path=path_vas,
                    source_channels=f.channels,
                    confidence=f.confidence,
                    resolved=True,
                )
            )

    # No argument resolved: keep one unresolved record for Channel 3 targeting.
    if not results:
        return [_unresolved(cs, parameter_index=-1)]
    return results


def _unresolved(cs: CallSite, *, parameter_index: int) -> BridgedCallSite:
    return BridgedCallSite(
        api_name=cs.api_name,
        call_site_va=cs.call_site_va,
        function_va=cs.function_va,
        api_resolution=cs.api_resolution,
        parameter_index=parameter_index,
        value=None,
        string_source=None,
        string_va=None,
        string_function_va=None,
        dataflow_path=(cs.call_site_va,),
        source_channels=(CHANNEL_BN,),
        confidence=CONF_UNRESOLVED,
        resolved=False,
    )


def _find_ssa_call(ssa, call_site_va: int, MLILOps):
    """The MLIL-SSA call instruction whose address is call_site_va."""
    call_ops = _call_ops(MLILOps)
    for block in ssa:
        for insn in block:
            if getattr(insn, "address", None) == call_site_va and insn.operation in call_ops:
                return insn
    return None


def _call_ops(MLILOps) -> set:
    names = (
        "MLIL_CALL_SSA",
        "MLIL_TAILCALL_SSA",
        "MLIL_CALL_UNTYPED_SSA",
        "MLIL_TAILCALL_UNTYPED_SSA",
        "MLIL_SYSCALL_SSA",
        "MLIL_SYSCALL_UNTYPED_SSA",
    )
    return {getattr(MLILOps, n) for n in names if hasattr(MLILOps, n)}


def _trace_arg(bv, ssa, expr, floss: FlossIndex, function_va: int, MLILOps):
    """Walk one argument expression back to its source(s).

    Returns None if nothing statically recoverable, else a 2-tuple:
        (path:list[int], findings:list[_Finding])
    `findings` has one entry for a plain string and N for an indicator array.
    """
    path: list[int] = []
    visited: set = set()
    findings = _resolve(bv, ssa, expr, floss, function_va, MLILOps, 0, path, visited)
    if not findings:
        return None
    return (path, findings)


def _resolve(bv, ssa, expr, floss, function_va, MLILOps, depth, path, visited):
    """Return a list of _Finding for `expr` (empty if unresolved)."""
    if depth > MAX_TRACE_DEPTH or expr is None:
        return []

    addr = getattr(expr, "address", None)
    if addr is not None:
        path.append(addr)

    # 0) Fast path: BN's own dataflow already constant-folded this to a pointer
    #    (catches values spilled to a stack slot and reloaded). Cheap and robust.
    fast = _const_string_from_value(bv, expr)
    if fast is not None:
        value, string_va = fast
        channels, conf = _score_static(value, floss)
        return [_Finding(value, SOURCE_STATIC, string_va, None, channels, conf)]

    op = getattr(expr, "operation", None)
    opname = getattr(op, "name", "") if op is not None else ""

    # 1) Constant pointer / import address -> maybe a static string.
    if opname in _CONST_OPS:
        const = getattr(expr, "constant", None)
        if const is None:
            return []
        read = _read_string_at(bv, const)
        if read is None:
            return []  # a constant that isn't a string -> Channel 3 territory in v1
        channels, conf = _score_static(read[0], floss)
        return [_Finding(read[0], SOURCE_STATIC, const, None, channels, conf)]

    # 2) Memory load -> possibly an indicator array: GetModuleHandleW(arr[i]).
    if opname in _LOAD_OPS:
        return _resolve_array_load(bv, ssa, expr, floss, function_va)

    # 3) A stack buffer passed by address (&buf) -> obfuscated-string territory:
    #    FLOSS may have decoded a stack/tight/decoded string into that buffer.
    #    ONLY literal MLIL_ADDRESS_OF triggers this. A bare MLIL_VAR_SSA of a
    #    stack variable must NOT be treated as a buffer here -- it holds a value
    #    to trace, and its definition is followed in branch 4. (Catching stack
    #    vars here shadows the SSA walk and drops almost every argument.)
    if opname == "MLIL_ADDRESS_OF":
        match = _match_obfuscated(function_va, floss)
        if match is None:
            return []
        value, source = match
        return [
            _Finding(
                value, source, None, function_va, (CHANNEL_BN, CHANNEL_FLOSS), CONF_OBFUSCATED_ASSOC
            )
        ]

    # 4) SSA variable -> follow its definition.
    if opname == "MLIL_VAR_SSA":
        var = getattr(expr, "src", None)
        if var is None or var in visited:
            return []
        visited.add(var)
        definition = _ssa_def(ssa, var)
        if definition is None:
            # No definition in this function. If it's a stack variable, it may
            # be a live-in buffer FLOSS decoded a string into -> try that
            # association. Otherwise it's a caller parameter / register live-in,
            # i.e. inter-procedural, which is out of v1 scope.
            if _is_stack_var(var):
                match = _match_obfuscated(function_va, floss)
                if match is not None:
                    value, source = match
                    return [
                        _Finding(
                            value,
                            source,
                            None,
                            function_va,
                            (CHANNEL_BN, CHANNEL_FLOSS),
                            CONF_OBFUSCATED_ASSOC,
                        )
                    ]
            return []
        def_addr = getattr(definition, "address", None)
        if def_addr is not None:
            path.append(def_addr)
        return _resolve(
            bv,
            ssa,
            getattr(definition, "src", None),
            floss,
            function_va,
            MLILOps,
            depth + 1,
            path,
            visited,
        )

    # 5) Phi node -> resolve each incoming version; first that yields values wins
    #    (multi-value phis across control flow are a v2 refinement).
    if opname == "MLIL_VAR_PHI":
        for src_var in getattr(expr, "src", []) or []:
            if src_var in visited:
                continue
            visited.add(src_var)
            definition = _ssa_def(ssa, src_var)
            if definition is None:
                continue
            branch_path = list(path)
            da = getattr(definition, "address", None)
            if da is not None:
                branch_path.append(da)
            got = _resolve(
                bv,
                ssa,
                getattr(definition, "src", None),
                floss,
                function_va,
                MLILOps,
                depth + 1,
                branch_path,
                visited,
            )
            if got:
                path[:] = branch_path
                return got
        return []

    # 6) Anything else (call return, arithmetic on non-consts) -> unresolved.
    return []


def _resolve_array_load(bv, ssa, load_expr, floss, function_va):
    """Resolve a load of the form `[&stack_base + index]` into the const-pointer
    strings that populate the contiguous stack slot run at `stack_base`.

    This is al-khaser's indicator-array idiom: a local array of module-name
    pointers, iterated in a loop and passed to GetModuleHandleW/LoadLibrary.
    A constant index picks one slot; a variable (loop) index enumerates the run.
    """
    addr_expr = getattr(load_expr, "src", None)
    if addr_expr is None:
        return []

    base_var, offset_expr = _split_base_index(addr_expr)
    if base_var is None:
        return []
    base_storage = _var_storage(base_var)
    if base_storage is None:
        return []

    stride = _pointer_size(bv)
    entries = _enumerate_pointer_array(ssa, base_storage, stride, bv)
    if not entries:
        return []

    const_off = _const_offset(offset_expr)
    if const_off is not None:
        target = base_storage + const_off
        picked = [e for e in entries if e[0] == target]
        entries = picked or entries  # fall back to whole run if the slot's absent

    findings, seen = [], set()
    for _storage, value, string_va in entries[:MAX_ARRAY_ELEMENTS]:
        if value in seen:
            continue
        seen.add(value)
        # An array element is a const-pointer string: score it exactly like any
        # static string (0.9 if FLOSS corroborates, 0.7 BN-only). The "this is a
        # set, not a single per-iteration value" nuance is a coordination
        # property (an OR over the elements), captured in coordination_constraint
        # / comparison semantics by the derivation stage -- not a confidence cap.
        channels, conf = _score_static(value, floss)
        findings.append(_Finding(value, SOURCE_STATIC, string_va, None, channels, conf))
    return findings


def _enumerate_pointer_array(ssa, base_storage, stride, bv):
    """The contiguous, stride-spaced run of const-pointer-to-string stack
    assignments anchored at base_storage. Returns [(storage, value, va), ...]."""
    slots: dict[int, tuple] = {}
    for block in ssa:
        for insn in block:
            if getattr(getattr(insn, "operation", None), "name", "") not in _SET_OPS:
                continue
            src = getattr(insn, "src", None)
            if (
                src is None
                or getattr(getattr(src, "operation", None), "name", "") not in _CONST_OPS
            ):
                continue
            const = getattr(src, "constant", None)
            if const is None:
                continue
            read = _read_string_at(bv, const)
            if read is None:
                continue
            var = getattr(insn, "dest", None)
            storage = _var_storage(var)
            if storage is None or not _is_stack_var(var):
                continue
            slots[storage] = (storage, read[0], const)  # last write wins per slot

    if base_storage not in slots:
        return []

    run = [slots[base_storage]]
    s = base_storage + stride
    while s in slots:
        run.append(slots[s])
        s += stride
    s = base_storage - stride
    while s in slots:
        run.insert(0, slots[s])
        s -= stride
    return run


def _split_base_index(addr_expr):
    """From a load address expression, return (base_stack_var, offset_expr).
    Handles `&var` (offset 0) and `&var + index`."""
    opname = getattr(getattr(addr_expr, "operation", None), "name", "")
    if opname == "MLIL_ADDRESS_OF":
        v = getattr(addr_expr, "src", None)
        return (v, None) if _is_stack_var(v) else (None, None)
    if opname in ("MLIL_ADD",):
        left = getattr(addr_expr, "left", None)
        right = getattr(addr_expr, "right", None)
        for a, b in ((left, right), (right, left)):
            base = _address_of_stack_var(a)
            if base is not None:
                return (base, b)
    return (None, None)


def _address_of_stack_var(e):
    if e is None:
        return None
    if getattr(getattr(e, "operation", None), "name", "") == "MLIL_ADDRESS_OF":
        v = getattr(e, "src", None)
        if _is_stack_var(v):
            return v
    return None


def _const_offset(offset_expr):
    """The constant byte-offset of an index expression, or None if it varies."""
    if offset_expr is None:
        return 0
    if getattr(getattr(offset_expr, "operation", None), "name", "") in _CONST_OPS:
        return getattr(offset_expr, "constant", None)
    val = getattr(offset_expr, "value", None)
    if val is not None and "Constant" in str(getattr(val, "type", "")):
        return getattr(val, "value", None)
    return None


def _const_string_from_value(bv, expr):
    """If BN's dataflow gives this expression a constant-pointer value that
    reads as a string, return (value, va). Else None."""
    val = getattr(expr, "value", None)
    if val is None:
        return None
    if "Constant" not in str(getattr(val, "type", "")):
        return None
    ptr = getattr(val, "value", None)
    if not isinstance(ptr, int):
        return None
    read = _read_string_at(bv, ptr)
    if read is None:
        return None
    return (read[0], ptr)


def _var_storage(var):
    """Stack offset of a Variable/SSAVariable/aliased var, or None."""
    if var is None:
        return None
    inner = getattr(var, "var", var)  # SSAVariable/aliased -> underlying Variable
    return getattr(inner, "storage", None)


def _is_stack_var(var) -> bool:
    """True if a Variable/SSAVariable lives on the stack.

    Checks the source type by enum *name* -- BN's str() of the enum does not
    contain 'Stack' (it renders as an int/repr), but `.name` is
    'StackVariableSourceType'. Falls back to the negative-storage signature of
    a stack local, so this stays correct even if source_type is unavailable.
    """
    if var is None:
        return False
    inner = getattr(var, "var", var)
    st = getattr(inner, "source_type", None)
    if st is not None:
        name = getattr(st, "name", None) or str(st)
        if "Stack" in name:
            return True
    storage = getattr(inner, "storage", None)
    return isinstance(storage, int) and storage < 0


def _pointer_size(bv) -> int:
    try:
        return bv.arch.address_size
    except Exception:  # noqa: BLE001
        return 4


def _ssa_def(ssa, var):
    """The defining instruction for an SSA variable, tolerating BN versions
    that return an instruction index instead of the instruction."""
    getter = getattr(ssa, "get_ssa_var_definition", None)
    if getter is None:
        return None
    d = getter(var)
    if d is None:
        return None
    if isinstance(d, int):
        try:
            return ssa[d]
        except Exception:  # noqa: BLE001
            return None
    return d


def _read_string_at(bv, addr):
    """(value, 'ascii'|'utf16') for a string at addr, else None. Tries BN's
    string reference first (respects analysis), then ascii, then a wide read."""
    try:
        ref = bv.get_string_at(addr)
    except Exception:  # noqa: BLE001
        ref = None
    if ref is not None and getattr(ref, "value", None):
        return (ref.value, "ascii")

    try:
        a = bv.get_ascii_string_at(addr, min_length=1)
    except Exception:  # noqa: BLE001
        a = None
    if a is not None and getattr(a, "value", None):
        return (a.value, "ascii")

    # Wide (UTF-16LE) fallback: read up to a NUL-NUL, decode leniently.
    try:
        raw = bv.read(addr, 512)
    except Exception:  # noqa: BLE001
        raw = b""
    if raw:
        end = raw.find(b"\x00\x00")
        chunk = raw[: end if end != -1 else len(raw)]
        if len(chunk) >= 2:
            try:
                decoded = chunk.decode("utf-16-le", errors="ignore").rstrip("\x00")
            except Exception:  # noqa: BLE001
                decoded = ""
            if decoded and decoded.isprintable():
                return (decoded, "utf16")
    return None


def _warn(msg: str) -> None:
    import logging

    logging.getLogger("clew.channels.binaryninja.dataflow").warning(msg)

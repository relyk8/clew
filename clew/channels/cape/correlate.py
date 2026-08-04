"""Proximity join of runtime cmp/test operands onto static candidates.

Channel 3 correlation. The static pipeline emits candidates with placeholder
comparison fields (comparison_operator="unknown", cmp_operand_a/_b=null). This
module fills them from the DynamoRIO cmplog logs by a proximity heuristic:
comparisons whose runtime PC lands just after a candidate's call site are the
values that check likely tested against. It is a first cut, not a forward
slice, so it emits every plausible comparison ranked by confidence and lets the
downstream fuzzer prune. Pure, stdlib plus cmplog_parse only, so its test runs
offline with no network and no monkeypatch.
"""

from __future__ import annotations

import logging

from .cmplog_parse import CmpRecord

logger = logging.getLogger(__name__)

# Window sizes in bytes past a call site. NARROW captures comparisons just after
# the call. WIDE is a looser band accepted only for return-value candidates,
# where the check may sit back in the caller. Function-extent-aware windowing is
# a later pass.
NARROW = 256
WIDE = 1024

# Default PE32 preferred image base. Runtime PCs rebase into this static space.
IMAGE_BASE = 0x400000

# Confidence starts here and is scaled by proximity and operand readability.
BASE_CONFIDENCE = 0.6

# Channel token for the source of these comparisons. Reuses the existing enum.
_SOURCE_CHANNELS = ["drio"]

# A wrong or missing --module-base makes every rebased PC miss the static module,
# yielding an empty (but valid-looking) correlation. Warn when that is likely: a
# non-trivial number of records parsed, none landing in the module's VA range.
_MIN_RECORDS_FOR_WARN = 1000


def rebase(pc: int, module_base: int | None, image_base: int) -> int:
    """Map a runtime PC into static VA space. Identity when module_base is None."""
    if module_base is None:
        return pc
    return pc - module_base + image_base


# Which relation a conditional branch tests, for `cmp a, b` immediately before
# it. Both mnemonic spellings of each condition are present because DynamoRIO
# defines them as aliases (OP_jae / OP_jnb) and decode_opcode_name may emit
# either. The schema's ComparisonOperator draws no signed/unsigned distinction,
# so jl (signed) and jb (unsigned) both land on less_than.
#
# Conditions that are not relational -- sign, overflow, parity, and the jcxz
# family -- are deliberately absent and fall through to "unknown" rather than
# being forced onto an operator that would misdescribe them.
_JCC_OPERATOR = {
    "je": "equality",
    "jz": "equality",
    "jne": "inequality",
    "jnz": "inequality",
    "jl": "less_than",
    "jnge": "less_than",
    "jb": "less_than",
    "jnae": "less_than",
    "jc": "less_than",
    "jle": "less_equal",
    "jng": "less_equal",
    "jbe": "less_equal",
    "jna": "less_equal",
    "jg": "greater_than",
    "jnle": "greater_than",
    "ja": "greater_than",
    "jnbe": "greater_than",
    "jge": "greater_equal",
    "jnl": "greater_equal",
    "jae": "greater_equal",
    "jnb": "greater_equal",
    "jnc": "greater_equal",
}


def _operator_for(record: CmpRecord) -> str:
    """The operator this comparison is testing.

    `test` is a mask check and is unambiguous on its own. `cmp` only sets flags;
    what the comparison *meant* is carried by the conditional branch that
    consumes them, which drtrace logs as `jcc`. Without it -- a legacy cmplog
    log, or a cmp whose consumer the client could not attribute -- the operator
    stays unknown rather than being guessed.
    """
    if record.opcode == "test":
        return "bitwise_and"
    if record.jcc:
        return _JCC_OPERATOR.get(record.jcc.lower(), "unknown")
    return "unknown"


def _render_operand(record: CmpRecord, index: int) -> str | None:
    """Render operand `index` value as lowercase hex. None if absent or unreadable."""
    if index >= len(record.operands):
        return None
    value = record.operands[index].value
    return None if value is None else f"0x{value:x}"


def _has_unreadable_mem(record: CmpRecord) -> bool:
    """True if either rendered operand is a mem read that could not be resolved."""
    return any(op.kind == "mem" and op.value is None for op in record.operands[:2])


def _clamp(value: float) -> float:
    """Bound a confidence to [0, 1]."""
    return max(0.0, min(1.0, value))


def _warn_if_unrebased(
    cmp_records: list[CmpRecord],
    rebased: list,
    csvas: list[int],
    module_base: int | None,
) -> None:
    """Warn on the likely-wrong-module-base case: many runtime records parsed but
    none land in the static module's VA range (so the correlation is silently
    empty, indistinguishable from a sample that defeated instrumentation)."""
    if len(cmp_records) < _MIN_RECORDS_FOR_WARN or not csvas:
        return
    lo, hi = min(csvas), max(csvas) + WIDE
    if any(lo <= rpc <= hi for rpc, _ in rebased):
        return
    logger.warning(
        "correlate: parsed %d comparison records but none landed in the static "
        "module range [0x%x, 0x%x]; the runtime module base likely differs from "
        "0x%x -- pass the correct --module-base (currently %s).",
        len(cmp_records),
        lo,
        hi,
        IMAGE_BASE,
        f"0x{module_base:x}" if module_base is not None else "unset",
    )


# Confidence stamped on a value drtrace actually watched go into (or come out
# of) an API call. Written out rather than derived: the static ladder is 0.9
# bn_xref+floss, 0.7 bn_xref, 0.6 obfuscated/FLOSS-only, 0.0 unresolved, and it
# is deliberately not monotone in channel count, so "one rung up" means nothing.
# 0.95 sits above every static rung because a runtime observation is the only
# evidence in the record that was not inferred: the value was seen.
RUNTIME_CONFIDENCE = 0.95

# The client logs a call site as drwrap_get_retaddr -- the address the API
# returns to. Unit 3 records call_site_va as the address of the call
# *instruction*. They differ by the length of that instruction, so the two never
# join on equality, and a naive match yields zero hits on every sample while
# looking like a sample that simply was not observed.
#
# x86 call encodings in range: FF D0 (register, 2), FF 55 xx (indirect, 3),
# E8 rel32 (direct, 5), FF 15 disp32 (indirect memory, 6), plus room for a
# prefix. A window is used rather than a fixed offset because the encoding is
# not knowable from the return address alone.
MIN_CALL_INSTR_LEN = 2
MAX_CALL_INSTR_LEN = 7


def match_call_site(retaddr: int, call_site_vas) -> int | None:
    """Static call_site_va that the runtime return address `retaddr` came from.

    The nearest call site below `retaddr` that sits within one call instruction
    of it. Returns None when nothing is close enough, which is the honest answer
    for a call site Unit 3 never enumerated -- exactly the case that becomes a
    new runtime candidate.
    """
    best = None
    for csva in call_site_vas:
        delta = retaddr - csva
        if MIN_CALL_INSTR_LEN <= delta <= MAX_CALL_INSTR_LEN:
            if best is None or csva > best:
                best = csva
    return best


def resolve_module_base(
    trace, record: dict | None = None, explicit: int | None = None
) -> int | None:
    """Runtime load base to rebase PCs against, or None to leave them alone.

    An explicit `--module-base` always wins: it is the analyst's override. Failing
    that, the module table the client now logs answers the question directly,
    which is what retires the old ASLR-off assumption -- previously the base had
    to be worked out by hand and passed in, and getting it wrong produced an
    empty correlation indistinguishable from a sample that defeated
    instrumentation.

    None means "no module table" (a legacy cmplog log), and PCs pass through
    unrebased -- correct when the module loaded at its preferred base, which is
    what the proven task-11 autoit3 run did.
    """
    if explicit is not None:
        return explicit
    sample_name = None
    if record:
        sample_path = record.get("sample_path") or ""
        sample_name = sample_path.replace("\\", "/").rsplit("/", 1)[-1] or None
    main = trace.main_module(sample_name)
    if main is None:
        return None
    logger.info(
        "correlate: rebasing from the logged module table (%s @ 0x%x)",
        main.name or "<unnamed>",
        main.base,
    )
    return main.base


def correlate_record(
    record: dict,
    cmp_records: list[CmpRecord],
    *,
    module_base: int | None = None,
    image_base: int = IMAGE_BASE,
) -> dict:
    """Enrich `record` in place with proximity-correlated comparison candidates.

    For each candidate, select cmp/test records whose rebased PC sits in the
    window after its call site, dedupe loop noise, rank by confidence, and fill
    the legacy comparison fields from the top entry. Mutates and returns record.
    """
    rebased = [(rebase(r.pc, module_base, image_base), r) for r in cmp_records]
    csvas = [int(c["call_site_va"], 16) for c in record["candidates"]]
    _warn_if_unrebased(cmp_records, rebased, csvas, module_base)

    for candidate in record["candidates"]:
        csva = int(candidate["call_site_va"], 16)
        is_retval = candidate.get("parameter_index") == -1

        # Window select. Narrow for all, wide only for return-value candidates.
        hits = []
        for rpc, r in rebased:
            dist = rpc - csva
            if 0 <= dist <= NARROW:
                hits.append((rpc, r, False))
            elif is_retval and NARROW < dist <= WIDE:
                hits.append((rpc, r, True))

        # Dedupe by (pc, opcode, operand values). A looped PC firing with
        # identical operands collapses to one, hit_count kept internal only.
        seen: dict[tuple, list] = {}
        for rpc, r, wide in hits:
            key = (rpc, r.opcode, tuple(op.value for op in r.operands))
            if key in seen:
                seen[key][3] += 1
            else:
                seen[key] = [rpc, r, wide, 1]

        comparisons = []
        for rpc, r, wide, _hit_count in seen.values():
            dist = rpc - csva
            # Two disjoint proximity bands so a narrow hit ALWAYS ranks above any
            # wide hit, and within each band a closer hit ranks higher (monotonic
            # in dist): narrow -> (0.5, 1.0], wide -> [0, 0.5). Nothing is dropped;
            # every comparison is still emitted, just ranked (scout #7).
            if wide:
                proximity = 0.5 * (1 - (dist - NARROW) / (WIDE - NARROW))
            else:
                proximity = 0.5 + 0.5 * (1 - dist / NARROW)
            readability = 0.7 if _has_unreadable_mem(r) else 1.0
            confidence = _clamp(BASE_CONFIDENCE * proximity * readability)
            comparisons.append(
                {
                    "comparison_operator": _operator_for(r),
                    "cmp_operand_a": _render_operand(r, 0),
                    "cmp_operand_b": _render_operand(r, 1),
                    "confidence": confidence,
                    "source_channels": list(_SOURCE_CHANNELS),
                }
            )

        comparisons.sort(key=lambda c: c["confidence"], reverse=True)
        candidate["comparison_candidates"] = comparisons

        # Fill legacy single fields from the top entry for back-compat. Empty
        # window leaves the placeholders untouched.
        if comparisons:
            top = comparisons[0]
            candidate["comparison_operator"] = top["comparison_operator"]
            candidate["evidence"]["cmp_operand_a"] = top["cmp_operand_a"]
            candidate["evidence"]["cmp_operand_b"] = top["cmp_operand_b"]

    return record


def _value_entry(value) -> dict:
    """A candidate_values entry for something drtrace watched happen."""
    return {
        "value": value,
        "represents": "unknown",
        "retarget_to": None,
        "confidence": RUNTIME_CONFIDENCE,
        "source_channels": list(_SOURCE_CHANNELS),
    }


def _observed_values(call) -> list[tuple[int, object]]:
    """(parameter_index, value) pairs this call demonstrated.

    Arguments read at call time, arguments re-read after the return, and the
    return value itself (parameter_index -1, the schema's "check is on the
    return value"). An argument whose text is unchanged across the call is
    reported once: it was an input, not an out-parameter.
    """
    observed: list[tuple[int, object]] = []
    for idx, text in sorted(call.arg_strings.items()):
        observed.append((idx, text))
    for idx, text in sorted(call.out_strings.items()):
        if call.arg_strings.get(idx) != text:
            observed.append((idx, text))
    if call.returned:
        observed.append((-1, call.retval))
    return observed


def _promote_or_append(candidate: dict, value) -> bool:
    """Record `value` on `candidate`. True if this was new information.

    When the value is already there, this unions `drio` into its provenance and
    raises its confidence rather than adding a duplicate: static inferred the
    value and runtime confirmed it, which is one value with two sources, not
    two values.

    Strictly additive. A candidate that was not observed this run is unobserved,
    not disproven -- one detonation covers one path -- so nothing is ever removed
    or demoted here.
    """
    values = candidate.setdefault("candidate_values", [])
    for existing in values:
        if existing.get("value") == value:
            channels = existing.setdefault("source_channels", [])
            if _SOURCE_CHANNELS[0] not in channels:
                channels.append(_SOURCE_CHANNELS[0])
            existing["confidence"] = max(existing.get("confidence") or 0.0, RUNTIME_CONFIDENCE)
            return False
    values.append(_value_entry(value))
    return True


def _new_candidate(csva: int, api: str, param_index: int, value, function_va: str | None) -> dict:
    """A candidate for a call site the static pass never enumerated.

    `function_va` is set only when a sibling candidate at this call site already
    knows it. For a site Unit 3 missed entirely the enclosing function is often
    one Binary Ninja never identified -- packed or runtime-unpacked code -- so
    there is no honest value, and guessing one would poison the two things the
    field exists for: grouping by function and cross-referencing into BN.
    """
    candidate = {
        "call_site_va": f"0x{csva:08x}",
        "api_name": api,
        "api_resolution": "runtime",
        "parameter_index": param_index,
        "comparison_operator": "unknown",
        "candidate_values": [_value_entry(value)],
        "evidence": {
            "channels": list(_SOURCE_CHANNELS),
            "string_source": None,
            "string_va": None,
            "string_function_va": None,
            "dataflow_path": [],
            "cmp_operand_a": None,
            "cmp_operand_b": None,
        },
    }
    if function_va is not None:
        candidate["function_va"] = function_va
    return candidate


def merge_observed_calls(
    record: dict,
    trace,
    *,
    module_base: int | None = None,
    image_base: int = IMAGE_BASE,
) -> dict:
    """Merge drtrace's observed API calls into `record["candidates"]`.

    An observed call whose site matches a static candidate enriches that
    candidate in place -- this is what finally answers the unresolved stubs the
    static pass leaves behind, where Channel 2 found the call site but could not
    work out what flowed into it. A call at a site the static pass never
    enumerated becomes a new candidate, which is how Channel 3 stops being an
    annotator of Channel 2 and starts producing candidates of its own.
    """
    candidates = record.setdefault("candidates", [])
    by_key: dict[tuple[int, int], dict] = {}
    function_va_by_site: dict[int, str] = {}
    call_site_vas: set[int] = set()
    for candidate in candidates:
        csva = int(candidate["call_site_va"], 16)
        call_site_vas.add(csva)
        by_key[(csva, candidate.get("parameter_index"))] = candidate
        if candidate.get("function_va") and csva not in function_va_by_site:
            function_va_by_site[csva] = candidate["function_va"]

    seen: set[tuple[int, int, object]] = set()
    enriched = added = 0
    unmatched_sites: set[int] = set()

    for call in trace.calls:
        site = rebase(call.site, module_base, image_base)
        matched = match_call_site(site, call_site_vas)
        for param_index, value in _observed_values(call):
            if value is None:
                continue
            key = (matched if matched is not None else site, param_index, value)
            if key in seen:
                continue
            seen.add(key)

            if matched is not None:
                candidate = by_key.get((matched, param_index))
                if candidate is not None:
                    if _promote_or_append(candidate, value):
                        enriched += 1
                    channels = candidate.setdefault("evidence", {}).setdefault("channels", [])
                    if _SOURCE_CHANNELS[0] not in channels:
                        channels.append(_SOURCE_CHANNELS[0])
                    continue
                # Known call site, but the static pass produced nothing for this
                # parameter -- still a new candidate, and the function is known.
                fresh = _new_candidate(
                    matched, call.api, param_index, value, function_va_by_site.get(matched)
                )
            else:
                unmatched_sites.add(site)
                fresh = _new_candidate(site, call.api, param_index, value, None)

            candidates.append(fresh)
            by_key[(int(fresh["call_site_va"], 16), param_index)] = fresh
            added += 1

    logger.info(
        "correlate: %d observed calls -> %d values onto existing candidates, "
        "%d new candidates (%d call sites the static pass never enumerated)",
        len(trace.calls),
        enriched,
        added,
        len(unmatched_sites),
    )
    if trace.capped:
        logger.warning(
            "correlate: %d (api, call site) pairs hit the client's logging cap; "
            "their observed call counts are lower bounds",
            len(trace.capped),
        )
    return record


def correlate_trace(
    record: dict,
    trace,
    *,
    module_base: int | None = None,
    image_base: int = IMAGE_BASE,
) -> dict:
    """Full Channel 3 correlation for a drtrace run: comparisons and API calls.

    The module base comes from the trace's own module table unless overridden.
    Comparison correlation runs first so that the candidates created from
    observed calls are not then scanned for comparisons -- their operands come
    from the call itself, not from a proximity guess.
    """
    base = resolve_module_base(trace, record, module_base)
    correlate_record(record, trace.comparisons, module_base=base, image_base=image_base)
    merge_observed_calls(record, trace, module_base=base, image_base=image_base)
    return record

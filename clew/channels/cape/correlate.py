"""Join Channel 3's runtime observations onto a static clew record.

The static pipeline emits candidates with placeholder comparison fields
(comparison_operator="unknown", cmp_operand_a/_b=null). This module fills them
from the DynamoRIO logs, and — for `drtrace` logs — adds candidates of its own.
Pure, stdlib plus the two parsers only, so its test runs offline with no network
and no monkeypatch.

Three passes, weakest evidence first so later ones can improve on it:

1. `correlate_record` — the **proximity** join, and all a `cmplog` log supports.
   A comparison whose runtime PC lands in a window after a candidate's call site
   is probably the check that call feeds. It is a guess about code layout, not a
   forward slice, so it emits everything plausible and ranks rather than drops.
2. `merge_observed_calls` — the observed API calls. A call at a site the static
   pass found fills that candidate's unresolved values; a call at a site it never
   enumerated becomes a new candidate. This is what makes Channel 3 a producer
   rather than an annotator of Channel 2.
3. `merge_temporal_comparisons` — the **temporal** join, which needs `drtrace`'s
   global sequence number. A comparison that executed after a traced call
   returned, on the same thread, before any other traced call, is bound to that
   call's result. That is an ordering the instrumentation observed rather than an
   address landing in a guessed window, so it outranks proximity and upgrades any
   proximity guess it confirms.

Every entry records which of the two bindings produced it, because a bare
confidence number hides the difference.
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


def _comparison_entry(record: CmpRecord, confidence: float, binding: str) -> dict:
    """One entry for a candidate's comparison_candidates array.

    `binding` records how the comparison was tied to the candidate, because the
    two ways are not equally good evidence and a bare confidence number hides
    which one produced it.
    """
    return {
        "comparison_operator": _operator_for(record),
        "cmp_operand_a": _render_operand(record, 0),
        "cmp_operand_b": _render_operand(record, 1),
        "confidence": _clamp(confidence),
        "source_channels": list(_SOURCE_CHANNELS),
        "binding": binding,
    }


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
# returns to. Enumeration records call_site_va as the address of the call
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
    for a call site static enumeration never found -- exactly the case that becomes a
    new runtime candidate.
    """
    best = None
    for csva in call_site_vas:
        delta = retaddr - csva
        if MIN_CALL_INSTR_LEN <= delta <= MAX_CALL_INSTR_LEN:
            if best is None or csva > best:
                best = csva
    return best


def sample_name(record: dict | None) -> str | None:
    """Basename of the analysed sample, for picking its module out of the table."""
    if not record:
        return None
    path = record.get("sample_path") or ""
    return path.replace("\\", "/").rsplit("/", 1)[-1] or None


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
    main = trace.main_module(sample_name(record))
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
            # every comparison is still emitted, just ranked.
            if wide:
                proximity = 0.5 * (1 - (dist - NARROW) / (WIDE - NARROW))
            else:
                proximity = 0.5 + 0.5 * (1 - dist / NARROW)
            readability = 0.7 if _has_unreadable_mem(r) else 1.0
            confidence = BASE_CONFIDENCE * proximity * readability
            comparisons.append(_comparison_entry(r, confidence, "proximity"))

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


def build_function_spans(candidates: list[dict]) -> list[tuple[int, int, str]]:
    """(start, known_extent, rendered_va) per function, sorted by start.

    `known_extent` is the highest call site the static pass found inside that
    function -- a *lower bound* on where the function's body reaches, which is
    all the record actually evidences. Used to place a runtime call site into a
    function without inventing boundaries the record does not contain.
    """
    spans: dict[int, tuple[int, str]] = {}
    for candidate in candidates:
        rendered = candidate.get("function_va")
        if not rendered:
            continue
        start = int(rendered, 16)
        csva = int(candidate["call_site_va"], 16)
        known = spans.get(start)
        if known is None or csva > known[0]:
            spans[start] = (csva, rendered)
    return sorted((start, extent, rendered) for start, (extent, rendered) in spans.items())


def function_va_for(site: int, spans: list[tuple[int, int, str]]) -> str | None:
    """The function containing `site`, or None when the record cannot say.

    Takes the nearest function starting at or below `site` and accepts it only
    if `site` falls within the extent that function is *known* to span. Because
    the nearest such function is chosen, a function starting between it and
    `site` automatically disqualifies it.

    Beyond that bound there is no evidence: Binary Ninja may simply not have
    carved a function there at all, which is the usual reason enumeration missed the
    call site in the first place. Returning None there is deliberate -- inventing
    a value would corrupt exactly what the field is for, grouping candidates by
    routine and cross-referencing back into BN.
    """
    lo, hi = 0, len(spans)
    while lo < hi:
        mid = (lo + hi) // 2
        if spans[mid][0] <= site:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return None
    start, extent, rendered = spans[lo - 1]
    return rendered if site <= extent else None


def _new_candidate(csva: int, api: str, param_index: int, value, function_va: str | None) -> dict:
    """A candidate for a call site the static pass never produced a value for.

    `function_va` is null rather than absent when it cannot be determined: the
    consumer gets a uniform shape, and null says "no answer" where a missing key
    would just look like a different kind of record.
    """
    return {
        "call_site_va": f"0x{csva:08x}",
        "function_va": function_va,
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
    spans = build_function_spans(candidates)

    # A traced call's site is wherever the caller was, which is not always the
    # sample: a system DLL calling a wrapped API on the sample's behalf reports a
    # site inside that DLL (autoit3 task 19: KERNELBASE calling
    # NtQueryInformationProcess in ntdll). Such a site is real, but it cannot
    # become a candidate -- the consumer cannot act on an address in a Microsoft
    # DLL that relocates every boot, and the sample did not write that call.
    # Values still merge onto matched static candidates, which are in the sample
    # by construction; only *new* candidates are scoped.
    sample_module = trace.main_module(sample_name(record)) if trace.modules else None

    seen: set[tuple[int, int, object]] = set()
    enriched = added = 0
    unmatched_sites: set[int] = set()
    placed = unplaced = 0
    foreign_sites: set[int] = set()

    for call in trace.calls:
        site = rebase(call.site, module_base, image_base)
        matched = match_call_site(site, call_site_vas)
        # Scoped on the raw runtime address: the module table is in runtime space.
        in_sample = sample_module is None or sample_module.contains(call.site)
        if matched is None and not in_sample:
            foreign_sites.add(call.site)
            continue
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
                # parameter -- still a new candidate, and the function is known
                # exactly, from a sibling candidate at the same site.
                fresh = _new_candidate(
                    matched, call.api, param_index, value, function_va_by_site.get(matched)
                )
            else:
                unmatched_sites.add(site)
                fresh = _new_candidate(
                    site, call.api, param_index, value, function_va_for(site, spans)
                )
            if fresh["function_va"] is None:
                unplaced += 1
            else:
                placed += 1

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
    if added:
        logger.info(
            "correlate: %d/%d new candidates placed in a known function; %d have "
            "function_va=null (no function the static pass identified spans that address)",
            placed,
            added,
            unplaced,
        )
    if foreign_sites:
        logger.info(
            "correlate: %d observed call site(s) lie outside the sample's module "
            "(a system DLL called the API on its behalf); no candidates emitted for them",
            len(foreign_sites),
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
    # Last, so it can upgrade the proximity pass's guesses in place and attach to
    # the return-value candidates merge_observed_calls has just created.
    merge_temporal_comparisons(record, trace, module_base=base, image_base=image_base)
    return record


# How many comparisons after an API return are treated as checks on what that
# call produced. The check on a return value is normally within a handful of
# instructions; this is generous enough to survive a few intervening compares
# without reaching into unrelated code.
TEMPORAL_WINDOW = 32

# A temporally-bound comparison starts here, above every proximity confidence
# (BASE_CONFIDENCE 0.6 scaled down by distance), because it rests on an ordering
# the instrumentation actually observed rather than on an address falling inside
# a guessed window.
TEMPORAL_BASE_CONFIDENCE = 0.9


def _thread_timeline(trace) -> dict[int, list]:
    """Per-thread comparisons ordered by the client's global sequence number.

    Comparisons with no seq (a legacy cmplog log) are excluded: without ordering
    there is nothing to bind temporally, and the proximity join already covers
    them.
    """
    timeline: dict[int, list] = {}
    for record in trace.comparisons:
        if record.seq is None:
            continue
        timeline.setdefault(record.tid, []).append(record)
    for records in timeline.values():
        records.sort(key=lambda r: r.seq)
    return timeline


def _next_call_seq(trace) -> dict[int, list[int]]:
    """Per-thread sorted seqs at which a traced call was entered.

    Used as the stop bound: once another traced API is entered, subsequent
    comparisons are about that call, not the previous one.
    """
    starts: dict[int, list[int]] = {}
    for call in trace.calls:
        starts.setdefault(call.tid, []).append(call.seq)
    for seqs in starts.values():
        seqs.sort()
    return starts


def merge_temporal_comparisons(
    record: dict,
    trace,
    *,
    module_base: int | None = None,
    image_base: int = IMAGE_BASE,
) -> dict:
    """Bind comparisons to the API return that produced the value they test.

    This is what Channel 3 is nominally for: "the comparison operands captured
    *after* an API returns". The proximity join can only ask whether a
    comparison's address sits near a call site, which is a guess about layout.
    With the client's global sequence number the question becomes an observed
    fact -- this comparison executed after that call returned, on that thread,
    before any other traced call -- so it is bound and ranked above proximity.

    Comparisons already found by the proximity pass are upgraded in place rather
    than duplicated: same comparison, better evidence for it.
    """
    timeline = _thread_timeline(trace)
    call_starts = _next_call_seq(trace)
    if not timeline:
        return record

    by_key: dict[tuple[int, int], dict] = {}
    call_site_vas: set[int] = set()
    for candidate in record.get("candidates", []):
        csva = int(candidate["call_site_va"], 16)
        call_site_vas.add(csva)
        by_key[(csva, candidate.get("parameter_index"))] = candidate

    bound = upgraded = 0
    for call in trace.calls:
        if not call.returned:
            continue
        records = timeline.get(call.tid)
        if not records:
            continue

        # Stop at the next traced call entered on this thread: past that point
        # the comparisons belong to it.
        limit = None
        for seq in call_starts.get(call.tid, []):
            if seq > call.return_seq:
                limit = seq
                break

        following = []
        for r in records:
            if r.seq <= call.return_seq:
                continue
            if limit is not None and r.seq >= limit:
                break
            following.append(r)
            if len(following) >= TEMPORAL_WINDOW:
                break
        if not following:
            continue

        site = rebase(call.site, module_base, image_base)
        matched = match_call_site(site, call_site_vas)
        if matched is None:
            continue
        # The check is on what the call produced, so it belongs to the
        # return-value candidate; fall back to any candidate at the site.
        candidate = by_key.get((matched, -1))
        if candidate is None:
            candidate = next(
                (c for c in record["candidates"] if int(c["call_site_va"], 16) == matched), None
            )
        if candidate is None:
            continue

        comparisons = candidate.setdefault("comparison_candidates", [])
        existing = {
            (c["comparison_operator"], c["cmp_operand_a"], c["cmp_operand_b"]): c
            for c in comparisons
        }
        for position, r in enumerate(following):
            # Decay with distance from the return: the first comparison after it
            # is the likeliest consumer of the value.
            nearness = 1.0 - (position / TEMPORAL_WINDOW)
            readability = 0.7 if _has_unreadable_mem(r) else 1.0
            entry = _comparison_entry(
                r, TEMPORAL_BASE_CONFIDENCE * nearness * readability, "temporal"
            )
            key = (entry["comparison_operator"], entry["cmp_operand_a"], entry["cmp_operand_b"])
            prior = existing.get(key)
            if prior is None:
                comparisons.append(entry)
                existing[key] = entry
                bound += 1
            elif entry["confidence"] > prior["confidence"] or prior.get("binding") != "temporal":
                # Same comparison the proximity pass already guessed at, now with
                # ordering evidence behind it. Upgrade rather than duplicate.
                prior["confidence"] = max(prior["confidence"], entry["confidence"])
                prior["binding"] = "temporal"
                upgraded += 1

        comparisons.sort(key=lambda c: c["confidence"], reverse=True)
        top = comparisons[0]
        candidate["comparison_operator"] = top["comparison_operator"]
        candidate.setdefault("evidence", {})["cmp_operand_a"] = top["cmp_operand_a"]
        candidate["evidence"]["cmp_operand_b"] = top["cmp_operand_b"]

    logger.info(
        "correlate: temporal join bound %d comparisons to a traced API return, "
        "upgraded %d the proximity pass had already guessed",
        bound,
        upgraded,
    )
    return record

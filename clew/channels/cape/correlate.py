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

from .cmplog_parse import CmpRecord

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


def rebase(pc: int, module_base: int | None, image_base: int) -> int:
    """Map a runtime PC into static VA space. Identity when module_base is None."""
    if module_base is None:
        return pc
    return pc - module_base + image_base


def _operator_for(opcode: str) -> str:
    """Best-effort operator. test is a mask check, cmp needs the following jcc."""
    return "bitwise_and" if opcode == "test" else "unknown"


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
            # Wide hits get a strictly-lower proximity factor so they rank below
            # narrow hits captured right at the call site.
            proximity = 0.5 * (1 - dist / WIDE) if wide else 1 - dist / NARROW
            readability = 0.7 if _has_unreadable_mem(r) else 1.0
            confidence = _clamp(BASE_CONFIDENCE * proximity * readability)
            comparisons.append(
                {
                    "comparison_operator": _operator_for(r.opcode),
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

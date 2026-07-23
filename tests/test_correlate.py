"""Offline tests for the Channel-3 proximity correlator.

Fixture-driven, no network, no monkeypatch. The synthetic log places cmp/test
records in and out of the windows of the input record's candidates.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from clew.channels.cape.correlate import IMAGE_BASE, correlate_record
from clew.channels.cape.cmplog_parse import parse_cmplog_files

FIXTURES = Path(__file__).parent / "fixtures"


def _load_records():
    return parse_cmplog_files([FIXTURES / "cmplog_synth_01.log"])


def _load_input():
    return json.loads((FIXTURES / "correlate_input_01.json").read_text())


def _by_va(record):
    return {c["call_site_va"]: c for c in record["candidates"]}


def test_matching_candidate_ranked_and_far_candidate_empty():
    rec = correlate_record(_load_input(), _load_records())
    by_va = _by_va(rec)

    matched = by_va["0x00401000"]
    comparisons = matched["comparison_candidates"]
    assert comparisons, "matching candidate should get correlated comparisons"
    confs = [c["confidence"] for c in comparisons]
    assert confs == sorted(confs, reverse=True)
    assert all(c["source_channels"] == ["drio"] for c in comparisons)

    far = by_va["0x0040f000"]
    assert far["comparison_candidates"] == []
    assert far["comparison_operator"] == "unknown"
    assert far["evidence"]["cmp_operand_a"] is None
    assert far["evidence"]["cmp_operand_b"] is None


def test_loop_duplicates_collapse_to_one_entry():
    rec = correlate_record(_load_input(), _load_records())
    matched = _by_va(rec)["0x00401000"]
    # Four distinct comparisons in the narrow window; the loop PC fired 3x with
    # identical operands and collapses to a single entry.
    comparisons = matched["comparison_candidates"]
    assert len(comparisons) == 4
    keys = {(c["cmp_operand_a"], c["cmp_operand_b"]) for c in comparisons}
    assert keys == {("0x1", "0x2"), ("0x2a", "0x2a"), ("0x5", "0xff"), (None, "0x0")}


def test_operator_mapping_test_and_cmp():
    rec = correlate_record(_load_input(), _load_records())
    comparisons = _by_va(rec)["0x00401000"]["comparison_candidates"]
    by_operands = {(c["cmp_operand_a"], c["cmp_operand_b"]): c for c in comparisons}
    # test -> bitwise_and, cmp -> unknown (honest first cut).
    assert by_operands[("0x2a", "0x2a")]["comparison_operator"] == "bitwise_and"
    assert by_operands[("0x1", "0x2")]["comparison_operator"] == "unknown"


def test_unreadable_mem_renders_null_and_lowers_confidence():
    rec = correlate_record(_load_input(), _load_records())
    comparisons = _by_va(rec)["0x00401000"]["comparison_candidates"]
    by_operands = {(c["cmp_operand_a"], c["cmp_operand_b"]): c for c in comparisons}
    unreadable = by_operands[(None, "0x0")]
    concrete = by_operands[("0x1", "0x2")]
    # readability factor 0.7 must sink the unreadable-mem comparison below a
    # closer, fully-concrete one.
    assert unreadable["confidence"] < concrete["confidence"]


def test_legacy_fields_mirror_top_entry():
    rec = correlate_record(_load_input(), _load_records())
    matched = _by_va(rec)["0x00401000"]
    top = matched["comparison_candidates"][0]
    assert matched["comparison_operator"] == top["comparison_operator"]
    assert matched["evidence"]["cmp_operand_a"] == top["cmp_operand_a"]
    assert matched["evidence"]["cmp_operand_b"] == top["cmp_operand_b"]


def test_return_value_wide_window_ranks_below_narrow():
    rec = correlate_record(_load_input(), _load_records())
    # The -1 candidate accepts a wider band; the wide hit must rank strictly
    # below the narrow hit for the same candidate.
    comparisons = _by_va(rec)["0x00402000"]["comparison_candidates"]
    assert len(comparisons) == 2
    narrow = next(c for c in comparisons if c["cmp_operand_a"] == "0x7")
    wide = next(c for c in comparisons if c["cmp_operand_a"] == "0x8")
    assert narrow["confidence"] > wide["confidence"]
    assert comparisons[0] is narrow


def test_call_site_and_parameter_index_are_not_mutated():
    rec = correlate_record(_load_input(), _load_records())
    by_va = _by_va(rec)
    assert by_va["0x00401000"]["parameter_index"] == 0
    assert by_va["0x00402000"]["parameter_index"] == -1
    assert set(by_va) == {"0x00401000", "0x00402000", "0x0040f000"}


@pytest.mark.parametrize("module_base", [None, 0x10000000])
def test_module_base_rebases_matching(module_base):
    records = _load_records()
    if module_base is not None:
        # Shift every PC as if the module loaded at module_base; rebase must
        # recover the static VAs so the same records land in-window.
        offset = module_base - IMAGE_BASE
        records = [dataclasses.replace(r, pc=r.pc + offset) for r in records]
    rec = correlate_record(_load_input(), records, module_base=module_base)
    matched = _by_va(rec)["0x00401000"]
    assert len(matched["comparison_candidates"]) == 4


def test_enriched_record_validates_against_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).resolve().parent.parent / "schema" / "clew_record.schema.json"
    if not schema_path.exists():
        pytest.skip("clew_record.schema.json not found")
    schema = json.loads(schema_path.read_text())
    rec = correlate_record(_load_input(), _load_records())
    jsonschema.validate(rec, schema)  # raises on any schema violation

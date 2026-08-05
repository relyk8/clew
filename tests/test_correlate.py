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


def test_warns_when_no_records_rebase_into_module(caplog):
    # D4: many records parsed but none land in the static module range (a wrong or
    # missing --module-base) must warn, not fail silently to an empty result.
    import logging

    from clew.channels.cape.cmplog_parse import CmpRecord

    record = {"candidates": [{"call_site_va": "0x401000", "parameter_index": 0, "evidence": {}}]}
    # 2000 records at an ASLR-relocated base far from 0x401000, no --module-base.
    recs = [CmpRecord(tid=1, pc=0xBF0000 + i, opcode="cmp", operands=[]) for i in range(2000)]
    with caplog.at_level(logging.WARNING):
        correlate_record(record, recs)
    assert "none landed in the static module range" in caplog.text
    assert record["candidates"][0]["comparison_candidates"] == []


def test_no_warn_when_records_land_in_module(caplog):
    import logging

    from clew.channels.cape.cmplog_parse import CmpRecord

    record = {"candidates": [{"call_site_va": "0x401000", "parameter_index": 0, "evidence": {}}]}
    # 2000 records right after the call site: they land in-module -> no warning.
    recs = [CmpRecord(tid=1, pc=0x401000 + (i % 200), opcode="cmp", operands=[]) for i in range(2000)]
    with caplog.at_level(logging.WARNING):
        correlate_record(record, recs)
    assert "none landed" not in caplog.text


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


def test_narrow_edge_hit_outranks_wide_just_past_boundary():
    # scout #7: previously a wide hit just past NARROW could out-score a narrow
    # hit near the NARROW edge (non-monotonic). Both must still be emitted, but
    # the narrow one must rank first.
    from clew.channels.cape.cmplog_parse import CmpRecord, Operand
    from clew.channels.cape.correlate import NARROW

    csva = 0x401000
    record = {"candidates": [{"call_site_va": "0x401000", "parameter_index": -1, "evidence": {}}]}
    recs = [
        CmpRecord(tid=1, pc=csva + NARROW - 6, opcode="cmp", operands=[Operand("imm", value=0x1)]),
        CmpRecord(tid=1, pc=csva + NARROW + 6, opcode="cmp", operands=[Operand("imm", value=0x2)]),
    ]
    correlate_record(record, recs)
    comps = record["candidates"][0]["comparison_candidates"]
    assert len(comps) == 2  # quantity preserved: both emitted
    assert comps[0]["cmp_operand_a"] == "0x1"  # the narrow (edge) hit ranks first


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


def _cmp(opcode="cmp", jcc=None):
    from clew.channels.cape.cmplog_parse import CmpRecord

    return CmpRecord(tid=1, pc=0x401010, opcode=opcode, operands=[], jcc=jcc)


def test_test_opcode_is_a_mask_check_regardless_of_jcc():
    from clew.channels.cape.correlate import _operator_for

    assert _operator_for(_cmp("test")) == "bitwise_and"
    assert _operator_for(_cmp("test", "jz")) == "bitwise_and"


def test_cmp_without_a_jcc_stays_unknown():
    """A legacy cmplog log carries no jcc, and the client declines to attribute
    one when another instruction rewrites the flags first. Neither is a licence
    to guess an operator."""
    from clew.channels.cape.correlate import _operator_for

    assert _operator_for(_cmp("cmp")) == "unknown"


@pytest.mark.parametrize(
    "jcc,expected",
    [
        ("je", "equality"),
        ("jz", "equality"),
        ("jne", "inequality"),
        ("jnz", "inequality"),
        ("jl", "less_than"),
        ("jb", "less_than"),
        ("jnae", "less_than"),
        ("jle", "less_equal"),
        ("jbe", "less_equal"),
        ("jg", "greater_than"),
        ("ja", "greater_than"),
        ("jnbe", "greater_than"),
        ("jge", "greater_equal"),
        ("jae", "greater_equal"),
        ("jnb", "greater_equal"),
    ],
)
def test_cmp_resolves_to_a_concrete_operator_from_its_jcc(jcc, expected):
    from clew.channels.cape.correlate import _operator_for

    assert _operator_for(_cmp("cmp", jcc)) == expected
    assert _operator_for(_cmp("cmp", jcc.upper())) == expected


@pytest.mark.parametrize("jcc", ["js", "jns", "jo", "jno", "jp", "jnp", "jcxz", "jecxz"])
def test_non_relational_conditions_are_not_forced_onto_an_operator(jcc):
    """Sign, overflow, parity and the jcxz family do not describe a relation
    between the two operands; calling them equality or less_than would be a
    worse answer than unknown."""
    from clew.channels.cape.correlate import _operator_for

    assert _operator_for(_cmp("cmp", jcc)) == "unknown"


def test_every_mapped_operator_is_a_schema_token():
    """The mapping feeds comparison_operator directly, so a typo here would ship
    a record that fails its own schema."""
    from clew.channels.cape.correlate import _JCC_OPERATOR

    schema_path = Path(__file__).parent.parent / "schema" / "clew_record.schema.json"
    allowed = set(json.loads(schema_path.read_text())["$defs"]["ComparisonOperator"]["enum"])
    assert set(_JCC_OPERATOR.values()) <= allowed


def _trace(modules):
    from clew.channels.cape.drtrace_parse import ModuleRecord, Trace

    return Trace(modules=[ModuleRecord(seq=i, base=b, end=e, name=n)
                          for i, (b, e, n) in enumerate(modules, 1)])


def test_explicit_module_base_overrides_the_logged_table():
    """--module-base is the analyst's override and must win over the table."""
    from clew.channels.cape.correlate import resolve_module_base

    trace = _trace([(0xBF0000, 0xC50000, "autoit3.exe")])
    assert resolve_module_base(trace, explicit=0x400000) == 0x400000


def test_module_base_comes_from_the_logged_table():
    from clew.channels.cape.correlate import resolve_module_base

    trace = _trace([(0xBF0000, 0xC50000, "autoit3.exe"), (0x77C10000, 0x77D50000, "ntdll.dll")])
    assert resolve_module_base(trace) == 0xBF0000


def test_module_base_prefers_the_records_own_sample_name():
    from clew.channels.cape.correlate import resolve_module_base

    trace = _trace([(0x400000, 0x410000, "helper.exe"), (0xBF0000, 0xC50000, "autoit3.exe")])
    record = {"sample_path": "/tmp/cuckoo/upload_x/autoit3.exe"}
    assert resolve_module_base(trace, record) == 0xBF0000


def test_no_module_table_leaves_pcs_unrebased():
    """A legacy cmplog log has no module records. Passing PCs through unchanged
    is right when the module loaded at its preferred base -- what task 11 did."""
    from clew.channels.cape.correlate import resolve_module_base

    assert resolve_module_base(_trace([])) is None


# --- hybrid merge of observed API calls -------------------------------------


def _call(api="GetModuleHandleW", site=0x401005, seq=10, args=None, argstr=None,
          outstr=None, retval=0, returned=True):
    from clew.channels.cape.drtrace_parse import ApiCall

    return ApiCall(
        seq=seq, tid=1, api=api, site=site,
        args=args or {}, arg_strings=argstr or {},
        return_seq=seq + 1 if returned else None,
        retval=retval if returned else None,
        out_strings=outstr or {},
    )


def _trace_with(calls, modules=()):
    from clew.channels.cape.drtrace_parse import ModuleRecord, Trace

    return Trace(
        modules=[ModuleRecord(seq=i, base=b, end=e, name=n)
                 for i, (b, e, n) in enumerate(modules, 1)],
        calls=list(calls),
    )


def _stub_record(csva="0x00401000", param=0, api="GetModuleHandleW", value=None,
                 function_va="0x00400f00"):
    return {
        "candidates": [
            {
                "call_site_va": csva,
                "function_va": function_va,
                "api_name": api,
                "api_resolution": "import",
                "parameter_index": param,
                "comparison_operator": "unknown",
                "candidate_values": [
                    {"value": value, "represents": "unknown", "retarget_to": None,
                     "confidence": 0.0 if value is None else 0.7,
                     "source_channels": ["bn_xref"]}
                ],
                "evidence": {"channels": ["bn_xref"], "cmp_operand_a": None,
                             "cmp_operand_b": None},
            }
        ]
    }


def test_return_address_joins_to_the_call_instruction_not_past_it():
    """drwrap logs the address the API returns to; Unit 3 records the address of
    the call instruction. Matching on equality would find nothing, on every
    sample, while looking exactly like a sample that was never observed."""
    from clew.channels.cape.correlate import match_call_site

    sites = {0x401000}
    assert match_call_site(0x401005, sites) == 0x401000  # E8 rel32
    assert match_call_site(0x401006, sites) == 0x401000  # FF 15 disp32
    assert match_call_site(0x401002, sites) == 0x401000  # FF D0
    assert match_call_site(0x401000, sites) is None      # the call itself
    assert match_call_site(0x401064, sites) is None      # far too distant


def test_nearest_call_site_wins_when_several_are_in_range():
    from clew.channels.cape.correlate import match_call_site

    assert match_call_site(0x401006, {0x401000, 0x401004}) == 0x401004


def test_observed_argument_fills_an_unresolved_static_stub():
    """The point of the whole channel: Channel 2 found the call site but could
    not resolve what flowed in, and the runtime observation answers it."""
    from clew.channels.cape.correlate import merge_observed_calls

    record = _stub_record()
    merge_observed_calls(record, _trace_with([_call(argstr={0: "SbieDll.dll"})]))

    candidate = next(c for c in record["candidates"] if c["parameter_index"] == 0)
    values = candidate["candidate_values"]
    assert [v["value"] for v in values] == [None, "SbieDll.dll"]
    assert values[1]["confidence"] == 0.95
    assert values[1]["source_channels"] == ["drio"]
    # The stub is kept, not overwritten: it is still what static concluded.
    assert values[0]["confidence"] == 0.0
    assert "drio" in candidate["evidence"]["channels"]


def test_runtime_confirmation_of_a_static_value_unions_rather_than_duplicates():
    """Static inferred it and runtime saw it: one value with two sources."""
    from clew.channels.cape.correlate import merge_observed_calls

    record = _stub_record(value="SbieDll.dll")
    merge_observed_calls(record, _trace_with([_call(argstr={0: "SbieDll.dll"})]))

    (value,) = record["candidates"][0]["candidate_values"]
    assert value["source_channels"] == ["bn_xref", "drio"]
    assert value["confidence"] == 0.95


def test_return_value_fills_a_parameter_index_minus_one_stub():
    from clew.channels.cape.correlate import merge_observed_calls

    record = _stub_record(param=-1)
    merge_observed_calls(record, _trace_with([_call(retval=0)]))

    values = record["candidates"][0]["candidate_values"]
    assert [v["value"] for v in values] == [None, 0]


def test_out_parameter_becomes_a_value_the_binary_never_contained():
    from clew.channels.cape.correlate import merge_observed_calls

    record = _stub_record(api="GetComputerNameA", param=0)
    merge_observed_calls(
        record,
        _trace_with([_call(api="GetComputerNameA", outstr={0: "DESKTOP-7F2K9"}, retval=1)]),
    )
    values = record["candidates"][0]["candidate_values"]
    assert "DESKTOP-7F2K9" in [v["value"] for v in values]


def test_an_unchanged_argument_is_not_reported_twice():
    """An in-string that is still there after the call was an input, not an
    out-parameter."""
    from clew.channels.cape.correlate import merge_observed_calls

    record = _stub_record()
    merge_observed_calls(
        record,
        _trace_with([_call(argstr={0: "kernel32.dll"}, outstr={0: "kernel32.dll"})]),
    )
    values = [v["value"] for v in record["candidates"][0]["candidate_values"]]
    assert values.count("kernel32.dll") == 1


def test_call_at_an_unenumerated_site_becomes_a_new_candidate():
    """Channel 3 producing rather than annotating: a site Unit 3 never found."""
    from clew.channels.cape.correlate import merge_observed_calls

    record = _stub_record()
    merge_observed_calls(
        record,
        _trace_with([_call(api="GetVolumeInformationW", site=0x43F108,
                           outstr={1: "VMware"})]),
    )
    fresh = [c for c in record["candidates"] if c["api_name"] == "GetVolumeInformationW"]
    assert [c["api_resolution"] for c in fresh] == ["runtime", "runtime"]
    assert {c["parameter_index"] for c in fresh} == {1, -1}  # out-param and retval
    assert all(c["evidence"]["channels"] == ["drio"] for c in fresh)
    # 0x43f108 lies past every function the static pass identified, so there is
    # no evidence placing it in one: null, and present rather than omitted.
    assert all(c["function_va"] is None for c in fresh)


def test_new_candidate_at_a_known_site_borrows_that_sites_function_va():
    """A known call site whose parameter had no static candidate: the enclosing
    function is known from its sibling, so it should be carried over."""
    from clew.channels.cape.correlate import merge_observed_calls

    record = _stub_record(param=0)
    merge_observed_calls(record, _trace_with([_call(retval=0x7C800000)]))

    fresh = [c for c in record["candidates"] if c["api_resolution"] == "runtime"]
    assert len(fresh) == 1
    assert fresh[0]["parameter_index"] == -1
    assert fresh[0]["function_va"] == "0x00400f00"


def test_a_looping_call_site_contributes_each_distinct_value_once():
    from clew.channels.cape.correlate import merge_observed_calls

    record = _stub_record()
    calls = [_call(argstr={0: "SbieDll.dll"}, seq=n) for n in range(20)]
    merge_observed_calls(record, _trace_with(calls))

    values = [v["value"] for v in record["candidates"][0]["candidate_values"]]
    assert values.count("SbieDll.dll") == 1


def test_merge_never_demotes_an_unobserved_candidate():
    """One detonation covers one path. A candidate that did not run this time is
    unobserved, not disproven."""
    from clew.channels.cape.correlate import merge_observed_calls

    record = _stub_record(value="untouched")
    before = json.loads(json.dumps(record))
    merge_observed_calls(record, _trace_with([]))
    assert record == before


def test_correlate_trace_rebases_from_the_module_table():
    """The sample loaded at 0xbf0000; its static image base is 0x400000. Without
    the table this needed a hand-passed --module-base."""
    from clew.channels.cape.correlate import correlate_trace

    record = _stub_record()
    trace = _trace_with(
        [_call(site=0xBF1005, argstr={0: "SbieDll.dll"})],
        modules=[(0xBF0000, 0xC50000, "s.exe")],
    )
    correlate_trace(record, trace)

    matched = next(c for c in record["candidates"] if c["parameter_index"] == 0)
    assert "SbieDll.dll" in [v["value"] for v in matched["candidate_values"]]
    # The site matched the static candidate rather than being treated as new, so
    # the only candidate added is the one for the call's return value.
    added = [c for c in record["candidates"] if c["api_resolution"] == "runtime"]
    assert [c["parameter_index"] for c in added] == [-1]


# --- placing a runtime call site in a function ------------------------------


def _spans_record():
    """Two functions the static pass found, with a gap between them that no
    identified function spans."""
    def cand(fva, csva):
        return {"call_site_va": csva, "function_va": fva, "api_name": "X",
                "api_resolution": "import", "parameter_index": 0,
                "candidate_values": [], "evidence": {"channels": ["bn_xref"]}}

    return [
        cand("0x00401000", "0x00401010"),
        cand("0x00401000", "0x00401040"),   # function A known to reach 0x401040
        cand("0x00402000", "0x00402008"),   # function B known to reach 0x402008
    ]


def test_function_span_is_the_highest_known_call_site():
    from clew.channels.cape.correlate import build_function_spans

    assert build_function_spans(_spans_record()) == [
        (0x401000, 0x401040, "0x00401000"),
        (0x402000, 0x402008, "0x00402000"),
    ]


def test_site_inside_a_known_function_extent_is_placed():
    from clew.channels.cape.correlate import build_function_spans, function_va_for

    spans = build_function_spans(_spans_record())
    # Between the function start and the furthest call site the record evidences.
    assert function_va_for(0x401020, spans) == "0x00401000"
    assert function_va_for(0x401040, spans) == "0x00401000"


def test_site_beyond_the_known_extent_is_null_not_guessed():
    """Past the last call site the record evidences there is nothing to say the
    function still runs -- BN may not have carved a function there at all, which
    is the usual reason Unit 3 missed the site."""
    from clew.channels.cape.correlate import build_function_spans, function_va_for

    spans = build_function_spans(_spans_record())
    assert function_va_for(0x401041, spans) is None
    assert function_va_for(0x401900, spans) is None   # the gap between A and B


def test_site_below_every_known_function_is_null():
    from clew.channels.cape.correlate import build_function_spans, function_va_for

    spans = build_function_spans(_spans_record())
    assert function_va_for(0x400010, spans) is None


def test_a_later_function_disqualifies_an_earlier_one():
    """Choosing the nearest function at or below the site means a function
    starting in between rules out the earlier one automatically."""
    from clew.channels.cape.correlate import build_function_spans, function_va_for

    spans = build_function_spans(_spans_record())
    assert function_va_for(0x402004, spans) == "0x00402000"


def test_unenumerated_site_inside_a_known_function_gets_placed():
    from clew.channels.cape.correlate import merge_observed_calls

    record = _stub_record(csva="0x00401000", function_va="0x00400f00")
    # 0x401080 is past the only known call site, so it cannot be placed...
    merge_observed_calls(record, _trace_with([_call(site=0x401082, returned=False,
                                                   argstr={0: "a.dll"})]))
    fresh = [c for c in record["candidates"] if c["api_resolution"] == "runtime"]
    assert fresh[0]["function_va"] is None


def test_function_va_is_null_never_absent():
    """A uniform shape for the consumer: null says 'no answer', a missing key
    just looks like a different kind of record."""
    from clew.channels.cape.correlate import merge_observed_calls

    record = _stub_record()
    merge_observed_calls(record, _trace_with([_call(site=0x999999, returned=False,
                                                   argstr={0: "x.dll"})]))
    fresh = [c for c in record["candidates"] if c["api_resolution"] == "runtime"]
    assert all("function_va" in c for c in fresh)
    assert fresh[0]["function_va"] is None


# --- temporal join ----------------------------------------------------------


def _cmp_at(seq, tid=1, pc=0x401100, opcode="cmp", jcc="jz", a=0x1, b=0x2):
    from clew.channels.cape.cmplog_parse import CmpRecord, Operand

    return CmpRecord(
        tid=tid, pc=pc, opcode=opcode, seq=seq, jcc=jcc,
        operands=[Operand("reg", value=a, reg="eax"), Operand("imm", value=b)],
    )


def _retval_record(csva="0x00401000"):
    return {
        "candidates": [
            {
                "call_site_va": csva,
                "function_va": "0x00400f00",
                "api_name": "GetTickCount",
                "api_resolution": "import",
                "parameter_index": -1,
                "comparison_operator": "unknown",
                "candidate_values": [],
                "evidence": {"channels": ["bn_xref"], "cmp_operand_a": None,
                             "cmp_operand_b": None},
            }
        ]
    }


def test_comparison_after_a_return_binds_to_that_call():
    """The channel's stated purpose: operands captured *after* an API returns."""
    from clew.channels.cape.correlate import merge_temporal_comparisons
    from clew.channels.cape.drtrace_parse import Trace

    record = _retval_record()
    trace = Trace(
        calls=[_call(api="GetTickCount", site=0x401005, seq=10, retval=0x4a3f)],
        comparisons=[_cmp_at(seq=12, a=0x4a3f, b=0x1388)],
    )
    merge_temporal_comparisons(record, trace)

    (cc,) = record["candidates"][0]["comparison_candidates"]
    assert cc["binding"] == "temporal"
    assert (cc["cmp_operand_a"], cc["cmp_operand_b"]) == ("0x4a3f", "0x1388")
    # Above anything the proximity pass can produce (BASE_CONFIDENCE is 0.6).
    assert cc["confidence"] > 0.6
    assert record["candidates"][0]["comparison_operator"] == "equality"


def test_comparison_before_the_return_is_not_bound():
    from clew.channels.cape.correlate import merge_temporal_comparisons
    from clew.channels.cape.drtrace_parse import Trace

    record = _retval_record()
    trace = Trace(
        calls=[_call(api="GetTickCount", site=0x401005, seq=10, retval=0x1)],
        comparisons=[_cmp_at(seq=5)],  # ran before the call returned (seq 11)
    )
    merge_temporal_comparisons(record, trace)
    assert record["candidates"][0].get("comparison_candidates", []) == []


def test_another_traced_call_ends_the_window():
    """Once a second API is entered, later comparisons are about that one."""
    from clew.channels.cape.correlate import merge_temporal_comparisons
    from clew.channels.cape.drtrace_parse import Trace

    record = _retval_record()
    trace = Trace(
        calls=[
            _call(api="GetTickCount", site=0x401005, seq=10, retval=0x1),
            _call(api="Sleep", site=0x402005, seq=20, retval=0x0),
        ],
        comparisons=[_cmp_at(seq=12, a=0xaa), _cmp_at(seq=25, a=0xbb)],
    )
    merge_temporal_comparisons(record, trace)
    ops = [c["cmp_operand_a"] for c in record["candidates"][0]["comparison_candidates"]]
    assert ops == ["0xaa"]


def test_comparisons_on_another_thread_are_not_bound():
    from clew.channels.cape.correlate import merge_temporal_comparisons
    from clew.channels.cape.drtrace_parse import Trace

    record = _retval_record()
    trace = Trace(
        calls=[_call(api="GetTickCount", site=0x401005, seq=10, retval=0x1)],
        comparisons=[_cmp_at(seq=12, tid=99)],
    )
    merge_temporal_comparisons(record, trace)
    assert record["candidates"][0].get("comparison_candidates", []) == []


def test_nearer_comparisons_outrank_later_ones():
    from clew.channels.cape.correlate import merge_temporal_comparisons
    from clew.channels.cape.drtrace_parse import Trace

    record = _retval_record()
    trace = Trace(
        calls=[_call(api="GetTickCount", site=0x401005, seq=10, retval=0x1)],
        comparisons=[_cmp_at(seq=12, a=0xaa), _cmp_at(seq=13, a=0xbb),
                     _cmp_at(seq=14, a=0xcc)],
    )
    merge_temporal_comparisons(record, trace)
    ops = [c["cmp_operand_a"] for c in record["candidates"][0]["comparison_candidates"]]
    assert ops == ["0xaa", "0xbb", "0xcc"]


def test_window_is_bounded():
    from clew.channels.cape.correlate import TEMPORAL_WINDOW, merge_temporal_comparisons
    from clew.channels.cape.drtrace_parse import Trace

    record = _retval_record()
    trace = Trace(
        calls=[_call(api="GetTickCount", site=0x401005, seq=10, retval=0x1)],
        comparisons=[_cmp_at(seq=12 + n, a=n) for n in range(TEMPORAL_WINDOW * 3)],
    )
    merge_temporal_comparisons(record, trace)
    assert len(record["candidates"][0]["comparison_candidates"]) == TEMPORAL_WINDOW


def test_a_proximity_guess_the_ordering_confirms_is_upgraded_not_duplicated():
    """Same comparison, better evidence for it -- one entry, promoted."""
    from clew.channels.cape.correlate import correlate_trace
    from clew.channels.cape.drtrace_parse import ModuleRecord, Trace

    record = _retval_record()
    # PC sits inside the proximity window after 0x401000 AND executes right
    # after the call returns, so both passes see it.
    shared = _cmp_at(seq=12, pc=0x401010, a=0x4a3f, b=0x1388)
    trace = Trace(
        modules=[ModuleRecord(seq=1, base=0x400000, end=0x410000, name="s.exe")],
        calls=[_call(api="GetTickCount", site=0x401005, seq=10, retval=0x4a3f)],
        comparisons=[shared],
    )
    correlate_trace(record, trace)

    ccs = record["candidates"][0]["comparison_candidates"]
    assert len(ccs) == 1, "the proximity entry should be upgraded, not duplicated"
    assert ccs[0]["binding"] == "temporal"
    assert ccs[0]["confidence"] > 0.6


def test_legacy_cmplog_comparisons_have_no_seq_and_bind_only_by_proximity():
    """A cmplog log carries no ordering, so the temporal pass must be a no-op
    rather than binding everything to the first call it sees."""
    from clew.channels.cape.cmplog_parse import CmpRecord, Operand
    from clew.channels.cape.correlate import merge_temporal_comparisons
    from clew.channels.cape.drtrace_parse import Trace

    record = _retval_record()
    trace = Trace(
        calls=[_call(api="GetTickCount", site=0x401005, seq=10, retval=0x1)],
        comparisons=[CmpRecord(tid=1, pc=0x401010, opcode="cmp",
                               operands=[Operand("imm", value=1)])],
    )
    merge_temporal_comparisons(record, trace)
    assert record["candidates"][0].get("comparison_candidates", []) == []


def test_binding_is_recorded_on_proximity_entries_too():
    rec = correlate_record(_load_input(), _load_records())
    ccs = _by_va(rec)["0x00401000"]["comparison_candidates"]
    assert ccs and all(c["binding"] == "proximity" for c in ccs)

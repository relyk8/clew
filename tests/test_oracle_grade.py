"""Tests for oracle grading.

Two layers:
  * Offline: exercise the grading logic with synthetic oracle/bridge dicts.
    These run everywhere (no BN, no fixtures).
  * Live (BN-gated): run the real bridge against al-khaser and grade its output
    against the hand-built `1fe91674eb8d_01/02.expected.json` oracles. Skipped
    automatically when Binary Ninja or the fixture binary is not present.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from clew.eval import oracle_grade as og

# --- synthetic candidate builders --------------------------------------------


def _bridge_array_candidate():
    """What to_partial_candidates() emits for the 12-DLL loop (abbreviated)."""
    return {
        "call_site_va": "0x004595fc",
        "function_va": "0x00459500",
        "api_name": "GetModuleHandleW",
        "api_resolution": "import",
        "parameter_index": 0,
        "comparison_operator": "unknown",
        "candidate_values": [
            {
                "value": "sbiedll.dll",
                "represents": "unknown",
                "retarget_to": None,
                "confidence": 0.9,
                "source_channels": ["bn_xref", "floss"],
            },
            {
                "value": "dbghelp.dll",
                "represents": "unknown",
                "retarget_to": None,
                "confidence": 0.9,
                "source_channels": ["bn_xref", "floss"],
            },
        ],
        "evidence": {
            "channels": ["bn_xref", "floss"],
            "string_source": "static",
            "string_va": None,
            "string_function_va": None,
            "dataflow_path": ["0x004595f7", "0x004595fb", "0x004595fc"],
            "cmp_operand_a": None,
            "cmp_operand_b": None,
        },
    }


def _oracle_array_candidate(values=("SbieDll.dll", "dbghelp.dll")):
    """A full schema candidate the way a hand-built oracle would write it."""
    return {
        "call_site_va": "0x004595fc",
        "function_va": "0x00459500",
        "api_name": "GetModuleHandleW",
        "api_resolution": "import",
        "parameter_index": 0,
        "comparison_operator": "equality",
        "evasion_tier": "tier_1",
        "iteration_number": 0,
        "candidate_values": [
            {
                "value": v,
                "represents": "sandbox_detected",
                "retarget_to": None,
                "confidence": 0.9,
                "source_channels": ["floss", "bn_xref"],
            }
            for v in values
        ],
        "coordination_constraint": {
            "gate_group_id": "modnames",
            "description": "OR over module names",
        },
        "evidence": {
            "channels": ["bn_xref", "floss"],
            "string_source": "static",
            "string_va": None,
            "string_function_va": None,
            "dataflow_path": ["0x004595fc"],
            "cmp_operand_a": None,
            "cmp_operand_b": None,
        },
    }


def _bridge_return_value_stub():
    """What the bridge emits for IsDebuggerPresent: located, unresolved, p=-1."""
    return {
        "call_site_va": "0x00434d4a",
        "function_va": "0x00434d20",
        "api_name": "IsDebuggerPresent",
        "api_resolution": "import",
        "parameter_index": -1,
        "comparison_operator": "unknown",
        "candidate_values": [
            {
                "value": None,
                "represents": "unknown",
                "retarget_to": None,
                "confidence": 0.0,
                "source_channels": ["bn_xref"],
            }
        ],
        "evidence": {
            "channels": ["bn_xref"],
            "string_source": None,
            "string_va": None,
            "string_function_va": None,
            "dataflow_path": ["0x00434d4a"],
            "cmp_operand_a": None,
            "cmp_operand_b": None,
        },
    }


def _oracle_return_value_candidate():
    """IsDebuggerPresent return-value check, fully classified by derivation."""
    return {
        "call_site_va": "0x00434d4a",
        "function_va": "0x00434d20",
        "api_name": "IsDebuggerPresent",
        "api_resolution": "import",
        "parameter_index": -1,
        "comparison_operator": "inequality",
        "evasion_tier": "tier_1",
        "iteration_number": 0,
        "candidate_values": [
            {
                "value": True,
                "represents": "debugger_detected",
                "retarget_to": False,
                "confidence": 0.9,
                "source_channels": ["bn_xref"],
            }
        ],
        "coordination_constraint": {"gate_group_id": None, "description": None},
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


# --- offline grading-logic tests ---------------------------------------------


def test_array_candidate_passes_when_values_match_case_insensitively():
    # oracle uses source casing "SbieDll.dll"; bridge has binary casing "sbiedll.dll"
    g = og.grade_candidate(_oracle_array_candidate(), _bridge_array_candidate())
    assert g.matched and g.passed
    # structural + parameter_index + value-set all graded True
    assert all(f.ok is not False for f in g.fields)


def test_derivation_fields_are_report_only_never_fail():
    g = og.grade_candidate(_oracle_array_candidate(), _bridge_array_candidate())
    for name in (
        "comparison_operator",
        "evasion_tier",
        "coordination_constraint",
        "candidate_values.represents/retarget_to",
    ):
        fv = next(f for f in g.fields if f.field == name)
        assert fv.ok is None  # reported, not graded
    assert g.passed  # despite bridge leaving them unset


def test_missing_value_fails_the_candidate():
    # oracle expects a third module name the bridge never found
    oracle = _oracle_array_candidate(values=("SbieDll.dll", "dbghelp.dll", "cuckoomon.dll"))
    g = og.grade_candidate(oracle, _bridge_array_candidate())
    vf = next(f for f in g.fields if f.field == "candidate_values.value(set)")
    assert vf.ok is False and "cuckoomon.dll" in vf.note
    assert not g.passed


def test_extra_bridge_value_is_allowed():
    # bridge found more than the oracle recorded -> noted, still passes
    oracle = _oracle_array_candidate(values=("SbieDll.dll",))
    g = og.grade_candidate(oracle, _bridge_array_candidate())
    vf = next(f for f in g.fields if f.field == "candidate_values.value(set)")
    assert vf.ok is True and "extra" in vf.note
    assert g.passed


def test_return_value_candidate_graded_on_structure_only():
    g = og.grade_candidate(_oracle_return_value_candidate(), _bridge_return_value_stub())
    assert g.is_return_value and g.matched and g.passed
    # the value field is report-only for a return-value check
    vf = next(f for f in g.fields if f.field == "candidate_values.value")
    assert vf.ok is None and "Channel 3" in vf.note
    # structural identification is graded and matches
    for name in ("call_site_va", "function_va", "api_name", "api_resolution", "parameter_index"):
        assert next(f for f in g.fields if f.field == name).ok is True


def test_return_value_wrong_call_site_still_fails_structural():
    stub = _bridge_return_value_stub()
    stub["function_va"] = "0x00999999"  # bridge mislocated the function
    g = og.grade_candidate(_oracle_return_value_candidate(), stub)
    assert next(f for f in g.fields if f.field == "function_va").ok is False
    assert not g.passed


def test_no_bridge_candidate_is_not_a_pass():
    g = og.grade_candidate(_oracle_array_candidate(), None)
    assert not g.matched and not g.passed


def test_grade_record_matches_by_call_site_and_param():
    record = {"candidates": [_oracle_array_candidate(), _oracle_return_value_candidate()]}
    bridge = [_bridge_array_candidate(), _bridge_return_value_stub()]
    grades = og.grade_record(record, bridge)
    assert len(grades) == 2
    assert og.all_passed(grades)
    report = og.format_report(grades, title="synthetic")
    assert "2/2 candidates pass" in report


# --- live BN-gated grading against the real oracles --------------------------

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"
SAMPLE = FIX / "al-khaser_x86.exe"
FLOSS = FIX / "al-khaser_x86.floss.json"
ORACLES = [FIX / "1fe91674eb8d_01.expected.json", FIX / "1fe91674eb8d_02.expected.json"]


@pytest.fixture(scope="module")
def bridge_candidates():
    if not SAMPLE.exists():
        pytest.skip(f"fixture binary not present: {SAMPLE}")
    try:
        import binaryninja  # noqa: F401
    except Exception:
        pytest.skip("binaryninja not available")
    from clew.channels.binaryninja import callsites as bn_callsites
    from clew.channels.binaryninja import dataflow

    # BN may be importable while no license can be checked out (a partial-BN
    # box with no Enterprise server configured). That is an environment gap,
    # not a test failure, so skip rather than error. Real analysis failures
    # (BNAnalysisError) still propagate.
    try:
        cs = bn_callsites.run_bn_callsites(str(SAMPLE), run_license_checkout=True)
        fi = dataflow.FlossIndex.from_floss_json(FLOSS) if FLOSS.exists() else None
        df = dataflow.run_bn_dataflow(cs, str(SAMPLE), floss_index=fi, run_license_checkout=True)
    except bn_callsites.BNNotAvailableError as e:
        pytest.skip(f"Binary Ninja license not available: {e}")
    return df.to_partial_candidates(include_unresolved=True)


@pytest.mark.parametrize("oracle_path", ORACLES, ids=lambda p: p.name)
def test_bridge_matches_oracle(oracle_path, bridge_candidates):
    if not oracle_path.exists():
        pytest.skip(f"oracle not present: {oracle_path.name}")
    expected = json.loads(oracle_path.read_text())
    grades = og.grade_record(expected, bridge_candidates)
    print("\n" + og.format_report(grades, title=oracle_path.name))
    assert grades, "oracle record had no candidates"
    failures = [g for g in grades if not g.passed]
    assert not failures, (
        f"{len(failures)} candidate(s) failed bridge-owned grading in "
        f"{oracle_path.name}; see report above"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v", "-s"]))

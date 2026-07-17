"""Tests for Channel 2 (Binary Ninja call-site enumeration).

Mirrors tests/test_floss.py: env-var-gated integration tests that run real
headless BN, plus offline unit tests that exercise the adapter/serializer
against a saved intermediate JSON fixture without running BN.

Integration tests run only when BN_INTEGRATION is set (the BN analysis is
slow, needs the sample on disk, and needs a checked-out Enterprise license
-- source bn_env.sh first; see docs/binary_ninja_headless_setup.md).
Generate the offline fixture once with the real run:

    BN_INTEGRATION=1 python -c "from clew.channels.bn_callsites import \
        run_bn_callsites; run_bn_callsites('tests/fixtures/al-khaser_x86.exe')\
        .write_json('tests/fixtures/al-khaser_x86.bn_callsites.json')"
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from clew.channels.bn_callsites import (
    RESOLUTION_GETPROCADDRESS,
    RESOLUTION_IMPORT,
    RESOLUTION_ORDINAL,
    V1_SCHEMA_RESOLUTIONS,
    BNCallSites,
    CallSite,
    load_bn_results,
    run_bn_callsites,
)

# Ground truth is loaded directly from the hand-built record so it has a single
# source of truth -- do not copy its values here. The record's first candidate
# is IsDebuggerPresent, imported, call site 0x00434d4a in function 0x00434d20.
_GT_RECORD = json.loads(
    (Path(__file__).parent / "fixtures" / "1fe91674eb8d_01.expected.json").read_text()
)
_GT_CANDIDATE = _GT_RECORD["candidates"][0]
GT_API = _GT_CANDIDATE["api_name"]
GT_CALL_SITE_VA = int(_GT_CANDIDATE["call_site_va"], 16)
GT_FUNCTION_VA = int(_GT_CANDIDATE["function_va"], 16)

# al-khaser exercises a broad sweep of anti-debug/anti-VM APIs; a handful we
# expect BN to enumerate as call sites regardless of dataflow. Note the WIDE
# variant: al-khaser calls OutputDebugStringW (confirmed via BN symbol probe),
# reached through its ImportAddressSymbol (IAT slot) which carries the refs.
EXPECTED_SOME_APIS = frozenset(
    {
        "IsDebuggerPresent",
        "GetTickCount",
        "OutputDebugStringW",
    }
)


integration = pytest.mark.skipif(
    not os.environ.get("BN_INTEGRATION"),
    reason="set BN_INTEGRATION to run the (slow, licensed) real BN analysis",
)


# --- unit tests (offline; need the saved intermediate JSON fixture) ----------


@pytest.fixture
def bn_fixture(fixtures_dir):
    path = fixtures_dir / "al-khaser_x86.bn_callsites.json"
    if not path.exists():
        pytest.skip(f"BN fixture not generated yet: {path}")
    return path


def test_load_intermediate_json(bn_fixture):
    result = load_bn_results(bn_fixture)
    assert isinstance(result, BNCallSites)
    assert result.call_sites, "fixture has no call sites"
    assert result.bn_core_version.startswith("4.")


def test_isdebuggerpresent_call_site_present(bn_fixture):
    """The hand-built record's IsDebuggerPresent call site is enumerated at
    the exact VA, in the exact function, as an import."""
    result = load_bn_results(bn_fixture)
    matches = [cs for cs in result.for_api(GT_API) if cs.call_site_va == GT_CALL_SITE_VA]
    assert matches, (
        f"{GT_API} @ {hex(GT_CALL_SITE_VA)} not enumerated; "
        f"got call sites for {GT_API}: "
        f"{[hex(cs.call_site_va) for cs in result.for_api(GT_API)]}"
    )
    cs = matches[0]
    assert cs.function_va == GT_FUNCTION_VA
    assert cs.api_resolution == RESOLUTION_IMPORT


def test_all_resolutions_are_valid(bn_fixture):
    """Every emitted call site carries a known resolution; the intermediate
    JSON may include 'unknown', but schema_emittable() must not."""
    result = load_bn_results(bn_fixture)
    valid = V1_SCHEMA_RESOLUTIONS | {"unknown"}
    assert all(cs.api_resolution in valid for cs in result.call_sites)
    assert all(cs.api_resolution in V1_SCHEMA_RESOLUTIONS for cs in result.schema_emittable())


def test_no_hashed_resolution_in_v1(bn_fixture):
    """v1 reserves but never produces 'hashed'."""
    result = load_bn_results(bn_fixture)
    assert all(cs.api_resolution != "hashed" for cs in result.call_sites)


def test_partial_candidates_are_callsite_stubs(bn_fixture):
    """to_partial_candidates() emits bn_xref-only stubs with value/dataflow
    fields left for later units."""
    result = load_bn_results(bn_fixture)
    stubs = result.to_partial_candidates()
    assert stubs
    for stub in stubs:
        assert stub["evidence"]["channels"] == ["bn_xref"]
        assert stub["parameter_index"] is None
        assert stub["evidence"]["dataflow_path"] == []
        assert stub["api_resolution"] in V1_SCHEMA_RESOLUTIONS


def test_no_import_thunk_rows(bn_fixture):
    """Regression guard: import-thunk stubs (where the call site sits at the
    exact start of its containing function) must be filtered out. Before the
    thunk filter, 673/11205 al-khaser rows were these degenerate stubs."""
    result = load_bn_results(bn_fixture)
    degenerate = [cs for cs in result.call_sites if cs.call_site_va == cs.function_va]
    assert not degenerate, (
        f"{len(degenerate)} import-thunk rows leaked through the filter, "
        f"e.g. {[hex(degenerate[0].call_site_va)]}"
    )


def test_isdebuggerpresent_real_sites_only(bn_fixture):
    """Every IsDebuggerPresent row is a genuine call site (distinct call and
    function VAs), not a thunk stub."""
    result = load_bn_results(bn_fixture)
    idp = result.for_api(GT_API)
    assert idp, f"no {GT_API} call sites in fixture"
    for cs in idp:
        assert cs.call_site_va != cs.function_va, (
            f"thunk row for {GT_API} at {hex(cs.call_site_va)}"
        )


def test_no_duplicate_rows(bn_fixture):
    """Each (call_site_va, api_name) pair appears once. Guards the dedup that
    absorbs BN's occasional duplicate MLIL expression at one address."""
    result = load_bn_results(bn_fixture)
    keys = [(cs.call_site_va, cs.api_name) for cs in result.call_sites]
    assert len(keys) == len(set(keys)), (
        f"{len(keys) - len(set(keys))} duplicate (call_site, api) rows"
    )


def test_no_internal_function_names(bn_fixture):
    """No row names an internal function (sub_*, j_sub_*, loc_*) — those have
    no symbol in BN and must not be classified as imports."""
    result = load_bn_results(bn_fixture)
    bad = [
        cs.api_name
        for cs in result.call_sites
        if cs.api_name.startswith(("sub_", "j_sub_", "loc_", "j_loc_"))
    ]
    assert not bad, f"internal-function names leaked in as APIs: {set(bad)}"


def test_roundtrip_serialization(tmp_path):
    """to_dict/write_json -> load_bn_results is lossless."""
    original = BNCallSites(
        sample_path="x.exe",
        sample_sha256="ab" * 32,
        bn_core_version="4.2.6455",
        call_sites=[
            CallSite(GT_API, GT_CALL_SITE_VA, GT_FUNCTION_VA, RESOLUTION_IMPORT, "cdecl"),
            CallSite("LoadLibraryA", 0x401000, 0x401000, RESOLUTION_GETPROCADDRESS, "stdcall"),
            CallSite("ordinal_17", 0x402000, 0x402000, RESOLUTION_ORDINAL, "stdcall", ordinal=17),
        ],
    )
    out = tmp_path / "rt.json"
    original.write_json(out)
    reloaded = load_bn_results(out)
    assert reloaded.to_dict() == original.to_dict()
    assert reloaded.for_api("ordinal_17")[0].ordinal == 17


def test_va_hex_format(tmp_path):
    """VAs serialize as 0x-prefixed lowercase hex, matching the schema."""
    cs = CallSite(GT_API, GT_CALL_SITE_VA, GT_FUNCTION_VA, RESOLUTION_IMPORT, "cdecl")
    d = cs.to_dict()
    assert d["call_site_va"] == "0x00434d4a"
    assert d["function_va"] == "0x00434d20"


# --- integration tests (run the real tool) -----------------------------------


@integration
def test_run_enumerates_isdebuggerpresent(fixtures_dir):
    """Day-one grading target: real headless BN enumerates the hand-built
    IsDebuggerPresent call site at the exact VA and function."""
    sample = fixtures_dir / "al-khaser_x86.exe"
    result = run_bn_callsites(sample)
    matches = [cs for cs in result.for_api(GT_API) if cs.call_site_va == GT_CALL_SITE_VA]
    assert matches, (
        f"BN did not enumerate {GT_API} @ {hex(GT_CALL_SITE_VA)}; "
        f"found: {sorted(hex(cs.call_site_va) for cs in result.for_api(GT_API))}"
    )
    assert matches[0].function_va == GT_FUNCTION_VA
    assert matches[0].api_resolution == RESOLUTION_IMPORT


@integration
def test_run_finds_expected_api_sweep(fixtures_dir):
    """BN enumerates the broad anti-analysis API set al-khaser uses."""
    sample = fixtures_dir / "al-khaser_x86.exe"
    result = run_bn_callsites(sample)
    found = result.api_names()
    missing = EXPECTED_SOME_APIS - found
    assert not missing, f"BN missed expected API call sites: {missing}"


@integration
def test_run_reports_pinned_version(fixtures_dir):
    """Surfaces version skew against BN_PINS early."""
    sample = fixtures_dir / "al-khaser_x86.exe"
    result = run_bn_callsites(sample)
    assert result.bn_core_version.startswith("4.2"), (
        f"BN core version {result.bn_core_version} differs from validated pin; "
        "re-validate and bump BN_PINS."
    )

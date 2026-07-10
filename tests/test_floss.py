"""Tests for Channel 1 (FLOSS).

Mirrors tests/test_capa.py: env-var-gated integration tests that run the
real tool, plus offline unit tests that exercise the adapter against a
saved fixture without running FLOSS (~100s).

Integration tests run only when FLOSS_INTEGRATION is set (the FLOSS run is
slow and needs the sample on disk). The unit tests need a saved FLOSS JSON
fixture at tests/fixtures/al-khaser_x86.floss.json; generate it once with:

    floss -j tests/fixtures/al-khaser_x86.exe > tests/fixtures/al-khaser_x86.floss.json
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from clew.channels.floss import (
    FlossResult,
    FlossString,
    load_floss_results,
    run_floss,
    _adapt_result_document,
)


# The 12 DLL fingerprints in al-khaser's loaded_dlls candidate (record #2).
# capa's `reference anti-VM strings` rule covers 8 and misses 4; FLOSS must
# recover all 12 — that gap is Channel 1's reason to exist
# (docs/schema_v2_notes.md finding #2).
#
# The full set of 12 is loaded from the record's candidate_values so it has a
# single source of truth -- do not copy those values here.
_GT_RECORD = json.loads(
    (Path(__file__).parent / "fixtures" / "1fe91674eb8d_02.expected.json").read_text()
)
ALKHASER_DLLS_ALL = frozenset(
    cv["value"] for cv in _GT_RECORD["candidates"][0]["candidate_values"]
)
# The 4 DLLs capa's rule misses live nowhere else (the fixture's `represents`
# field is detection-category, not capa coverage), so keep them explicit and
# DERIVE the covered set. Assert the missed set is a subset of the loaded 12 so
# a fixture change that drops one of these DLLs surfaces here immediately.
ALKHASER_DLLS_CAPA_MISSED = frozenset({
    "dbghelp.dll", "sbiedll.dll", "api_log.dll", "dir_watch.dll",
})
assert ALKHASER_DLLS_CAPA_MISSED <= ALKHASER_DLLS_ALL, (
    "capa-missed DLLs absent from fixture "
    "1fe91674eb8d_02.expected.json: "
    f"{ALKHASER_DLLS_CAPA_MISSED - ALKHASER_DLLS_ALL}"
)
ALKHASER_DLLS_CAPA_COVERED = ALKHASER_DLLS_ALL - ALKHASER_DLLS_CAPA_MISSED


integration = pytest.mark.skipif(
    not os.environ.get("FLOSS_INTEGRATION"),
    reason="set FLOSS_INTEGRATION to run the (~100s) real FLOSS analysis",
)


# --- unit tests (offline; need the saved JSON fixture) -----------------------

@pytest.fixture
def floss_fixture(fixtures_dir):
    path = fixtures_dir / "al-khaser_x86.floss.json"
    if not path.exists():
        pytest.skip(f"FLOSS fixture not generated yet: {path}")
    return path


def test_load_and_adapt_static_strings(floss_fixture):
    """Adapter loads a saved ResultDocument and maps static strings, with
    the 4 capa-missed DLLs present (they live as static .rdata strings)."""
    result = load_floss_results(floss_fixture)
    assert isinstance(result, FlossResult)
    values = result.values()
    # the whole point of the channel: the capa-missed DLLs are recoverable.
    missing = ALKHASER_DLLS_CAPA_MISSED - values
    assert not missing, f"FLOSS fixture missing capa-gap DLLs: {missing}"


def test_adapter_drops_language_strings(floss_fixture):
    """language_strings / language_strings_missed are not surfaced (v2 #16);
    every adapted string carries one of the four schema sources."""
    result = load_floss_results(floss_fixture)
    valid_sources = {"static", "stackstring", "tightstring", "decoded"}
    assert all(s.source in valid_sources for s in result.all_strings())


def test_flossstring_location_fields_by_source(floss_fixture):
    """Each category preserves its native location field and leaves the
    others None (no premature normalization)."""
    result = load_floss_results(floss_fixture)
    for s in result.static:
        assert s.offset is not None
        assert s.address is None and s.function is None
    for s in result.stackstring + result.tightstring:
        assert s.function is not None and s.program_counter is not None
        assert s.offset is None and s.address is None
    for s in result.decoded:
        assert s.address is not None and s.address_type is not None
        assert s.offset is None and s.function is None


# --- integration tests (run the real tool) -----------------------------------

@integration
def test_run_floss_extracts_all_twelve_dlls(fixtures_dir):
    """Day-one grading target: FLOSS recovers all 12 record-#2 DLL
    fingerprints, including the 4 capa misses."""
    sample = fixtures_dir / "al-khaser_x86.exe"
    result = run_floss(sample)
    values = result.values()
    missing = ALKHASER_DLLS_ALL - values
    assert not missing, f"FLOSS failed to extract: {missing}"


@integration
def test_run_floss_recovers_capa_gap(fixtures_dir):
    """Sharp assertion of the channel's justification: the exact 4 DLLs
    capa's anti-VM rule misses are present in FLOSS output."""
    sample = fixtures_dir / "al-khaser_x86.exe"
    result = run_floss(sample)
    values = result.values()
    assert ALKHASER_DLLS_CAPA_MISSED <= values


@integration
def test_run_floss_static_only_is_fast(fixtures_dir):
    """Static-only run (deobfuscation disabled) still recovers the DLLs,
    since they're plain .rdata strings — and skips the expensive workspace."""
    sample = fixtures_dir / "al-khaser_x86.exe"
    result = run_floss(
        sample,
        enable_stack=False,
        enable_tight=False,
        enable_decoded=False,
    )
    assert ALKHASER_DLLS_ALL <= result.values()
    # deobfuscation off -> those categories empty
    assert result.stackstring == []
    assert result.decoded == []

"""Tests for the static orchestrator.

Offline (run everywhere): `assemble_record` envelope, `sha256_file`, assembling
from real bridge-shaped candidates, and schema validation of the record *after*
the derivation fields are added -- confirming the pipeline emits exactly the
intermediate shape the boundary calls for.

Guarded: the capa/tiers glue imports `clew.channels.capa` + `clew.tiers`; it runs
where those modules exist (the cluster) and skips otherwise. There is no live
pipeline pytest -- `run_static_pipeline` needs capa rules/sigs paths and a BN
license; drive it via the CLI (`python -m clew.pipeline ...`).
"""
from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from clew import pipeline
from clew.analysis.dataflow import (BridgedCallSite, BNDataflow, SOURCE_STATIC,
                         CHANNEL_BN, CHANNEL_FLOSS, CONF_STATIC_CORROBORATED)


# --- helpers -----------------------------------------------------------------

def _resolved(**kw) -> BridgedCallSite:
    base = dict(
        api_name="GetModuleHandleW", call_site_va=0x401234, function_va=0x401200,
        api_resolution="import", parameter_index=0, value="SbieDll.dll",
        string_source=SOURCE_STATIC, string_va=0x404020, string_function_va=None,
        dataflow_path=(0x401220, 0x401228, 0x401234),
        source_channels=(CHANNEL_BN, CHANNEL_FLOSS),
        confidence=CONF_STATIC_CORROBORATED, resolved=True)
    base.update(kw)
    return BridgedCallSite(**base)


def _unresolved(**kw) -> BridgedCallSite:
    base = dict(
        api_name="IsDebuggerPresent", call_site_va=0x434d4a, function_va=0x434d20,
        api_resolution="import", parameter_index=-1, value=None,
        string_source=None, string_va=None, string_function_va=None,
        dataflow_path=(0x434d4a,), source_channels=(CHANNEL_BN,),
        confidence=0.0, resolved=False)
    base.update(kw)
    return BridgedCallSite(**base)


def _candidates(*bridged, include_unresolved=True):
    df = BNDataflow("/x/al.exe", "a" * 64, "4.2.6455", list(bridged))
    return df.to_partial_candidates(include_unresolved=include_unresolved)


# --- assemble_record ---------------------------------------------------------

def test_assemble_record_envelope():
    cands = _candidates(_resolved())
    rec = pipeline.assemble_record(
        sample_sha256="a" * 64, sample_path="/x/al.exe",
        capa_techniques=["check for debugger via API"],
        derivation_status="fully_derivable", bridge_candidates=cands)
    assert rec["sample_sha256"] == "a" * 64
    assert rec["sample_path"] == "/x/al.exe"
    assert rec["clew_version"] == pipeline.CLEW_VERSION
    assert rec["capa_techniques"] == ["check for debugger via API"]
    assert rec["derivation_status"] == "fully_derivable"
    assert rec["total_iterations"] == 1
    assert rec["candidates"] == cands


def test_assemble_record_copies_inputs():
    techniques = ["a"]
    cands = _candidates(_resolved())
    rec = pipeline.assemble_record(
        sample_sha256="b" * 64, sample_path=None, capa_techniques=techniques,
        derivation_status=None, bridge_candidates=cands)
    techniques.append("b")                    # mutating the input must not leak in
    assert rec["capa_techniques"] == ["a"]
    assert rec["sample_path"] is None
    assert rec["derivation_status"] is None   # no_capa_signal path can pass None


def test_assemble_includes_unresolved_when_asked():
    # resolved + return-value stub -> both present with include_unresolved
    cands = _candidates(_resolved(), _unresolved(), include_unresolved=True)
    rec = pipeline.assemble_record(
        sample_sha256="c" * 64, sample_path="/x", capa_techniques=[],
        derivation_status="partially_derivable", bridge_candidates=cands)
    apis = {c["api_name"] for c in rec["candidates"]}
    assert {"GetModuleHandleW", "IsDebuggerPresent"} <= apis


def test_sha256_file(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(b"clew-static-pipeline")
    assert pipeline.sha256_file(p) == hashlib.sha256(b"clew-static-pipeline").hexdigest()


def test_record_json_round_trips():
    rec = pipeline.assemble_record(
        sample_sha256="d" * 64, sample_path="/x", capa_techniques=["t"],
        derivation_status="not_derivable", bridge_candidates=_candidates(_resolved()))
    assert json.loads(json.dumps(rec)) == rec


# --- schema validation of the record after derivation completes it -----------

def _find_schema():
    here = pathlib.Path(__file__).resolve()
    for cand in (here.parent.parent / "schema" / "clew_record.schema.json",
                 here.parent / "clew_record.schema.json"):
        if cand.exists():
            return cand
    return None


def test_record_plus_derivation_validates_against_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = _find_schema()
    if schema_path is None:
        pytest.skip("clew_record.schema.json not found")
    schema = json.loads(schema_path.read_text())

    rec = pipeline.assemble_record(
        sample_sha256="e" * 64, sample_path="/x/al.exe",
        capa_techniques=["check for debugger via API"],
        derivation_status="fully_derivable",
        bridge_candidates=_candidates(_resolved(), _unresolved()))

    # simulate the derivation stage completing every candidate: the three
    # bridge-absent fields, plus concrete comparison/represents semantics.
    for c in rec["candidates"]:
        c["evasion_tier"] = "tier_1"
        c["iteration_number"] = 0
        # coordination_constraint is a required object; null fields = no constraint
        c["coordination_constraint"] = {"gate_group_id": None, "description": None}
        c["comparison_operator"] = "equality"
        for v in c["candidate_values"]:
            v["represents"] = "sandbox_detected"

    jsonschema.validate(rec, schema)          # raises on any schema violation


# --- capa / tiers glue (guarded: runs on the cluster, skips without them) -----

def test_capa_techniques_and_status_from_capa_result():
    pytest.importorskip("clew.channels.capa")
    pytest.importorskip("clew.tiers")
    import types

    fake = types.SimpleNamespace(
        rule_names=frozenset({"check for debugger via API", "get OS version"}),
        raw={"rules": {
            "check for debugger via API": {
                "meta": {"namespace": "anti-analysis/anti-debugging/debugger-detection"}},
            "get OS version": {"meta": {"namespace": "host-interaction/os/version"}},
        }})
    techniques, status = pipeline.capa_techniques_and_status(fake)
    # only the anti-analysis rule is an evasion technique
    assert "check for debugger via API" in techniques
    assert "get OS version" not in techniques
    # status is one of the four derivation buckets (whatever classify returns)
    assert status in {"fully_derivable", "partially_derivable",
                      "not_derivable", "no_capa_signal"}


def test_quiet_floss_logging_suppresses_and_restores():
    import logging
    lg = logging.getLogger("vivisect")
    lg.setLevel(logging.DEBUG)                 # pretend vivisect is chatty
    with pipeline._quiet_floss_logging():
        assert lg.level == logging.ERROR       # raised inside the block
    assert lg.level == logging.DEBUG           # restored exactly on exit


def test_quiet_floss_logging_restores_on_exception():
    import logging
    lg = logging.getLogger("envi")
    lg.setLevel(logging.INFO)
    with pytest.raises(ValueError):
        with pipeline._quiet_floss_logging():
            raise ValueError("boom")
    assert lg.level == logging.INFO            # restored even when body raises


def test_quiet_floss_logging_is_scoped_not_global():
    import logging
    # a logger OUTSIDE the vivisect/floss trees must be untouched
    other = logging.getLogger("clew.somewhere")
    other.setLevel(logging.DEBUG)
    with pipeline._quiet_floss_logging():
        assert other.level == logging.DEBUG    # unaffected (unlike logging.disable)


# --- FLOSS cache: key, sigs identity, and miss-vs-stale safety ---------------

def test_sigs_identity_stable_and_size_sensitive(tmp_path):
    d = tmp_path / "sigs"
    d.mkdir()
    (d / "a.sig").write_bytes(b"xxxx")
    (d / "sub").mkdir()
    (d / "sub" / "b.sig").write_bytes(b"yy")
    first = pipeline._sigs_identity(d)
    assert first == pipeline._sigs_identity(d)          # deterministic
    (d / "a.sig").write_bytes(b"xxxxADDED")             # content/size change
    assert pipeline._sigs_identity(d) != first          # detected


def test_sigs_identity_bundled_sentinel():
    assert pipeline._sigs_identity(None) == "bundled"


def test_floss_cache_key_shape():
    k = pipeline._floss_cache_key("a" * 64, None)
    assert k["sample_sha256"] == "a" * 64
    assert k["min_length"] == pipeline.FLOSS_MIN_LENGTH
    assert k["sigs_identity"] == "bundled"
    assert set(k["flags"]) == {"static", "stack", "tight", "decoded"}


def test_key_diff_names_the_changed_field():
    have = {"floss_version": "3.0.0", "min_length": 4}
    want = {"floss_version": "3.1.0", "min_length": 4}
    d = pipeline._key_diff(have, want)
    assert "floss_version" in d and "3.0.0" in d and "3.1.0" in d
    assert "min_length" not in d                        # unchanged field omitted


def test_cache_read_miss_returns_none(tmp_path):
    # empty cache dir -> clean miss, not an error
    assert pipeline._floss_cache_read("b" * 64, None, tmp_path) is None


def test_cache_read_stale_raises_naming_field(tmp_path):
    sha = "c" * 64
    # write a data file + a key sidecar whose key deliberately disagrees
    (tmp_path / f"{sha}.floss.json").write_text("{}")
    stale_key = pipeline._floss_cache_key(sha, None)
    stale_key["floss_version"] = "SOME-OTHER-VERSION"
    (tmp_path / f"{sha}.floss.key.json").write_text(json.dumps(stale_key))
    with pytest.raises(pipeline.FlossCacheStale) as ei:
        pipeline._floss_cache_read(sha, None, tmp_path)
    assert "floss_version" in str(ei.value)             # tells the operator why
    assert "refresh-floss-cache" in str(ei.value)       # and how to fix it


def test_cache_read_matching_key_attempts_load(tmp_path):
    # a MATCHING key must pass the stale gate and proceed to the FLOSS loader;
    # without flare-floss installed that surfaces as ImportError (not stale),
    # which confirms the gate opened rather than the key logic misfiring.
    sha = "d" * 64
    (tmp_path / f"{sha}.floss.json").write_text("{}")
    (tmp_path / f"{sha}.floss.key.json").write_text(
        json.dumps(pipeline._floss_cache_key(sha, None)))
    with pytest.raises((ImportError, Exception)) as ei:
        pipeline._floss_cache_read(sha, None, tmp_path)
    assert not isinstance(ei.value, pipeline.FlossCacheStale)


def test_cache_read_unreadable_key_is_stale(tmp_path):
    sha = "e" * 64
    (tmp_path / f"{sha}.floss.json").write_text("{}")
    (tmp_path / f"{sha}.floss.key.json").write_text("{ this is not json")
    with pytest.raises(pipeline.FlossCacheStale):
        pipeline._floss_cache_read(sha, None, tmp_path)


# --- capa path defaults: env-overridable, cluster fallback -------------------

def test_capa_path_defaults_fall_back_when_env_unset(monkeypatch):
    monkeypatch.delenv("CLEW_CAPA_RULES", raising=False)
    monkeypatch.delenv("CLEW_CAPA_SIGS", raising=False)
    assert pipeline._default_capa_rules() == pipeline.DEFAULT_CAPA_RULES
    assert pipeline._default_capa_sigs() == pipeline.DEFAULT_CAPA_SIGS


def test_capa_path_defaults_respect_env(monkeypatch):
    monkeypatch.setenv("CLEW_CAPA_RULES", "/opt/my/rules")
    monkeypatch.setenv("CLEW_CAPA_SIGS", "/opt/my/sigs")
    assert pipeline._default_capa_rules() == "/opt/my/rules"
    assert pipeline._default_capa_sigs() == "/opt/my/sigs"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

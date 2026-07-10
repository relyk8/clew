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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

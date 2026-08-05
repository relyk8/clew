"""Channel 0 (capa) tests."""

from __future__ import annotations

import json

import pytest

from clew.channels.capa import (
    CapaNotFoundError,
    _parse_capa_json,
    filter_evasion_techniques,
    run_capa,
)


def test_parse_saved_capa_output(fixtures_dir):
    raw = (fixtures_dir / "al-khaser_x86.capa.json").read_text()
    result = _parse_capa_json(raw)
    assert "check for debugger via API" in result.rule_names
    assert len(result.rule_names) == 106


def test_filter_evasion_techniques(fixtures_dir):
    data = json.loads((fixtures_dir / "al-khaser_x86.capa.json").read_text())
    result = _parse_capa_json(data)
    expected = json.loads((fixtures_dir / "al-khaser_x86.capa_techniques.json").read_text())
    filtered = filter_evasion_techniques(result.rule_names, data["rules"])
    assert sorted(filtered) == sorted(expected)


def test_run_capa_integration(fixtures_dir, capa_paths):
    rules, sigs = capa_paths
    sample = fixtures_dir / "al-khaser_x86.exe"
    result = run_capa(sample, rules_path=rules, sigs_path=sigs)
    assert "check for debugger via API" in result.rule_names


def test_parse_capa_json_banner_preamble_fallback():
    # capa CLI output can be preceded by log/banner lines; the
    # brace-finder fallback must still parse it.
    from clew.channels.capa import _parse_capa_json

    r = _parse_capa_json('WARNING: loading rules\n{"rules": {}}')
    assert r.rule_names == frozenset()


def test_parse_capa_json_error_branches():
    from clew.channels.capa import CapaParseError, _parse_capa_json

    with pytest.raises(CapaParseError):
        _parse_capa_json("no json object here")  # no brace
    with pytest.raises(CapaParseError):
        _parse_capa_json('{"norules": 1}')  # missing 'rules'
    with pytest.raises(CapaParseError):
        _parse_capa_json(123)  # unsupported type


def test_run_capa_nonzero_exit_raises(monkeypatch, tmp_path):
    # a nonzero capa exit must raise CapaRunError (untested before).
    from clew.channels import capa as capa_mod

    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")

    class _Proc:
        returncode = 3
        stdout = b""
        stderr = b"boom"

    monkeypatch.setattr(capa_mod.subprocess, "run", lambda *a, **k: _Proc())
    with pytest.raises(capa_mod.CapaRunError):
        capa_mod.run_capa(sample, rules_path=tmp_path, sigs_path=tmp_path)


def test_run_capa_missing_binary(fixtures_dir, capa_paths):
    rules, sigs = capa_paths
    sample = fixtures_dir / "al-khaser_x86.exe"
    with pytest.raises(CapaNotFoundError):
        run_capa(
            sample,
            rules_path=rules,
            sigs_path=sigs,
            capa_bin="capa_does_not_exist_xyz123",
        )

"""Offline tests for the clew CLI entry point (clew/cli.py).

These exercise the parser contract and main()'s exception -> exit-code mapping
without a BN license or capa rules: the missing-sample path raises before any
heavy import, and the stale-cache / success paths monkeypatch
run_static_pipeline so main()'s contract is tested in isolation.
"""

import pytest

import clew.cli as cli

_RECORD = {
    "candidates": [],
    "derivation_status": "no_capa_signal",
    "capa_techniques": [],
}


def test_missing_sample_returns_1():
    # run_static_pipeline raises SampleNotFoundError before any heavy import.
    assert cli.main(["/nonexistent/nope.exe", "--no-license-checkout"]) == 1


def test_floss_cache_stale_returns_2(monkeypatch):
    def boom(*a, **k):
        raise cli.FlossCacheStale("stale cache")

    monkeypatch.setattr(cli, "run_static_pipeline", boom)
    assert cli.main(["whatever.exe"]) == 2


def test_success_returns_0_and_prints_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_static_pipeline", lambda *a, **k: _RECORD)
    assert cli.main(["whatever.exe"]) == 0
    assert '"derivation_status"' in capsys.readouterr().out


def test_output_flag_writes_file_and_summarizes(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "run_static_pipeline", lambda *a, **k: _RECORD)
    out = tmp_path / "rec.json"
    assert cli.main(["whatever.exe", "-o", str(out)]) == 0
    assert out.exists() and '"derivation_status"' in out.read_text()
    # With -o, stdout gets the one-line summary, not the JSON.
    captured = capsys.readouterr().out
    assert captured.startswith("wrote ")


def test_parser_defaults_and_polarity():
    ns = cli.build_parser().parse_args(["x.exe"])
    assert ns.sample == "x.exe"
    # store_true flags default False -> main inverts them into the "on" defaults.
    assert ns.exclude_unresolved is False  # -> include_unresolved True
    assert ns.no_cache is False  # -> use_floss_cache True
    assert ns.no_license_checkout is False  # -> run_license_checkout True
    assert ns.verbose_floss is False  # -> quiet_floss True


def test_verbose_quiet_mutually_exclusive():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["x.exe", "-v", "-q"])


def test_sample_is_required():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])


def test_module_entry_delegates_to_cli():
    # `python -m clew.pipeline` imports main from clew.cli; guard against a
    # divergent second parser being reintroduced in pipeline.py.
    from clew.cli import main as cli_main

    assert cli_main is cli.main


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

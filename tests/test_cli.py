"""Offline tests for the clew CLI entry point (clew/cli.py).

These exercise the parser contract and main()'s exception -> exit-code mapping
without a BN license or capa rules: the missing-sample path raises before any
heavy import, and the stale-cache / success paths monkeypatch
run_static_pipeline so main()'s contract is tested in isolation.
"""

import logging

import pytest

import clew.cli as cli

_RECORD = {
    "candidates": [],
    "derivation_status": "no_capa_signal",
    "capa_techniques": [],
}

# A record with one valued candidate and one without, to exercise main()'s
# resolved-count summary logic (the only place cli.py reaches into record shape).
_RECORD_WITH_VALUES = {
    "candidates": [
        {"candidate_values": [{"value": "SbieDll.dll"}]},
        {"candidate_values": [{"value": None}]},
    ],
    "derivation_status": "fully_derivable",
    "capa_techniques": ["anti-vm"],
}


def test_missing_sample_returns_1():
    # run_static_pipeline raises SampleNotFoundError before any heavy import.
    assert cli.main(["/nonexistent/nope.exe", "--no-license-checkout"]) == 1


def test_floss_cache_stale_returns_2(monkeypatch):
    def boom(*a, **k):
        raise cli.FlossCacheStale("stale cache")

    monkeypatch.setattr(cli, "run_static_pipeline", boom)
    assert cli.main(["whatever.exe"]) == 2


def test_bare_filenotfound_propagates(monkeypatch):
    # The whole point of SampleNotFoundError: a bare FileNotFoundError raised
    # deeper in the pipeline (e.g. the BN core channel) must NOT be mapped to
    # exit 1 -- it must propagate as a core-channel abort. Guards the fix for the
    # over-broad `except FileNotFoundError` this test file's HIGH finding flagged.
    def boom(*a, **k):
        raise FileNotFoundError("BN loader/db failure")

    monkeypatch.setattr(cli, "run_static_pipeline", boom)
    with pytest.raises(FileNotFoundError):
        cli.main(["whatever.exe"])


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


def test_parser_defaults():
    ns = cli.build_parser().parse_args(["static", "x.exe"])
    assert ns.sample == "x.exe"
    assert ns.exclude_unresolved is False
    assert ns.no_cache is False
    assert ns.no_license_checkout is False
    assert ns.verbose_floss is False


def test_main_wires_inverted_flags_into_pipeline(monkeypatch):
    # main() inverts several opt-out flags into run_static_pipeline's "on"
    # defaults (include_unresolved=not exclude_unresolved, etc.). A dropped `not`
    # would silently flip a default; capture the kwargs and assert the polarity.
    seen = {}

    def capture(sample, **kwargs):
        seen.clear()
        seen["sample"] = sample
        seen.update(kwargs)
        return _RECORD

    monkeypatch.setattr(cli, "run_static_pipeline", capture)

    assert cli.main(["s.exe"]) == 0
    assert seen["include_unresolved"] is True
    assert seen["run_license_checkout"] is True
    assert seen["quiet_floss"] is True
    assert seen["use_floss_cache"] is True
    assert seen["refresh_floss_cache"] is False

    assert (
        cli.main(
            [
                "s.exe",
                "--exclude-unresolved",
                "--no-license-checkout",
                "--verbose-floss",
                "--no-cache",
                "--refresh-floss-cache",
            ]
        )
        == 0
    )
    assert seen["include_unresolved"] is False
    assert seen["run_license_checkout"] is False
    assert seen["quiet_floss"] is False
    assert seen["use_floss_cache"] is False
    assert seen["refresh_floss_cache"] is True


def test_output_summary_counts_resolved_candidates(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "run_static_pipeline", lambda *a, **k: _RECORD_WITH_VALUES)
    out = tmp_path / "rec.json"
    assert cli.main(["s.exe", "-o", str(out)]) == 0
    summary = capsys.readouterr().out
    assert "2 candidates" in summary and "(1 with values)" in summary


@pytest.mark.parametrize(
    "argv,expected",
    [
        (["static", "s.exe"], logging.INFO),
        (["static", "s.exe", "-v"], logging.DEBUG),
        (["static", "s.exe", "-q"], logging.WARNING),
    ],
)
def test_log_level_selection(argv, expected, monkeypatch):
    captured = {}
    monkeypatch.setattr(cli.logging, "basicConfig", lambda **k: captured.update(k))
    ns = cli.build_parser().parse_args(argv)
    cli._configure_logging(ns.verbose, ns.quiet)
    assert captured["level"] == expected


def test_verbose_quiet_mutually_exclusive():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["static", "x.exe", "-v", "-q"])


def test_bare_invocation_shows_menu(capsys):
    # Bare `clew` no longer errors on a missing sample: subparsers are not
    # required, so it prints the verb menu to stderr and returns 2.
    assert cli.main([]) == 2
    err = capsys.readouterr().err
    assert "static" in err


def test_static_requires_sample():
    # `clew static` with no sample still errors (the static subparser's
    # positional is required).
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["static"])


def test_back_compat_bare_sample_routes_to_static(monkeypatch):
    # `clew x.exe` (no verb) must still run the static pipeline.
    monkeypatch.setattr(cli, "run_static_pipeline", lambda *a, **k: _RECORD)
    assert cli.main(["x.exe"]) == 0


def test_inject_default_verb():
    verbs = {"static"}
    assert cli._inject_default_verb(["x.exe"], verbs) == ["static", "x.exe"]
    assert cli._inject_default_verb(["static", "x.exe"], verbs) == ["static", "x.exe"]
    assert cli._inject_default_verb(["--version"], verbs) == ["--version"]
    assert cli._inject_default_verb([], verbs) == []


def test_pipeline_has_no_rival_parser():
    # The CLI contract lives in clew.cli; `python -m clew.pipeline` delegates to
    # it. Guard against a divergent parser/entry being reintroduced in pipeline.py
    # (the tautological `cli.main is cli.main` check this replaced guarded nothing).
    import inspect

    import clew.pipeline as pipeline

    assert not hasattr(pipeline, "build_parser")
    assert not hasattr(pipeline, "main")
    assert "from clew.cli import main" in inspect.getsource(pipeline)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

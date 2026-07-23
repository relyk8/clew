"""Offline tests for the clew CLI entry point (clew/cli.py).

These exercise the parser contract and main()'s exception -> exit-code mapping
without a BN license or capa rules: the missing-sample path raises before any
heavy import, and the stale-cache / success paths monkeypatch
run_static_pipeline so main()'s contract is tested in isolation.
"""

import copy
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path

import pytest

import clew.cli as cli

FIXTURES = Path(__file__).parent / "fixtures"

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


def test_success_returns_0_and_writes_default_file(monkeypatch, capsys, tmp_path):
    # No -o: the record lands in results/<sha>.clew.json (relative to cwd), not
    # stdout. chdir into a temp dir so the write is isolated.
    rec = dict(_RECORD, sample_sha256="deadbeef")
    monkeypatch.setattr(cli, "run_static_pipeline", lambda *a, **k: rec)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["whatever.exe"]) == 0
    out = tmp_path / "results" / "deadbeef.clew.json"
    assert out.exists() and '"derivation_status"' in out.read_text()
    # stdout stays clean (the summary is logged to stderr).
    assert capsys.readouterr().out == ""


def test_dash_output_prints_json_to_stdout(monkeypatch, capsys):
    # `-o -` is the pipe escape hatch: the record JSON goes to stdout.
    rec = dict(_RECORD, sample_sha256="deadbeef")
    monkeypatch.setattr(cli, "run_static_pipeline", lambda *a, **k: rec)
    assert cli.main(["whatever.exe", "-o", "-"]) == 0
    assert '"derivation_status"' in capsys.readouterr().out


def test_output_flag_writes_file_and_summarizes(monkeypatch, capsys, tmp_path):
    rec = dict(_RECORD, sample_sha256="deadbeef")
    monkeypatch.setattr(cli, "run_static_pipeline", lambda *a, **k: rec)
    out = tmp_path / "rec.json"
    assert cli.main(["whatever.exe", "-o", str(out)]) == 0
    assert out.exists() and '"derivation_status"' in out.read_text()
    # With -o <path>, stdout stays clean; the summary is logged to stderr.
    assert capsys.readouterr().out == ""


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

    # -o - keeps these arg-capture runs from writing a results/ file.
    assert cli.main(["s.exe", "-o", "-"]) == 0
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
                "-o",
                "-",
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
    rec = dict(_RECORD_WITH_VALUES, sample_sha256="deadbeef")
    monkeypatch.setattr(cli, "run_static_pipeline", lambda *a, **k: rec)
    out = tmp_path / "rec.json"
    assert cli.main(["s.exe", "-o", str(out)]) == 0
    # The summary rides the "wrote" log line to stderr, not stdout.
    summary = capsys.readouterr().err
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
    assert cli.main(["x.exe", "-o", "-"]) == 0


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


def _has_filled_comparison(record):
    # A candidate whose correlator output is non-empty and whose legacy operand
    # fields were mirrored (non-null) from the top comparison.
    for c in record["candidates"]:
        if c.get("comparison_candidates") and c["evidence"]["cmp_operand_a"] is not None:
            return True
    return False


def test_correlate_cmplog_dir_happy_path(tmp_path, capsys):
    # Pure offline path: copy the synth log into a dir, correlate the fixture
    # record against it, assert exit 0 and a filled comparison in the output.
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    shutil.copy(FIXTURES / "cmplog_synth_01.log", log_dir / "cmplog.1.log")
    out = tmp_path / "enriched.json"
    rc = cli.main(
        [
            "correlate",
            "--record",
            str(FIXTURES / "correlate_input_01.json"),
            "--cmplog-dir",
            str(log_dir),
            "-o",
            str(out),
        ]
    )
    assert rc == 0
    # With -o <path>, stdout stays clean; the summary is logged to stderr.
    assert capsys.readouterr().out == ""
    enriched = json.loads(out.read_text())
    assert _has_filled_comparison(enriched)


def test_correlate_default_writes_results_file(tmp_path, monkeypatch, capsys):
    # No -o: the enriched record lands in results/<sha>.clew.json under cwd.
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    shutil.copy(FIXTURES / "cmplog_synth_01.log", log_dir / "cmplog.1.log")
    monkeypatch.chdir(tmp_path)
    rc = cli.main(
        [
            "correlate",
            "--record",
            str(FIXTURES / "correlate_input_01.json"),
            "--cmplog-dir",
            str(log_dir),
        ]
    )
    assert rc == 0
    assert capsys.readouterr().out == ""
    sha = json.loads((FIXTURES / "correlate_input_01.json").read_text())["sample_sha256"]
    out = tmp_path / "results" / f"{sha}.clew.json"
    assert out.exists()
    assert _has_filled_comparison(json.loads(out.read_text()))


def test_correlate_dash_output_prints_json(tmp_path, capsys):
    # `-o -` streams the enriched record to stdout for piping.
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    shutil.copy(FIXTURES / "cmplog_synth_01.log", log_dir / "cmplog.1.log")
    rc = cli.main(
        [
            "correlate",
            "--record",
            str(FIXTURES / "correlate_input_01.json"),
            "--cmplog-dir",
            str(log_dir),
            "-o",
            "-",
        ]
    )
    assert rc == 0
    assert _has_filled_comparison(json.loads(capsys.readouterr().out))


def test_correlate_missing_record_returns_1(tmp_path):
    rc = cli.main(
        [
            "correlate",
            "--record",
            str(tmp_path / "nope.json"),
            "--cmplog-dir",
            str(tmp_path),
        ]
    )
    assert rc == 1


def test_correlate_empty_cmplog_dir_warns_and_succeeds(tmp_path, capsys):
    # A readable dir with no logs is not an error: correlation just yields empty
    # comparison_candidates.
    out = tmp_path / "enriched.json"
    rc = cli.main(
        [
            "correlate",
            "--record",
            str(FIXTURES / "correlate_input_01.json"),
            "--cmplog-dir",
            str(tmp_path),
            "-o",
            str(out),
        ]
    )
    assert rc == 0
    enriched = json.loads(out.read_text())
    assert all(c["comparison_candidates"] == [] for c in enriched["candidates"])


def test_correlate_task_path_reads_and_enriches(monkeypatch, capsys):
    from clew.channels.cape import client as cape_client

    monkeypatch.setattr(
        cape_client.CapeClient,
        "fetch_cmplog_logs",
        lambda self, task_id, storage_root: [FIXTURES / "cmplog_synth_01.log"],
    )
    rc = cli.main(
        [
            "correlate",
            "--record",
            str(FIXTURES / "correlate_input_01.json"),
            "--task",
            "10",
            "-o",
            "-",
        ]
    )
    assert rc == 0
    enriched = json.loads(capsys.readouterr().out)
    assert _has_filled_comparison(enriched)


def test_correlate_task_cape_error_returns_2(monkeypatch):
    from clew.channels.cape import client as cape_client

    def boom(self, task_id, storage_root):
        raise cape_client.CapeError("cannot read cmplog logs")

    monkeypatch.setattr(cape_client.CapeClient, "fetch_cmplog_logs", boom)
    rc = cli.main(
        [
            "correlate",
            "--record",
            str(FIXTURES / "correlate_input_01.json"),
            "--task",
            "10",
        ]
    )
    assert rc == 2


def test_correlate_source_is_required_and_exclusive():
    # Neither --cmplog-dir nor --task -> the required group errors.
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["correlate", "--record", "r.json"])
    # Both at once -> mutually exclusive.
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(
            ["correlate", "--record", "r.json", "--cmplog-dir", "d", "--task", "1"]
        )


# ---------- detonate ----------


def test_detonate_no_wait_prints_task_id_and_submits_free_mode(monkeypatch, capsys):
    # Guards the critical free-mode requirement: without options={"free":"yes"}
    # and package="exe_cmplog", capemon corrupts DynamoRIO and 0 logs land.
    from clew.channels.cape import client as cape_client

    seen = {}

    def fake_submit(self, sample_path, **kwargs):
        seen["sample_path"] = sample_path
        seen.update(kwargs)
        return 42

    monkeypatch.setattr(cape_client.CapeClient, "submit", fake_submit)
    assert cli.main(["detonate", "x.exe"]) == 0
    assert capsys.readouterr().out.strip() == json.dumps({"task_id": 42})
    assert seen["package"] == "exe_cmplog"
    assert seen["options"] == {"free": "yes"}


def test_detonate_wait_reported_returns_0(monkeypatch, capsys):
    from clew.channels.cape import client as cape_client

    monkeypatch.setattr(cape_client.CapeClient, "submit", lambda self, s, **k: 42)
    monkeypatch.setattr(cape_client.CapeClient, "poll", lambda self, tid, **k: "reported")
    assert cli.main(["detonate", "x.exe", "--wait"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out == {"task_id": 42, "status": "reported"}


def test_detonate_wait_failed_returns_2(monkeypatch, capsys):
    from clew.channels.cape import client as cape_client

    monkeypatch.setattr(cape_client.CapeClient, "submit", lambda self, s, **k: 42)
    monkeypatch.setattr(cape_client.CapeClient, "poll", lambda self, tid, **k: "failed_analysis")
    assert cli.main(["detonate", "x.exe", "--wait"]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "failed_analysis"


def test_detonate_missing_sample_returns_1(monkeypatch):
    from clew.channels.cape import client as cape_client

    def boom(self, sample_path, **kwargs):
        raise FileNotFoundError(sample_path)

    monkeypatch.setattr(cape_client.CapeClient, "submit", boom)
    assert cli.main(["detonate", "x.exe"]) == 1


def test_detonate_cape_error_returns_2(monkeypatch):
    from clew.channels.cape import client as cape_client

    def boom(self, sample_path, **kwargs):
        raise cape_client.CapeError("submit error")

    monkeypatch.setattr(cape_client.CapeClient, "submit", boom)
    assert cli.main(["detonate", "x.exe"]) == 2


def test_detonate_output_flag_writes_file(monkeypatch, capsys, tmp_path):
    from clew.channels.cape import client as cape_client

    monkeypatch.setattr(cape_client.CapeClient, "submit", lambda self, s, **k: 42)
    out = tmp_path / "task.json"
    assert cli.main(["detonate", "x.exe", "-o", str(out)]) == 0
    assert json.loads(out.read_text()) == {"task_id": 42}
    # With -o, stdout carries no task JSON.
    assert capsys.readouterr().out == ""


# ---------- tasks ----------


def test_format_tasks_table_headers_and_values():
    rows = [
        {"task": "10", "sample": "signtool.exe", "pkg": "exe_cmplog",
         "status": "reported", "records": "24429", "age": "2h"},
        {"task": "9", "sample": "al-khaser_x86.exe", "pkg": "exe_cmplog",
         "status": "reported", "records": "0", "age": "3h"},
        {"task": "3", "sample": "clew_smoke.exe", "pkg": "exe",
         "status": "failed_analysis", "records": "-", "age": "3d"},
    ]
    table = cli._format_tasks_table(rows)
    # Header present with the fixed column order.
    assert "TASK  SAMPLE" in table
    assert "RECORDS" in table and "AGE" in table
    # Values line up in the body (incl a "-" RECORDS cell).
    assert "signtool.exe" in table
    assert "24429" in table
    lines = table.splitlines()
    # The failed task's row carries a "-" in the RECORDS column.
    smoke_line = next(line for line in lines if "clew_smoke.exe" in line)
    assert "-" in smoke_line


def test_humanize_age_buckets():
    from datetime import timedelta

    now = datetime.now()

    def fmt(delta):
        return (now - delta).strftime("%Y-%m-%d %H:%M:%S")

    assert cli._humanize_age(fmt(timedelta(seconds=12))).endswith("s")
    assert cli._humanize_age(fmt(timedelta(minutes=4))).endswith("m")
    assert cli._humanize_age(fmt(timedelta(hours=2))).endswith("h")
    assert cli._humanize_age(fmt(timedelta(days=3))) == "3d"


def test_humanize_age_garbage_returns_dash():
    assert cli._humanize_age("not a timestamp") == "-"
    assert cli._humanize_age(None) == "-"


_RAW_TASKS = [
    {
        "id": 10,
        "target": "/tmp/cuckoo-tmp/upload_h0nz812e/signtool.exe",
        "sample": {"id": 5, "sha256": "abc"},
        "package": "exe_cmplog",
        "status": "reported",
        "added_on": "2026-07-22 15:43:41",
    },
    {
        "id": 3,
        "target": "/tmp/cuckoo-tmp/upload_1uq71ey_/clew_smoke.exe",
        "sample": {"id": 2},
        "package": "exe",
        "status": "failed_analysis",
        "added_on": "2026-07-20 20:10:40",
    },
]


def _patch_tasks(monkeypatch, records=24429):
    from clew.channels.cape import client as cape_client

    monkeypatch.setattr(
        cape_client.CapeClient, "list_tasks", lambda self, limit=None, status=None: _RAW_TASKS
    )
    monkeypatch.setattr(
        cape_client.CapeClient,
        "count_cmplog_lines",
        lambda self, task_id, storage_root: records,
    )


def test_tasks_table_shows_sample_basename_and_record_count(monkeypatch, capsys):
    _patch_tasks(monkeypatch)
    assert cli.main(["tasks"]) == 0
    out = capsys.readouterr().out
    # Basename taken from the string `target`, not the `sample` metadata dict.
    assert "signtool.exe" in out
    assert "clew_smoke.exe" in out
    # RECORDS filled for the reported task, "-" for the non-terminal one.
    assert "24429" in out


def test_tasks_json_includes_records(monkeypatch, capsys):
    _patch_tasks(monkeypatch)
    assert cli.main(["tasks", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert isinstance(rows, list) and rows
    assert rows[0]["sample"] == "signtool.exe"
    assert rows[0]["records"] == "24429"
    # The non-terminal task shows "-" RECORDS.
    assert rows[1]["records"] == "-"


def test_tasks_cape_error_returns_2(monkeypatch):
    from clew.channels.cape import client as cape_client

    def boom(self, limit=None, status=None):
        raise cape_client.CapeError("connection refused")

    monkeypatch.setattr(cape_client.CapeClient, "list_tasks", boom)
    assert cli.main(["tasks"]) == 2


# ---------- run (static -> detonate --wait -> correlate) ----------


# A minimal intermediate record whose call sites align with PC windows in the
# synth cmplog log, so correlate lands at least one comparison. The first
# candidate (0x00401000) sits just before the 0x0040100x/0x0040102x comparisons.
_RUN_RECORD = {
    "candidates": [
        {
            "call_site_va": "0x00401000",
            "function_va": "0x00400f00",
            "api_name": "IsDebuggerPresent",
            "parameter_index": 0,
            "comparison_operator": "unknown",
            "candidate_values": [{"value": None}],
            "evidence": {"cmp_operand_a": None, "cmp_operand_b": None},
        },
        {
            "call_site_va": "0x0040f000",
            "function_va": "0x0040ef00",
            "api_name": "GetModuleHandleA",
            "parameter_index": 0,
            "comparison_operator": "unknown",
            "candidate_values": [{"value": None}],
            "evidence": {"cmp_operand_a": None, "cmp_operand_b": None},
        },
    ],
    "derivation_status": "fully_derivable",
    "capa_techniques": [],
}


def _patch_run_stages(monkeypatch, poll_status="reported"):
    from clew.channels.cape import client as cape_client

    # Deep-copy per call: correlate_record mutates the record in place.
    def fresh_record(*a, **k):
        return copy.deepcopy(_RUN_RECORD)

    monkeypatch.setattr(cli, "run_static_pipeline", fresh_record)
    monkeypatch.setattr(cape_client.CapeClient, "submit", lambda self, s, **k: 77)
    monkeypatch.setattr(cape_client.CapeClient, "poll", lambda self, tid, **k: poll_status)
    monkeypatch.setattr(
        cape_client.CapeClient,
        "fetch_cmplog_logs",
        lambda self, task_id, storage_root: [FIXTURES / "cmplog_synth_01.log"],
    )


def test_run_happy_path_emits_enriched_record(monkeypatch, capsys):
    _patch_run_stages(monkeypatch)
    # -o - streams the enriched record to stdout so the test can read it.
    assert cli.main(["run", "sample.exe", "--no-license-checkout", "-o", "-"]) == 0
    enriched = json.loads(capsys.readouterr().out)
    # The matching candidate carries proximity comparisons and mirrored legacy fields.
    first = enriched["candidates"][0]
    assert first["comparison_candidates"]
    assert first["evidence"]["cmp_operand_a"] is not None
    # The out-of-window candidate stays empty.
    assert enriched["candidates"][1]["comparison_candidates"] == []


def test_run_detonation_failed_returns_2_without_correlating(monkeypatch):
    from clew.channels.cape import client as cape_client

    _patch_run_stages(monkeypatch, poll_status="failed_analysis")

    def boom(self, task_id, storage_root):
        raise AssertionError("correlate must not run after a failed detonation")

    monkeypatch.setattr(cape_client.CapeClient, "fetch_cmplog_logs", boom)
    assert cli.main(["run", "sample.exe", "--no-license-checkout"]) == 2


def test_run_static_not_found_returns_1(monkeypatch):
    def boom(*a, **k):
        raise cli.SampleNotFoundError("no such sample")

    monkeypatch.setattr(cli, "run_static_pipeline", boom)
    assert cli.main(["run", "/nonexistent/nope.exe", "--no-license-checkout"]) == 1


def test_run_parser_carries_merged_flags():
    ns = cli.build_parser().parse_args(["run", "x.exe"])
    assert ns.func is cli._cmd_run
    assert ns.sample == "x.exe"
    # Detonate stage defaults.
    assert ns.package == "exe_cmplog"
    assert ns.timeout == 120
    # Correlate stage defaults.
    assert ns.module_base is None
    assert ns.storage_root == "/opt/CAPEv2/storage/analyses"
    # Static stage flags merged in.
    assert ns.exclude_unresolved is False
    assert ns.no_cache is False
    assert ns.no_license_checkout is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

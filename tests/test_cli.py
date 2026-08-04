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


def test_emit_record_creates_missing_parent_dir(tmp_path):
    # `-o <newdir>/f.json` into a non-existent dir must create the parent, not
    # crash after computing the record (D1 / scout #8).
    target = tmp_path / "newdir" / "out.clew.json"
    cli._emit_record({"sample_sha256": "abc123"}, target, "summary")
    assert target.is_file()
    assert json.loads(target.read_text())["sample_sha256"] == "abc123"


def test_detonate_dash_o_streams_to_stdout(monkeypatch, capsys, tmp_path):
    # `detonate -o -` must stream the task-id JSON to stdout, not create a file
    # literally named "-" (M1 / scout #13).
    import clew.channels.cape.client as capeclient

    monkeypatch.setattr(capeclient.CapeClient, "submit", lambda self, *a, **k: 42)
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["detonate", "x.exe", "-o", "-"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {"task_id": 42}
    assert not (tmp_path / "-").exists()


def test_detonate_wait_poll_error_returns_2(monkeypatch):
    # poll() raising CapeError under --wait (timeout / CAPE down) must be a clean
    # exit 2, not an uncaught traceback (M4 / scout #3).
    import clew.channels.cape.client as capeclient

    def boom(self, *a, **k):
        raise capeclient.CapeError("timeout")

    monkeypatch.setattr(capeclient.CapeClient, "submit", lambda self, *a, **k: 7)
    monkeypatch.setattr(capeclient.CapeClient, "poll", boom)
    assert cli.main(["detonate", "x.exe", "--wait"]) == 2


def test_poll_timeout_raises_capeerror():
    # poll() must raise CapeError (not builtin TimeoutError) so callers' existing
    # `except CapeError` handles it (M4 / scout #3).
    import clew.channels.cape.client as capeclient

    c = capeclient.CapeClient("http://x")
    with pytest.raises(capeclient.CapeError):
        c.poll(1, poll_interval=0, max_wait=-1)


def test_correlate_rejects_cape_url(monkeypatch):
    # --cape-url was inert on correlate (its --task path reads local disk, not
    # REST) and has been removed (D2 cleanup): argparse must reject it.
    with pytest.raises(SystemExit):
        cli.main(["correlate", "--record", "r.json", "--task", "1", "--cape-url", "http://x"])


def test_records_computed_for_all_terminal_states(tmp_path):
    # M2: RECORDS reflects any terminal task, not only 'reported'.
    class FakeClient:
        def count_cmplog_lines(self, tid, root):
            return 7 if tid in (1, 2) else None

    tasks = [
        {"id": 1, "status": "reported", "target": "a.exe"},
        {"id": 2, "status": "failed_processing", "target": "b.exe"},
        {"id": 3, "status": "running", "target": "c.exe"},
    ]
    by_id = {r["task"]: r["records"] for r in cli._build_display_rows(tasks, FakeClient(), str(tmp_path))}
    assert by_id["1"] == "7"  # reported
    assert by_id["2"] == "7"  # terminal failure now also counted
    assert by_id["3"] == "-"  # non-terminal: not counted


def test_humanize_age_iso_tz_and_future(monkeypatch):
    # scout #17: the fromisoformat fallback, tz-aware drop, and future clamp were
    # untested (only the strptime buckets + garbage were covered).
    assert cli._humanize_age("2020-01-01T00:00:00.123456+00:00").endswith("d")  # ISO + offset
    assert cli._humanize_age("2020-01-01T00:00:00+00:00").endswith("d")  # tz-aware, tzinfo dropped
    assert cli._humanize_age("2999-01-01T00:00:00") == "0s"  # future clamps, no negative
    assert cli._humanize_age("not a date") == "-"
    assert cli._humanize_age(None) == "-"


def test_run_enforce_timeout_threads_to_submit(monkeypatch, tmp_path):
    # M3: `run` exposes --enforce-timeout/--no-enforce-timeout and threads it into
    # submit (previously it was forced on with no override).
    import clew.channels.cape.client as capeclient

    captured = {}

    def fake_submit(self, sample, **kw):
        captured.update(kw)
        raise capeclient.CapeError("stop after submit")  # short-circuit the run

    monkeypatch.setattr(capeclient.CapeClient, "submit", fake_submit)
    monkeypatch.setattr(
        cli, "run_static_pipeline", lambda *a, **k: {"candidates": [], "sample_sha256": "x"}
    )
    monkeypatch.chdir(tmp_path)  # the pre-detonation checkpoint writes results/<sha>
    cli.main(["run", "x.exe", "--no-enforce-timeout"])
    assert captured.get("enforce_timeout") is False


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


# (argv, dest, expected) for every short flag. Shorts are what gets typed from
# memory, so a rename that silently drops one is a quiet break -- pin the map.
_SHORT_FLAGS = [
    (["tasks", "-s", "reported"], "status", "reported"),
    (["tasks", "-l", "3"], "limit", 3),
    (["tasks", "-a"], "all", True),
    (["tasks", "-j"], "json", True),
    (["tasks", "-w"], "watch", True),
    (["tasks", "-i", "5"], "interval", 5.0),
    (["tasks", "-u", "http://x"], "cape_url", "http://x"),
    (["correlate", "-r", "r.json", "--task", "1"], "record", "r.json"),
    (["correlate", "--record", "r.json", "-t", "16"], "task", 16),
    (["correlate", "--record", "r.json", "-t", "1", "-m", "0xc00000"], "module_base", 0xC00000),
    (["detonate", "s.exe", "-p", "exe_drcov"], "package", "exe_drcov"),
    (["detonate", "s.exe", "-T", "300"], "timeout", 300),
    (["detonate", "s.exe", "-w"], "wait", True),
    (["detonate", "s.exe", "-u", "http://x"], "cape_url", "http://x"),
    (["detonate", "s.exe", "-o", "out.json"], "output", Path("out.json")),
    (["static", "x.exe", "-o", "-"], "output", Path("-")),
    (["run", "s.exe", "-T", "60"], "timeout", 60),
    (["run", "s.exe", "-p", "exe_drcov"], "package", "exe_drcov"),
    (["run", "s.exe", "-m", "0x400000"], "module_base", 0x400000),
    (["run", "s.exe", "-u", "http://x"], "cape_url", "http://x"),
]


@pytest.mark.parametrize("argv,dest,expected", _SHORT_FLAGS)
def test_short_flag_maps_to_its_long_option(argv, dest, expected):
    assert getattr(cli.build_parser().parse_args(argv), dest) == expected


def test_short_flag_meaning_is_stable_across_verbs():
    # The letter policy: one letter, one meaning everywhere. -t is always
    # --task, which is why --timeout had to take -T.
    p = cli.build_parser()
    assert p.parse_args(["correlate", "--record", "r", "-t", "9"]).task == 9
    assert p.parse_args(["detonate", "s.exe", "-T", "9"]).timeout == 9
    assert p.parse_args(["run", "s.exe", "-T", "9"]).timeout == 9
    # -t must NOT be a timeout alias on the verbs that lack --task.
    with pytest.raises(SystemExit):
        p.parse_args(["detonate", "s.exe", "-t", "9"])


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
    # failed_analysis is terminal too, so its RECORDS are counted (M2).
    assert rows[1]["records"] == "24429"


def _capture_limit(monkeypatch):
    # list_tasks does the windowing, so assert on the limit it is handed.
    from clew.channels.cape import client as cape_client

    seen = {}

    def fake_list(self, limit=None, status=None):
        seen["limit"] = limit
        return []

    monkeypatch.setattr(cape_client.CapeClient, "list_tasks", fake_list)
    return seen


def test_tasks_defaults_to_a_window(monkeypatch, capsys):
    # The dashboard is a recent-activity view: unbounded history costs a
    # filesystem read per terminal row and only grows.
    seen = _capture_limit(monkeypatch)
    assert cli.main(["tasks"]) == 0
    assert seen["limit"] == cli.DEFAULT_TASKS_LIMIT


def test_tasks_all_shows_full_history(monkeypatch, capsys):
    # --all opts back into everything; list_tasks reads None as unlimited.
    seen = _capture_limit(monkeypatch)
    assert cli.main(["tasks", "--all"]) == 0
    assert seen["limit"] is None


def test_tasks_explicit_limit_still_wins(monkeypatch, capsys):
    seen = _capture_limit(monkeypatch)
    assert cli.main(["tasks", "--limit", "3"]) == 0
    assert seen["limit"] == 3


def test_tasks_limit_and_all_are_mutually_exclusive():
    # Asking for both a window and everything is a contradiction, so argparse
    # rejects it rather than silently picking one.
    with pytest.raises(SystemExit):
        cli.main(["tasks", "--limit", "3", "--all"])


def test_tasks_cape_error_returns_2(monkeypatch):
    from clew.channels.cape import client as cape_client

    def boom(self, limit=None, status=None):
        raise cape_client.CapeError("connection refused")

    monkeypatch.setattr(cape_client.CapeClient, "list_tasks", boom)
    assert cli.main(["tasks"]) == 2


def _bounded_watch(monkeypatch, frames: int):
    # Bound the otherwise-infinite loop the way a user does: interrupt it.
    calls = {"n": 0}

    def fake_sleep(_interval):
        calls["n"] += 1
        if calls["n"] >= frames:
            raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", fake_sleep)
    return calls


def test_watch_redraws_in_place_on_a_tty(monkeypatch, capsys):
    # A tty gets the clear-and-home escape per frame, so frames overwrite each
    # other instead of scrolling, and the cursor is hidden then restored.
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    _bounded_watch(monkeypatch, frames=3)
    assert cli._watch(lambda: "BODY", 0.0, as_json=False) == 0
    out = capsys.readouterr().out
    assert out.count(cli._ANSI_HOME_CLEAR) == 3
    assert out.startswith(cli._ANSI_CURSOR_HIDE)
    assert out.endswith(cli._ANSI_CURSOR_SHOW)
    assert "Ctrl-C to exit" in out


def test_watch_restores_cursor_when_render_raises(monkeypatch, capsys):
    # The cursor must come back even when the loop dies on a CAPE error, or the
    # user is left with an invisible cursor in their shell.
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)

    def boom():
        raise RuntimeError("cape exploded")

    with pytest.raises(RuntimeError):
        cli._watch(boom, 0.0, as_json=False)
    assert capsys.readouterr().out.endswith(cli._ANSI_CURSOR_SHOW)


def test_watch_emits_no_ansi_when_redirected(monkeypatch, capsys):
    # Redirected output must stay a clean log: no escapes, and the commented
    # timestamp keeps consecutive frames separable.
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False, raising=False)
    _bounded_watch(monkeypatch, frames=2)
    assert cli._watch(lambda: "BODY", 0.0, as_json=False) == 0
    out = capsys.readouterr().out
    assert "\033[" not in out
    assert out.count("# clew tasks @") == 2


def test_watch_json_stays_machine_readable(monkeypatch, capsys):
    # --json is a data stream even on a tty: no escapes, no header, so each
    # frame parses on its own.
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    _bounded_watch(monkeypatch, frames=2)
    assert cli._watch(lambda: '[{"task": "1"}]', 0.0, as_json=True) == 0
    out = capsys.readouterr().out
    assert "\033[" not in out
    assert "clew tasks @" not in out
    assert json.loads(out.strip().splitlines()[0]) == [{"task": "1"}]


def test_watch_reuses_the_one_shot_body(monkeypatch, capsys):
    # The guard against a second table renderer: whatever the one-shot path
    # prints is exactly what a frame redraws.
    from clew.channels.cape import client as cape_client

    tasks = [{"id": 1, "target": "/tmp/s.exe", "package": "exe_cmplog", "status": "reported"}]
    monkeypatch.setattr(cape_client.CapeClient, "list_tasks", lambda self, **k: tasks)
    monkeypatch.setattr(cape_client.CapeClient, "count_cmplog_lines", lambda self, *a: 7)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False, raising=False)

    assert cli.main(["tasks"]) == 0
    one_shot = capsys.readouterr().out.strip()

    _bounded_watch(monkeypatch, frames=1)
    assert cli.main(["tasks", "--watch"]) == 0
    framed = capsys.readouterr().out
    assert one_shot in framed


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
    # Real records always carry this (schema-required, filled by assemble_record);
    # `run` needs it to resolve the pre-detonation checkpoint path.
    "sample_sha256": "runsha",
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


def test_run_happy_path_emits_enriched_record(monkeypatch, capsys, tmp_path):
    _patch_run_stages(monkeypatch)
    monkeypatch.chdir(tmp_path)  # the pre-detonation checkpoint writes results/<sha>
    # -o - streams the enriched record to stdout so the test can read it.
    assert cli.main(["run", "sample.exe", "--no-license-checkout", "-o", "-"]) == 0
    enriched = json.loads(capsys.readouterr().out)
    # The matching candidate carries proximity comparisons and mirrored legacy fields.
    first = enriched["candidates"][0]
    assert first["comparison_candidates"]
    assert first["evidence"]["cmp_operand_a"] is not None
    # The out-of-window candidate stays empty.
    assert enriched["candidates"][1]["comparison_candidates"] == []


def test_run_detonation_failed_returns_2_without_correlating(monkeypatch, tmp_path):
    from clew.channels.cape import client as cape_client

    _patch_run_stages(monkeypatch, poll_status="failed_analysis")
    monkeypatch.chdir(tmp_path)

    def boom(self, task_id, storage_root):
        raise AssertionError("correlate must not run after a failed detonation")

    monkeypatch.setattr(cape_client.CapeClient, "fetch_cmplog_logs", boom)
    assert cli.main(["run", "sample.exe", "--no-license-checkout"]) == 2
    # The expensive stage-1 record survives the failed detonation.
    kept = tmp_path / "results" / "runsha.clew.json"
    assert kept.is_file()
    assert json.loads(kept.read_text())["candidates"][0]["api_name"] == "IsDebuggerPresent"


def test_run_failed_detonation_logs_resume_command(monkeypatch, tmp_path, capsys):
    # The checkpoint is only useful if the user is told where it is and how to
    # pick the run back up, so the failure path names both the file and the task.
    # Asserted on stderr, not caplog: _configure_logging(force=True) drops
    # caplog's root handler.
    _patch_run_stages(monkeypatch, poll_status="failed_analysis")
    monkeypatch.chdir(tmp_path)
    assert cli.main(["run", "sample.exe", "--no-license-checkout"]) == 2
    hint = capsys.readouterr().err
    assert "results/runsha.clew.json" in hint
    assert "clew correlate --record" in hint
    assert "--task 77" in hint


def test_run_checkpoint_written_before_submit(monkeypatch, tmp_path):
    # The checkpoint must land *before* CAPE is touched -- that is the whole
    # point: a submit that never succeeds still leaves the static work on disk.
    import clew.channels.cape.client as capeclient

    seen = {}

    def fake_submit(self, sample, **kw):
        seen["checkpoint_exists"] = (tmp_path / "results" / "runsha.clew.json").is_file()
        raise capeclient.CapeError("cape is down")

    _patch_run_stages(monkeypatch)
    monkeypatch.setattr(capeclient.CapeClient, "submit", fake_submit)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["run", "sample.exe", "--no-license-checkout"]) == 2
    assert seen["checkpoint_exists"] is True


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

"""Top-level command-line entry point for the clew pipeline.

Both the `clew` console script and `python -m clew.pipeline` dispatch here. This
module owns argument parsing and logging setup; the analysis itself lives in
`clew.pipeline.run_static_pipeline`. Runtime progress is emitted through the
`logging` module (per-stage lines to stderr). The record-producing verbs
(`static`, `correlate`, `run`) default their output to a durable
`results/<sha256>.clew.json` file and log a one-line summary to stderr, so a
multi-megabyte record never floods stdout by accident. Pass `-o <path>` to
redirect, or `-o -` to stream the JSON to stdout for piping.

The surface is a subcommand dispatcher (`clew <verb> ...`): `static`,
`correlate`, `detonate`, `tasks`, and `run` (which chains static -> detonate
--wait -> correlate for one sample). Bare `clew <sample>` stays a back-compat
alias for `clew static <sample>`.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from clew.pipeline import (
    CLEW_VERSION,
    DEFAULT_CAPA_RULES,
    DEFAULT_CAPA_SIGS,
    DEFAULT_FLOSS_CACHE,
    FlossCacheStale,
    SampleNotFoundError,
    _default_capa_rules,
    _default_capa_sigs,
    run_static_pipeline,
)


def _add_static_flags(parser) -> None:
    # The static-stage flags, shared by the `static` and `run` verbs. Factored so
    # the two surfaces cannot drift on defaults. Excludes the `sample` positional
    # and `-o` (each verb owns those with its own help text).
    parser.add_argument(
        "--capa-rules",
        type=Path,
        default=Path(_default_capa_rules()),
        help=f"capa rules dir (default: $CLEW_CAPA_RULES or {DEFAULT_CAPA_RULES})",
    )
    parser.add_argument(
        "--capa-sigs",
        type=Path,
        default=Path(_default_capa_sigs()),
        help=f"capa signatures dir (default: $CLEW_CAPA_SIGS or {DEFAULT_CAPA_SIGS})",
    )
    parser.add_argument(
        "--floss-sigs",
        type=Path,
        default=None,
        help="FLOSS signature file for decoding-routine identification (default: FLOSS built-in)",
    )
    parser.add_argument(
        "--capa-bin",
        default="capa",
        help="capa executable to invoke (default: capa on PATH)",
    )
    parser.add_argument(
        "--no-license-checkout",
        action="store_true",
        help="assume a license is already checked out for this process",
    )
    parser.add_argument(
        "--exclude-unresolved",
        action="store_true",
        help="omit located-but-unresolved call sites (the Channel 3 work list)",
    )
    parser.add_argument(
        "--verbose-floss",
        action="store_true",
        help="don't suppress vivisect/FLOSS emulator logging (debugging FLOSS)",
    )
    parser.add_argument(
        "--floss-cache",
        type=Path,
        default=None,
        help=f"FLOSS result cache directory (default: {DEFAULT_FLOSS_CACHE}/)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="disable the FLOSS result cache (always re-run FLOSS, don't read/write)",
    )
    parser.add_argument(
        "--refresh-floss-cache",
        action="store_true",
        help="force a FLOSS re-run and overwrite the cache entry (use after a FLOSS/sigs change)",
    )


def _add_static_subparser(sub, parent) -> None:
    s = sub.add_parser(
        "static",
        parents=[parent],
        help="run the static pipeline over a PE32 sample and emit the clew record",
        description="Run the clew static pipeline over a PE32 sample and emit the "
        "intermediate clew record.",
    )
    s.add_argument("sample", help="path to the PE32 sample")
    _add_static_flags(s)
    s.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the record here; default results/<sha256>.clew.json, '-' for stdout",
    )
    s.set_defaults(func=_cmd_static)


def _add_correlate_subparser(sub, parent) -> None:
    s = sub.add_parser(
        "correlate",
        parents=[parent],
        help="join runtime cmp/test operands (Channel 3) onto a static clew record",
        description="Enrich a static clew record with proximity-correlated comparison "
        "operands from DynamoRIO cmplog logs.",
    )
    s.add_argument(
        "--record",
        required=True,
        help="path to the intermediate record JSON to enrich",
    )
    # Exactly one log source is required: a local dir of logs (offline primary
    # path) or a CAPE task id (reads logs from CAPE storage on this host).
    source = s.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--cmplog-dir",
        help="dir of cmplog.*.log files (offline; no CAPE needed)",
    )
    source.add_argument(
        "--task",
        type=int,
        help="CAPE task id; reads cmplog.*.log from CAPE storage",
    )
    s.add_argument(
        "--module-base",
        type=lambda v: int(v, 0),
        default=None,
        help="runtime load base to rebase PCs into static VA space (0x... accepted)",
    )
    s.add_argument(
        "--storage-root",
        default="/opt/CAPEv2/storage/analyses",
        help="CAPE analyses storage root (only used with --task)",
    )
    s.add_argument(
        "--cape-url",
        default=os.environ.get("CAPE_BASE_URL", "http://127.0.0.1:8000"),
        help="CAPE base URL (only used with --task; default $CAPE_BASE_URL)",
    )
    s.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the record here; default results/<sha256>.clew.json, '-' for stdout",
    )
    s.set_defaults(func=_cmd_correlate)


def _add_detonate_subparser(sub, parent) -> None:
    s = sub.add_parser(
        "detonate",
        parents=[parent],
        help="submit a sample to CAPE for DynamoRIO comparison logging (Channel 3)",
        description="Submit a PE32 sample to CAPE under the exe_cmplog package and emit "
        "the task id (with --wait, block for the terminal status).",
    )
    s.add_argument("sample", help="path to the PE32 sample")
    s.add_argument(
        "--package",
        default="exe_cmplog",
        help="CAPE analysis package (default: exe_cmplog, the cmplog DR client)",
    )
    s.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="guest analysis timeout in seconds (default: 120)",
    )
    s.add_argument(
        "--wait",
        action="store_true",
        help="block until the task reaches a terminal state and report the status",
    )
    # enforce_timeout defaults True: sleepy anti-analysis samples otherwise hang
    # the guest. BooleanOptionalAction gives the --enforce-timeout/--no-* pair.
    s.add_argument(
        "--enforce-timeout",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="kill the guest at --timeout instead of waiting for self-exit (default: on)",
    )
    s.add_argument(
        "--cape-url",
        default=os.environ.get("CAPE_BASE_URL", "http://127.0.0.1:8000"),
        help="CAPE base URL (default $CAPE_BASE_URL or http://127.0.0.1:8000)",
    )
    s.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the result JSON here (default: stdout)",
    )
    s.set_defaults(func=_cmd_detonate)


def _add_tasks_subparser(sub, parent) -> None:
    s = sub.add_parser(
        "tasks",
        parents=[parent],
        help="list CAPE tasks with a cmplog RECORDS column (a dashboard for Channel 3)",
        description="List CAPE analysis tasks as a table (or JSON), showing the cmplog "
        "record count for terminal tasks. With --watch, refresh in place.",
    )
    s.add_argument(
        "--status",
        default=None,
        help="only show tasks with this status (e.g. reported, failed_analysis)",
    )
    s.add_argument(
        "--limit",
        type=int,
        default=None,
        help="show at most this many tasks (newest first)",
    )
    s.add_argument(
        "--json",
        action="store_true",
        help="emit the rows as JSON instead of a table (for piping)",
    )
    s.add_argument(
        "--watch",
        action="store_true",
        help="refresh continuously until interrupted (Ctrl-C to exit)",
    )
    s.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="seconds between refreshes when --watch is set (default: 2.0)",
    )
    s.add_argument(
        "--cape-url",
        default=os.environ.get("CAPE_BASE_URL", "http://127.0.0.1:8000"),
        help="CAPE base URL (default $CAPE_BASE_URL or http://127.0.0.1:8000)",
    )
    s.add_argument(
        "--storage-root",
        default="/opt/CAPEv2/storage/analyses",
        help="CAPE analyses storage root (read for the RECORDS column)",
    )
    s.set_defaults(func=_cmd_tasks)


def _add_run_subparser(sub, parent) -> None:
    s = sub.add_parser(
        "run",
        parents=[parent],
        help="run static -> detonate --wait -> correlate end to end for one sample",
        description="Chain the static pipeline, a CAPE cmplog detonation, and proximity "
        "correlation into one enriched clew record for a single sample.",
    )
    s.add_argument("sample", help="path to the PE32 sample")
    # Static stage (shared with the `static` verb, same defaults).
    _add_static_flags(s)
    # Detonate stage.
    s.add_argument(
        "--package",
        default="exe_cmplog",
        help="CAPE analysis package (default: exe_cmplog, the cmplog DR client)",
    )
    s.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="guest analysis timeout in seconds (default: 120)",
    )
    s.add_argument(
        "--cape-url",
        default=os.environ.get("CAPE_BASE_URL", "http://127.0.0.1:8000"),
        help="CAPE base URL (default $CAPE_BASE_URL or http://127.0.0.1:8000)",
    )
    # Correlate stage.
    s.add_argument(
        "--module-base",
        type=lambda v: int(v, 0),
        default=None,
        help="runtime load base to rebase PCs into static VA space (0x... accepted)",
    )
    s.add_argument(
        "--storage-root",
        default="/opt/CAPEv2/storage/analyses",
        help="CAPE analyses storage root (read for the cmplog logs)",
    )
    s.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the record here; default results/<sha256>.clew.json, '-' for stdout",
    )
    s.set_defaults(func=_cmd_run)


def build_parser() -> argparse.ArgumentParser:
    # A shared parent carries the global verbosity group so it works after any
    # verb (clew static -v ...). A global flag placed BEFORE an explicit verb is
    # not supported (write `clew static -v ...`, not `clew -v static ...`); the
    # legacy no-verb form `clew -v sample.exe` still works because it injects the
    # `static` verb ahead of the flags (see _inject_default_verb).
    parent = argparse.ArgumentParser(add_help=False)
    verbosity = parent.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="verbose (debug-level) logging",
    )
    verbosity.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="only log warnings and errors (suppress per-stage progress)",
    )

    p = argparse.ArgumentParser(
        prog="clew",
        parents=[parent],
        description="clew per-sample candidate-extraction pipeline.",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"clew {CLEW_VERSION}",
    )
    sub = p.add_subparsers(dest="command")
    _add_static_subparser(sub, parent)
    _add_correlate_subparser(sub, parent)
    _add_detonate_subparser(sub, parent)
    _add_tasks_subparser(sub, parent)
    _add_run_subparser(sub, parent)
    return p


def _known_verbs(parser: argparse.ArgumentParser) -> set[str]:
    # Read the registered subparser choices so the back-compat injection stays
    # correct as verbs are added in later commits.
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    return set()


def _inject_default_verb(argv, known_verbs):
    # Back-compat: `clew sample.exe` -> `clew static sample.exe`. argparse can't
    # fall through to a default positional, so inject the verb before parsing.
    if not argv:
        return argv
    if argv[0] in known_verbs:
        return argv
    if argv[0] in ("-h", "--help", "--version"):
        return argv
    return ["static", *argv]


def _configure_logging(verbose: int, quiet: bool) -> None:
    if quiet:
        level = logging.WARNING
    elif verbose >= 1:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
        force=True,
    )


def _default_record_path(record) -> Path:
    # The record is the tool's durable product, keyed by sample hash so reruns
    # of the same sample land on the same file.
    return Path("results") / f"{record['sample_sha256']}.clew.json"


def _emit_record(record, output, summary: str) -> None:
    # Resolve where a record-producing verb writes its output. The record is
    # MB-scale, so a bare stdout dump is a footgun: default to a durable file and
    # log the summary to stderr. `-o -` is the escape hatch for piping.
    text = json.dumps(record, indent=2)
    if output == Path("-"):
        # Pipe mode: JSON to stdout, nothing else on stdout.
        print(text)
        return
    if output is None:
        path = _default_record_path(record)
        path.parent.mkdir(parents=True, exist_ok=True)
    else:
        path = output
    path.write_text(text)
    logging.getLogger("clew.cli").info("wrote %s: %s", path, summary)


def _cmd_static(args) -> int:
    log = logging.getLogger("clew.cli")
    log.info("clew %s starting", CLEW_VERSION)

    try:
        record = run_static_pipeline(
            args.sample,
            capa_rules_path=args.capa_rules,
            capa_sigs_path=args.capa_sigs,
            floss_sigs_path=args.floss_sigs,
            capa_bin=args.capa_bin,
            include_unresolved=not args.exclude_unresolved,
            run_license_checkout=not args.no_license_checkout,
            quiet_floss=not args.verbose_floss,
            floss_cache_dir=args.floss_cache,
            use_floss_cache=not args.no_cache,
            refresh_floss_cache=args.refresh_floss_cache,
        )
    except FlossCacheStale as e:
        log.error("%s", e)
        return 2
    except SampleNotFoundError as e:
        log.error("%s", e)
        return 1

    resolved = sum(
        1
        for c in record["candidates"]
        if any(v.get("value") is not None for v in c["candidate_values"])
    )
    summary = (
        f"{len(record['candidates'])} candidates ({resolved} with values), "
        f"derivation_status={record['derivation_status']}, "
        f"{len(record['capa_techniques'])} capa techniques"
    )
    _emit_record(record, args.output, summary)
    log.info("done")
    return 0


def _cmd_correlate(args) -> int:
    # Lazy imports: keep `clew static` and the offline suite free of the CAPE
    # client (which pulls requests) and the correlator.
    from clew.channels.cape.cmplog_parse import parse_cmplog_files
    from clew.channels.cape.correlate import correlate_record

    log = logging.getLogger("clew.cli")

    record_path = Path(args.record)
    try:
        record = json.loads(record_path.read_text())
    except FileNotFoundError:
        log.error("record not found: %s", record_path)
        return 1

    if args.cmplog_dir is not None:
        cmplog_dir = Path(args.cmplog_dir)
        if not cmplog_dir.is_dir():
            log.error("cmplog dir not found: %s", cmplog_dir)
            return 1
        logs = sorted(cmplog_dir.glob("cmplog.*.log"))
        if not logs:
            log.warning("no cmplog.*.log files in %s (comparisons will be empty)", cmplog_dir)
    else:
        from clew.channels.cape.client import CapeClient, CapeError

        try:
            logs = CapeClient(args.cape_url).fetch_cmplog_logs(args.task, args.storage_root)
        except CapeError as e:
            log.error("%s", e)
            return 2

    cmp_records = parse_cmplog_files(logs)
    log.info("parsed %d comparison records from %d log(s)", len(cmp_records), len(logs))
    enriched = correlate_record(record, cmp_records, module_base=args.module_base)

    with_cmps = [c for c in enriched["candidates"] if c.get("comparison_candidates")]
    total_cmps = sum(len(c["comparison_candidates"]) for c in with_cmps)
    summary = (
        f"{len(enriched['candidates'])} candidates, "
        f"{len(with_cmps)} with comparison_candidates ({total_cmps} total comparisons)"
    )
    _emit_record(enriched, args.output, summary)
    log.info("done")
    return 0


def _cmd_detonate(args) -> int:
    # Lazy import: keep the CAPE client (which pulls requests) out of `clew
    # static` and the offline suite.
    from clew.channels.cape.client import CapeClient, CapeError

    log = logging.getLogger("clew.cli")

    c = CapeClient(args.cape_url)
    try:
        # free=yes is mandatory: capemon otherwise corrupts DynamoRIO and the
        # run yields 0 logs. It rides inside the options string via submit().
        tid = c.submit(
            args.sample,
            package=args.package,
            timeout=args.timeout,
            enforce_timeout=args.enforce_timeout,
            options={"free": "yes"},
        )
    except FileNotFoundError:
        log.error("sample not found: %s", args.sample)
        return 1
    except CapeError as e:
        log.error("submit failed: %s", e)
        return 2

    log.info("submitted task %s (package=%s)", tid, args.package)

    if args.wait:
        status = c.poll(tid, progress=lambda s: log.info("task %s: %s", tid, s))
        result = {"task_id": tid, "status": status}
        rc = 0 if status == "reported" else 2
    else:
        result = {"task_id": tid}
        rc = 0

    text = json.dumps(result)
    if args.output:
        args.output.write_text(text)
        log.info("wrote %s", args.output)
    else:
        print(text)
    return rc


def _humanize_age(added_on: str | None) -> str:
    # Parse the CAPE added_on timestamp and return a compact age relative to
    # now (12s / 4m / 2h / 3d). Real wall-clock is fine here, this runs in the
    # user's CLI process. Unparseable or missing -> "-".
    if not added_on:
        return "-"
    parsed = None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(added_on, fmt)
            break
        except (ValueError, TypeError):
            continue
    if parsed is None:
        try:
            # ISO 8601 with fractional seconds or offset.
            parsed = datetime.fromisoformat(added_on)
        except (ValueError, TypeError):
            return "-"
    # A tz-aware timestamp cannot be subtracted from a naive now(); drop the
    # tzinfo and compare in wall-clock terms (good enough for an age column).
    if parsed.tzinfo is not None:
        parsed = parsed.replace(tzinfo=None)
    seconds = int((datetime.now() - parsed).total_seconds())
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def _build_display_rows(tasks, client, storage_root) -> list[dict]:
    # Map raw CAPE task dicts to the display rows the table/JSON consume. The
    # real payload carries the on-disk path in `target` (a string) and `sample`
    # as a metadata dict, so prefer target and fall back defensively.
    rows = []
    for t in tasks:
        target = t.get("target")
        sample_field = t.get("sample")
        name = None
        for candidate in (target, sample_field):
            if isinstance(candidate, str) and candidate:
                name = os.path.basename(candidate)
                break
        status = t.get("status", "unknown")
        task_id = t.get("id")
        # RECORDS only makes sense once the task is terminal and its logs are
        # written; for anything else, or an unreadable/missing log, show "-".
        records = "-"
        if status == "reported" and task_id is not None:
            n = client.count_cmplog_lines(task_id, storage_root)
            if n is not None:
                records = str(n)
        rows.append(
            {
                "task": str(task_id) if task_id is not None else "-",
                "sample": name or "-",
                "pkg": t.get("package") or "-",
                "status": status,
                "records": records,
                "age": _humanize_age(t.get("added_on")),
            }
        )
    return rows


def _format_tasks_table(display_rows: list[dict]) -> str:
    # Fixed-width, right-padded table. Columns size to the widest cell so the
    # header and values line up regardless of content.
    columns = [
        ("TASK", "task"),
        ("SAMPLE", "sample"),
        ("PKG", "pkg"),
        ("STATUS", "status"),
        ("RECORDS", "records"),
        ("AGE", "age"),
    ]
    widths = {}
    for header, key in columns:
        widest = max([len(header)] + [len(str(r.get(key, ""))) for r in display_rows])
        widths[key] = widest

    def render(cells) -> str:
        return "  ".join(
            str(value).ljust(widths[key]) for (_, key), value in zip(columns, cells)
        ).rstrip()

    lines = [render([header for header, _ in columns])]
    for r in display_rows:
        lines.append(render([r.get(key, "") for _, key in columns]))
    return "\n".join(lines)


def _requests_exc():
    # The requests base exception, resolved lazily so requests (a Channel-3-only
    # dep) stays out of the module-top imports. Falls back to a never-matching
    # empty tuple if requests is somehow absent, so the CapeError branch still works.
    try:
        import requests

        return requests.RequestException
    except ImportError:  # pragma: no cover
        return ()


def _cmd_tasks(args) -> int:
    # Lazy import: keep the CAPE client (which pulls requests) out of `clew
    # static` and the offline suite.
    from clew.channels.cape.client import CapeClient, CapeError

    log = logging.getLogger("clew.cli")
    c = CapeClient(args.cape_url)

    def render() -> None:
        tasks = c.list_tasks(limit=args.limit, status=args.status)
        rows = _build_display_rows(tasks, c, args.storage_root)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print(_format_tasks_table(rows))

    try:
        if args.watch:
            try:
                while True:
                    # A timestamp header each redraw marks the refresh without
                    # aggressively clearing the screen (progress lands on stderr).
                    print(f"# clew tasks @ {datetime.now():%H:%M:%S} (Ctrl-C to exit)")
                    render()
                    time.sleep(args.interval)
            except KeyboardInterrupt:
                return 0
        else:
            render()
    except (CapeError, _requests_exc()) as e:
        log.error("cannot reach CAPE at %s: %s", args.cape_url, e)
        return 2
    return 0


def _cmd_run(args) -> int:
    # Lazy import: keep the CAPE client (which pulls requests) and the correlator
    # out of `clew static` and the offline suite.
    from clew.channels.cape.client import CapeClient, CapeError
    from clew.channels.cape.cmplog_parse import parse_cmplog_files
    from clew.channels.cape.correlate import correlate_record

    log = logging.getLogger("clew.cli")
    log.info("clew %s run starting", CLEW_VERSION)

    # Stage 1/3 static: the fast local pipeline (same inverted flags as `static`).
    try:
        record = run_static_pipeline(
            args.sample,
            capa_rules_path=args.capa_rules,
            capa_sigs_path=args.capa_sigs,
            floss_sigs_path=args.floss_sigs,
            capa_bin=args.capa_bin,
            include_unresolved=not args.exclude_unresolved,
            run_license_checkout=not args.no_license_checkout,
            quiet_floss=not args.verbose_floss,
            floss_cache_dir=args.floss_cache,
            use_floss_cache=not args.no_cache,
            refresh_floss_cache=args.refresh_floss_cache,
        )
    except FlossCacheStale as e:
        log.error("%s", e)
        return 2
    except SampleNotFoundError as e:
        log.error("%s", e)
        return 1
    log.info("stage 1/3 static: %d candidates", len(record["candidates"]))

    # Stage 2/3 detonate: submit under cmplog + free mode and block for terminal.
    c = CapeClient(args.cape_url)
    try:
        # free=yes is mandatory: capemon otherwise corrupts DynamoRIO and the run
        # yields 0 logs. It rides inside the options string via submit().
        tid = c.submit(
            args.sample,
            package=args.package,
            timeout=args.timeout,
            options={"free": "yes"},
        )
    except FileNotFoundError:
        log.error("sample not found: %s", args.sample)
        return 1
    except CapeError as e:
        log.error("submit failed: %s", e)
        return 2
    log.info("submitted task %s (package=%s)", tid, args.package)

    status = c.poll(tid, progress=lambda s: log.info("task %s: %s", tid, s))
    if status != "reported":
        # A failed detonation has no logs to correlate against.
        log.error("task %s did not report (status=%s), cannot correlate", tid, status)
        return 2
    log.info("stage 2/3 detonate: task %s reported", tid)

    # Stage 3/3 correlate: join the runtime comparisons onto the static record. An
    # empty log set is honest, not a failure -- some samples defeat DynamoRIO and
    # legitimately yield zero comparisons.
    try:
        logs = c.fetch_cmplog_logs(tid, args.storage_root)
    except CapeError as e:
        log.error("%s", e)
        return 2
    cmp_records = parse_cmplog_files(logs)
    enriched = correlate_record(record, cmp_records, module_base=args.module_base)
    with_cmps = [cand for cand in enriched["candidates"] if cand.get("comparison_candidates")]
    log.info("stage 3/3 correlate: %d candidates with comparisons", len(with_cmps))

    total_cmps = sum(len(cand["comparison_candidates"]) for cand in with_cmps)
    summary = (
        f"{len(enriched['candidates'])} candidates, "
        f"{len(with_cmps)} with comparison_candidates ({total_cmps} total comparisons)"
    )
    _emit_record(enriched, args.output, summary)
    log.info("done")
    return 0


def main(argv=None) -> int:
    raw = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    argv2 = _inject_default_verb(raw, _known_verbs(parser))
    args = parser.parse_args(argv2)
    _configure_logging(args.verbose, args.quiet)
    if getattr(args, "command", None) is None:
        # Bare `clew` -> show the verb menu.
        parser.print_help(sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

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
from datetime import datetime, timezone
from pathlib import Path

from clew.config import default_capa_bin, load_config, loaded_files
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

# Timeout used when --capa is given without a value. capa is a subprocess and a
# hostile or merely large sample can hang it; 300s proved too tight in practice
# (autoit3 exceeded it on a loaded box), so the default that applies when the
# analyst opts in is deliberately generous.
DEFAULT_CAPA_TIMEOUT = 600


def _capa_timeout(value: str):
    # --capa takes an optional value, so `clew static --capa sample.exe` makes
    # argparse swallow the sample as the timeout. That is unavoidable with
    # nargs="?", but the stock error ("invalid int value: 'sample.exe'") explains
    # nothing, so name both working forms instead.
    try:
        return int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"expected a timeout in seconds, got {value!r}. If that is your sample, "
            f"put --capa after it (clew static SAMPLE --capa) or attach the value "
            f"with '=' (--capa=600)."
        ) from None


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
        default=default_capa_bin(),
        help="capa executable to invoke (default: the capa installed alongside clew, "
        "else capa on PATH)",
    )
    # One flag, two jobs: presence enables Channel 0, and the optional value is
    # its timeout. capa is off by default because it is the slowest stage and
    # contributes no candidate values.
    parser.add_argument(
        "--capa",
        dest="capa_timeout",
        nargs="?",
        type=_capa_timeout,
        const=DEFAULT_CAPA_TIMEOUT,
        default=None,
        metavar="SECONDS",
        help=f"run capa (Channel 0), optionally with a timeout in seconds "
        f"(default {DEFAULT_CAPA_TIMEOUT}); omitted entirely, capa does not run and "
        f"derivation_status is null",
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
    s.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing record even if it carries Channel 3 runtime data",
    )
    s.set_defaults(func=_cmd_static)


def _add_correlate_subparser(sub, parent) -> None:
    s = sub.add_parser(
        "correlate",
        parents=[parent],
        help="join Channel 3 runtime observations onto a static clew record",
        description="Enrich a static clew record from DynamoRIO logs: comparison "
        "operands, and (drtrace logs only) the observed API calls, their arguments, "
        "out-parameters and return values.",
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
        # --cmplog-dir kept as an alias: it is in usage.md, in the journal, and
        # in muscle memory, and the directory may still hold cmplog logs.
        "--log-dir",
        "--cmplog-dir",
        dest="log_dir",
        help="dir of drtrace.*.log or cmplog.*.log files (offline; no CAPE needed)",
    )
    source.add_argument(
        "--task",
        type=int,
        help="CAPE task id; reads the trace logs from CAPE storage",
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
        "--max-cmp-records",
        type=int,
        default=5_000_000,
        help="cap comparison records loaded from the logs (0 = unlimited); guards "
        "host memory/CPU against a hostile sample's oversized log",
    )
    s.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the record here; default results/<sha256>.clew.json, '-' for stdout",
    )
    s.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing record even if it carries Channel 3 runtime data",
    )
    s.set_defaults(func=_cmd_correlate)


def _add_detonate_subparser(sub, parent) -> None:
    s = sub.add_parser(
        "detonate",
        parents=[parent],
        help="submit a sample to CAPE for DynamoRIO comparison logging (Channel 3)",
        description="Submit a PE32 sample to CAPE under the exe_drtrace package and emit "
        "the task id (with --wait, block for the terminal status).",
    )
    s.add_argument("sample", help="path to the PE32 sample")
    s.add_argument(
        "--package",
        default="exe_drtrace",
        help="CAPE analysis package (default: exe_drtrace, the drtrace DR client)",
    )
    s.add_argument(
        "--sample-args",
        default=None,
        help="command line to pass to the sample itself, e.g. al-khaser's "
        "'--check VBOX --check DEBUG --sleep 5'. Commas are not allowed: CAPE's "
        "option string is comma-separated",
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
        help="list CAPE tasks with a trace RECORDS column (a dashboard for Channel 3)",
        description="List CAPE analysis tasks as a table (or JSON), showing the trace "
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
        "--show-drtrace",
        type=int,
        metavar="TASK",
        default=None,
        help="decode and print one task's drtrace output instead of the table",
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
        description="Chain the static pipeline, a CAPE drtrace detonation, and "
        "correlation into one enriched clew record for a single sample.",
    )
    s.add_argument("sample", help="path to the PE32 sample")
    # Static stage (shared with the `static` verb, same defaults).
    _add_static_flags(s)
    # Detonate stage.
    s.add_argument(
        "--package",
        default="exe_drtrace",
        help="CAPE analysis package (default: exe_drtrace, the drtrace DR client)",
    )
    s.add_argument(
        "--sample-args",
        default=None,
        help="command line to pass to the sample itself, e.g. al-khaser's "
        "'--check VBOX --check DEBUG --sleep 5'. Commas are not allowed: CAPE's "
        "option string is comma-separated",
    )
    s.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="guest analysis timeout in seconds (default: 120)",
    )
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
        help="CAPE analyses storage root (read for the trace logs)",
    )
    s.add_argument(
        "--max-cmp-records",
        type=int,
        default=5_000_000,
        help="cap comparison records loaded from the logs (0 = unlimited); guards "
        "host memory/CPU against a hostile sample's oversized log",
    )
    s.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the record here; default results/<sha256>.clew.json, '-' for stdout",
    )
    s.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing record even if it carries Channel 3 runtime data",
    )
    s.set_defaults(func=_cmd_run)


def _add_doctor_subparser(sub, parent) -> None:
    s = sub.add_parser(
        "doctor",
        parents=[parent],
        help="check that clew's prerequisites are installed and configured",
        description="Report whether Binary Ninja, capa, FLOSS and CAPE are reachable and "
        "correctly configured, with the fix for anything that is not.",
    )
    s.add_argument(
        "--license",
        action="store_true",
        help="also load Binary Ninja and take a license seat (slower; consumes a seat)",
    )
    s.add_argument(
        "--cape-url",
        default=os.environ.get("CAPE_BASE_URL", "http://127.0.0.1:8000"),
        help="CAPE base URL to probe (default $CAPE_BASE_URL or http://127.0.0.1:8000)",
    )
    s.add_argument(
        "--storage-root",
        default="/opt/CAPEv2/storage/analyses",
        help="CAPE analyses storage root to check for readability",
    )
    s.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="seconds to wait on the CAPE probe (default: 5)",
    )
    s.set_defaults(func=_cmd_doctor)


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
    _add_doctor_subparser(sub, parent)
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


class RecordRegression(Exception):
    """Writing this record would replace observed runtime data with less."""


def _has_runtime_data(record) -> bool:
    """Whether a record carries Channel 3 observations.

    Any of the three shapes correlation produces: comparisons joined onto a
    candidate, a candidate Channel 3 produced itself, or a value it contributed
    to a static candidate.
    """
    for candidate in record.get("candidates") or []:
        if candidate.get("comparison_candidates"):
            return True
        if candidate.get("api_resolution") == "runtime":
            return True
        for value in candidate.get("candidate_values") or []:
            if "drio" in (value.get("source_channels") or []):
                return True
    return False


def _would_regress(record, path: Path) -> bool:
    """True if `path` holds runtime data that `record` does not.

    `static` and `correlate` share a default output path keyed on the sample
    hash, so re-running `static` on an already-correlated sample silently
    replaced a detonation's worth of observation with a record that never had
    any. The check is deliberately asymmetric: re-running `static` over a
    `static` record, or re-correlating, replaces like with like and is allowed.
    """
    if _has_runtime_data(record) or not path.exists():
        return False
    try:
        existing = json.loads(path.read_text())
    except (OSError, ValueError):
        # Unreadable or not JSON: nothing to protect, and refusing here would
        # strand the user behind a file they cannot inspect.
        return False
    return _has_runtime_data(existing)


def _emit_record(record, output, summary: str, force: bool = False) -> None:
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
    else:
        path = output
    if not force and _would_regress(record, path):
        raise RecordRegression(
            f"{path} already holds Channel 3 runtime data and this record has none. "
            f"Re-run with --force to overwrite it, or -o <path> to write elsewhere."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
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
            capa_timeout=args.capa_timeout,
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
    # A null derivation_status means capa was not run at all. Printing the bare
    # None would read as a failure rather than a deliberate skip.
    if record["derivation_status"] is None:
        capa_part = "capa not run"
    else:
        capa_part = (
            f"derivation_status={record['derivation_status']}, "
            f"{len(record['capa_techniques'])} capa techniques"
        )
    summary = f"{len(record['candidates'])} candidates ({resolved} with values), {capa_part}"
    _emit_record(record, args.output, summary, force=args.force)
    log.info("done")
    return 0


def _logs_from_dir(log_dir: Path) -> tuple[list[Path], str | None]:
    """(logs, kind) for a local directory. drtrace wins when both are present."""
    for kind in ("drtrace", "cmplog"):
        logs = sorted(log_dir.glob(f"{kind}.*.log"))
        if logs:
            return logs, kind
    return [], None


def _apply_correlation(record: dict, logs: list[Path], kind: str | None, args, log) -> dict:
    """Run the Channel 3 correlation appropriate to the log family.

    Shared by `correlate` and `run` so the two verbs cannot drift on which
    parser, which entry point, or which caps they use.
    """
    if kind == "drtrace":
        from clew.channels.cape.correlate import correlate_trace
        from clew.channels.cape.drtrace_parse import parse_drtrace_files

        trace = parse_drtrace_files(logs, max_records=args.max_cmp_records)
        log.info(
            "parsed %d comparisons, %d API calls, %d module loads from %d drtrace log(s)",
            len(trace.comparisons),
            len(trace.calls),
            len(trace.modules),
            len(logs),
        )
        return correlate_trace(record, trace, module_base=args.module_base)

    from clew.channels.cape.cmplog_parse import parse_cmplog_files
    from clew.channels.cape.correlate import correlate_record

    cmp_records = parse_cmplog_files(logs, max_records=args.max_cmp_records)
    log.info("parsed %d comparison records from %d cmplog log(s)", len(cmp_records), len(logs))
    return correlate_record(record, cmp_records, module_base=args.module_base)


def _correlation_summary(record: dict) -> str:
    candidates = record["candidates"]
    with_cmps = [c for c in candidates if c.get("comparison_candidates")]
    total_cmps = sum(len(c["comparison_candidates"]) for c in with_cmps)
    produced = [c for c in candidates if c.get("api_resolution") == "runtime"]
    summary = (
        f"{len(candidates)} candidates, "
        f"{len(with_cmps)} with comparison_candidates ({total_cmps} total comparisons)"
    )
    if produced:
        summary += f", {len(produced)} produced from observed API calls"
    return summary


def _cmd_correlate(args) -> int:
    log = logging.getLogger("clew.cli")

    record_path = Path(args.record)
    try:
        record = json.loads(record_path.read_text())
    except FileNotFoundError:
        log.error("record not found: %s", record_path)
        return 1

    if args.log_dir is not None:
        log_dir = Path(args.log_dir)
        if not log_dir.is_dir():
            log.error("log dir not found: %s", log_dir)
            return 1
        logs, kind = _logs_from_dir(log_dir)
        if not logs:
            log.warning(
                "no drtrace.*.log or cmplog.*.log files in %s (nothing to correlate)", log_dir
            )
    else:
        # Lazy import: keep the CAPE client (which pulls requests) out of `clew
        # static` and the offline suite.
        from clew.channels.cape.client import CapeClient, CapeError

        try:
            # fetch_trace_logs reads CAPE's on-disk storage (no REST call), so
            # the client needs no base URL here (correlate has no --cape-url).
            logs, kind = CapeClient("").fetch_trace_logs(args.task, args.storage_root)
        except CapeError as e:
            log.error("%s", e)
            return 2
        if not logs:
            log.warning("task %s has no Channel 3 logs (nothing to correlate)", args.task)

    enriched = _apply_correlation(record, logs, kind, args, log)
    _emit_record(enriched, args.output, _correlation_summary(enriched), force=args.force)
    log.info("done")
    return 0


def _submit_options(args) -> dict[str, str]:
    """CAPE package options for a Channel 3 submission.

    `free=yes` is mandatory and not negotiable: capemon otherwise injects into
    drrun.exe, corrupts DynamoRIO, and the run yields no logs at all.

    `arguments` is how a sample's own command line reaches it. That matters for
    samples whose behaviour is selectable -- al-khaser runs only the check groups
    named by `--check`, which is what lets it exercise the target APIs without
    the groups that defeat instrumentation.
    """
    options = {"free": "yes"}
    sample_args = getattr(args, "sample_args", None)
    if sample_args:
        options["arguments"] = sample_args
    return options


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
            options=_submit_options(args),
        )
    except FileNotFoundError:
        log.error("sample not found: %s", args.sample)
        return 1
    except CapeError as e:
        log.error("submit failed: %s", e)
        return 2

    log.info("submitted task %s (package=%s)", tid, args.package)

    if args.wait:
        try:
            status = c.poll(tid, progress=lambda s: log.info("task %s: %s", tid, s))
        except CapeError as e:
            log.error("%s", e)
            return 2
        result = {"task_id": tid, "status": status}
        rc = 0 if status == "reported" else 2
    else:
        result = {"task_id": tid}
        rc = 0

    text = json.dumps(result)
    if args.output and args.output != Path("-"):
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
        log.info("wrote %s", args.output)
    else:
        # No -o, or `-o -`: stream to stdout (consistent with the record verbs).
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
    # CAPE writes added_on in UTC with no offset. Comparing that against a local
    # now() puts every recent task in the future west of Greenwich -- the clamp
    # below then reported them all as "0s", and older ones under-reported by the
    # UTC offset. So a naive timestamp is read as UTC, and the comparison is done
    # in UTC. A tz-aware one is honoured as given.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    seconds = int((datetime.now(timezone.utc) - parsed).total_seconds())
    if seconds < 0:
        # Still possible from clock skew between this host and the CAPE host.
        seconds = 0
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


# Terminal CAPE task states (mirrors CapeClient.poll). A task is "done" in any of
# these; RECORDS is meaningful for all of them, not just 'reported'.
_TERMINAL_STATUSES = frozenset({"reported", "failed_analysis", "failed_processing"})


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
        if status in _TERMINAL_STATUSES and task_id is not None:
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


def _display_string(text: str) -> str:
    """Quote a logged string for display without mangling it.

    repr() would double every backslash, which makes a Windows path unreadable.
    But these bytes came from memory the sample controls, so printing them raw
    would let a crafted string emit terminal escapes. Escape the control
    characters, leave everything else alone.
    """
    safe = "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in text)
    return f"'{safe}'"


def _print_trace(task_id: int, storage_root) -> int:
    """Decode one task's logs to stdout.

    The RECORDS column answers "did anything come back". This answers "what",
    which otherwise means reading hex out of a log file by hand: the client
    encodes logged strings because they come from memory the sample controls.
    """
    from clew.channels.cape.client import CapeClient, CapeError

    log = logging.getLogger("clew.cli")
    try:
        logs, kind = CapeClient("").fetch_trace_logs(task_id, storage_root)
    except CapeError as exc:
        log.error("%s", exc)
        return 2
    if not logs:
        log.error("task %s has no Channel 3 logs", task_id)
        return 1

    if kind == "cmplog":
        from clew.channels.cape.cmplog_parse import parse_cmplog_files

        records = parse_cmplog_files(logs)
        print(f"task {task_id}: cmplog, {len(records)} comparisons (no API tracing)")
        return 0

    from clew.channels.cape.drtrace_parse import parse_drtrace_files

    trace = parse_drtrace_files(logs)
    main = trace.main_module()
    print(f"task {task_id}: drtrace, {len(trace.modules)} modules, "
          f"{len(trace.calls)} calls, {len(trace.comparisons)} comparisons")
    if main is not None:
        print(f"  sample module: {main.name} @ 0x{main.base:08x}-0x{main.end:08x}")

    if trace.calls:
        print("\n  observed API calls")
        for call in trace.calls:
            rv = f"-> 0x{call.retval:x}" if call.retval is not None else "(no return)"
            strings = " ".join(
                [f"arg{i}={_display_string(v)}" for i, v in sorted(call.arg_strings.items())]
                + [f"out{i}={_display_string(v)}" for i, v in sorted(call.out_strings.items())]
            )
            print(f"    seq={call.seq:<7} {call.api:<28} site=0x{call.site:08x} "
                  f"{rv} {strings}".rstrip())

    resolved = [r for r in trace.comparisons if r.jcc]
    print(f"\n  comparisons: {len(trace.comparisons)} "
          f"({len(resolved)} carry the branch that resolves the operator)")
    for notice in trace.capped:
        print(f"  capped: {notice.api} at 0x{notice.site:08x} after {notice.after} calls")
    return 0


def _cmd_tasks(args) -> int:
    # Lazy import: keep the CAPE client (which pulls requests) out of `clew
    # static` and the offline suite.
    from clew.channels.cape.client import CapeClient, CapeError

    log = logging.getLogger("clew.cli")
    if args.show_drtrace is not None:
        return _print_trace(args.show_drtrace, args.storage_root)
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


def _run_checkpoint_path(args, record) -> Path:
    # Where `run` parks the static record before handing off to CAPE. `-o -` has
    # no file to park in, so fall back to the durable default: the safety net
    # matters most in pipe mode, where nothing else lands on disk.
    if args.output is None or args.output == Path("-"):
        return _default_record_path(record)
    return args.output


def _log_resume(log, checkpoint: Path, tid=None) -> None:
    # Stage 1 is the expensive half (BN analysis + a license seat). If a later
    # stage fails, say where that work is and how to pick it back up.
    if tid is None:
        log.error("static record kept at %s", checkpoint)
    else:
        log.error(
            "static record kept at %s -- resume with: clew correlate --record %s --task %s",
            checkpoint,
            checkpoint,
            tid,
        )


def _cmd_run(args) -> int:
    # Lazy import: keep the CAPE client (which pulls requests) out of `clew
    # static` and the offline suite. The parser and correlator are imported
    # inside _apply_correlation, which picks them per log family.
    from clew.channels.cape.client import CapeClient, CapeError

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
            capa_timeout=args.capa_timeout,
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

    # Checkpoint before handing off to CAPE. Stages 2 and 3 fail routinely (a
    # sample that self-terminates under detonation, a wedged CAPE that never
    # reaches terminal), and without this the static analysis is discarded on
    # every one of those paths. The final _emit_record overwrites this file.
    checkpoint = _run_checkpoint_path(args, record)
    # The checkpoint is a *static* record, and it lands on the default path, so
    # it can regress an existing correlated one exactly as `clew static` can --
    # and it does so before the detonation that would replace the runtime data.
    # Same guard, checked here because this write does not go through
    # _emit_record.
    if not args.force and _would_regress(record, checkpoint):
        raise RecordRegression(
            f"{checkpoint} already holds Channel 3 runtime data, and `run` would "
            f"overwrite it with the static record before detonating. Re-run with "
            f"--force to replace it, or -o <path> to write elsewhere."
        )
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    checkpoint.write_text(json.dumps(record, indent=2))
    log.info("checkpointed static record to %s", checkpoint)

    # Stage 2/3 detonate: submit under cmplog + free mode and block for terminal.
    c = CapeClient(args.cape_url)
    try:
        # free=yes is mandatory: capemon otherwise corrupts DynamoRIO and the run
        # yields 0 logs. It rides inside the options string via submit().
        tid = c.submit(
            args.sample,
            package=args.package,
            timeout=args.timeout,
            enforce_timeout=args.enforce_timeout,
            options=_submit_options(args),
        )
    except FileNotFoundError:
        log.error("sample not found: %s", args.sample)
        _log_resume(log, checkpoint)
        return 1
    except CapeError as e:
        log.error("submit failed: %s", e)
        _log_resume(log, checkpoint)
        return 2
    log.info("submitted task %s (package=%s)", tid, args.package)

    try:
        status = c.poll(tid, progress=lambda s: log.info("task %s: %s", tid, s))
    except CapeError as e:
        log.error("%s", e)
        _log_resume(log, checkpoint, tid)
        return 2
    if status != "reported":
        # A failed detonation has no logs to correlate against.
        log.error("task %s did not report (status=%s), cannot correlate", tid, status)
        _log_resume(log, checkpoint, tid)
        return 2
    log.info("stage 2/3 detonate: task %s reported", tid)

    # Stage 3/3 correlate: join the runtime comparisons onto the static record. An
    # empty log set is honest, not a failure -- some samples defeat DynamoRIO and
    # legitimately yield zero comparisons.
    try:
        logs, kind = c.fetch_trace_logs(tid, args.storage_root)
    except CapeError as e:
        log.error("%s", e)
        _log_resume(log, checkpoint, tid)
        return 2
    enriched = _apply_correlation(record, logs, kind, args, log)
    summary = _correlation_summary(enriched)
    log.info("stage 3/3 correlate: %s", summary)
    _emit_record(enriched, args.output, summary, force=args.force)
    if args.output == Path("-"):
        # Pipe mode: _emit_record only streamed to stdout, so refresh the
        # checkpoint rather than leaving a stale static-only record on disk.
        checkpoint.write_text(json.dumps(enriched, indent=2))
    log.info("done")
    return 0


def _cmd_doctor(args) -> int:
    # Lazy import to match the other verbs; doctor pulls the CAPE client only
    # when it actually probes CAPE.
    from clew.doctor import format_report, has_failures, run_checks

    checks = run_checks(
        cape_url=args.cape_url,
        storage_root=args.storage_root,
        timeout=args.timeout,
        license_check=args.license,
    )
    # The report is this verb's artifact, so it goes to stdout (as `tasks` does),
    # leaving stderr for logging.
    print(format_report(checks, version=CLEW_VERSION, location=str(Path(__file__).parent)))
    return 1 if has_failures(checks) else 0


def main(argv=None) -> int:
    raw = sys.argv[1:] if argv is None else argv
    # Load config files into the environment before the parser is built. Several
    # defaults (--cape-url, --capa-rules, --capa-sigs) read os.environ at parser
    # construction time, so a load placed any later would not reach them.
    load_config()
    parser = build_parser()
    argv2 = _inject_default_verb(raw, _known_verbs(parser))
    args = parser.parse_args(argv2)
    _configure_logging(args.verbose, args.quiet)
    # Config loading necessarily runs before -v/-q are parsed, so it cannot log
    # its own result. Report it here, once logging reflects the user's choice.
    for entry in loaded_files():
        logging.getLogger("clew.config").debug(
            "%s: %d key(s) defined, %d applied",
            entry.path,
            len(entry.defined),
            len(entry.applied),
        )
    if getattr(args, "command", None) is None:
        # Bare `clew` -> show the verb menu.
        parser.print_help(sys.stderr)
        return 2
    try:
        return args.func(args)
    except RecordRegression as exc:
        logging.getLogger("clew.cli").error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

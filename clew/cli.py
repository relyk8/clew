"""Top-level command-line entry point for the clew pipeline.

Both the `clew` console script and `python -m clew.pipeline` dispatch here. This
module owns argument parsing and logging setup; the analysis itself lives in
`clew.pipeline.run_static_pipeline`. Runtime progress is emitted through the
`logging` module (per-stage lines to stderr); stdout carries only the output --
the record JSON (default) or, with `-o`, a one-line summary -- so stdout stays
clean for piping.

The surface is a subcommand dispatcher (`clew <verb> ...`). `static` and
`correlate` are registered today; detonate/tasks/run land in later commits. Bare
`clew <sample>` stays a back-compat alias for `clew static <sample>`.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
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


def _add_static_subparser(sub, parent) -> None:
    s = sub.add_parser(
        "static",
        parents=[parent],
        help="run the static pipeline over a PE32 sample and emit the clew record",
        description="Run the clew static pipeline over a PE32 sample and emit the "
        "intermediate clew record.",
    )
    s.add_argument("sample", help="path to the PE32 sample")
    s.add_argument(
        "--capa-rules",
        type=Path,
        default=Path(_default_capa_rules()),
        help=f"capa rules dir (default: $CLEW_CAPA_RULES or {DEFAULT_CAPA_RULES})",
    )
    s.add_argument(
        "--capa-sigs",
        type=Path,
        default=Path(_default_capa_sigs()),
        help=f"capa signatures dir (default: $CLEW_CAPA_SIGS or {DEFAULT_CAPA_SIGS})",
    )
    s.add_argument("--floss-sigs", type=Path, default=None)
    s.add_argument("--capa-bin", default="capa")
    s.add_argument(
        "--no-license-checkout",
        action="store_true",
        help="assume a license is already checked out for this process",
    )
    s.add_argument(
        "--exclude-unresolved",
        action="store_true",
        help="omit located-but-unresolved call sites (the Channel 3 work list)",
    )
    s.add_argument(
        "--verbose-floss",
        action="store_true",
        help="don't suppress vivisect/FLOSS emulator logging (debugging FLOSS)",
    )
    s.add_argument(
        "--floss-cache",
        type=Path,
        default=None,
        help=f"FLOSS result cache directory (default: {DEFAULT_FLOSS_CACHE}/)",
    )
    s.add_argument(
        "--no-cache",
        action="store_true",
        help="disable the FLOSS result cache (always re-run FLOSS, don't read/write)",
    )
    s.add_argument(
        "--refresh-floss-cache",
        action="store_true",
        help="force a FLOSS re-run and overwrite the cache entry (use after a FLOSS/sigs change)",
    )
    s.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the record JSON here (default: stdout)",
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
        help="write the enriched record JSON here (default: stdout)",
    )
    s.set_defaults(func=_cmd_correlate)


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

    text = json.dumps(record, indent=2)
    if args.output:
        args.output.write_text(text)
        resolved = sum(
            1
            for c in record["candidates"]
            if any(v.get("value") is not None for v in c["candidate_values"])
        )
        print(
            f"wrote {args.output}: {len(record['candidates'])} candidates "
            f"({resolved} with values), "
            f"derivation_status={record['derivation_status']}, "
            f"{len(record['capa_techniques'])} capa techniques"
        )
    else:
        print(text)
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

    text = json.dumps(enriched, indent=2)
    if args.output:
        args.output.write_text(text)
        with_cmps = [c for c in enriched["candidates"] if c.get("comparison_candidates")]
        total_cmps = sum(len(c["comparison_candidates"]) for c in with_cmps)
        print(
            f"wrote {args.output}: {len(enriched['candidates'])} candidates, "
            f"{len(with_cmps)} with comparison_candidates ({total_cmps} total comparisons)"
        )
    else:
        print(text)
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

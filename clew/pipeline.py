"""clew static pipeline: run the static channels and assemble one record.

Runs Channel 0/1 (capa), Channel 1 (FLOSS), and Channel 2 (Binary Ninja:
Unit 3 call-site enumeration + Unit 4 dataflow bridge) over a single sample and
assembles the sample-level *intermediate* clew record.

Single analysis: the BN view is opened and analysed ONCE, inside one Enterprise
license checkout, and both Unit 3 (`enumerate_with_view`) and Unit 4
(`bridge_with_view`) run on it -- not two `update_analysis_and_wait` passes.

Boundary: this produces an INTERMEDIATE record. The sample-level fields that are
statically available -- `sample_sha256`, `capa_techniques`, `derivation_status`
-- are filled here. The candidates are the bridge's `to_partial_candidates()`
output: call site + argument dataflow + values, with the three derivation-owned
fields (`evasion_tier`, `iteration_number`, `coordination_constraint`) and the
Channel-4 comparison operands deliberately absent. The derivation stage (Person
B) completes each candidate and Channel 4 adds comparison semantics. This is the
same boundary the oracle grader validated.

Degradation: capa and FLOSS are enrichment. If capa fails or times out the
record gets `derivation_status = "no_capa_signal"` and no techniques (the same
operational bucket as zero anti-analysis rules). If FLOSS fails the bridge runs
with an empty index (BN-only static strings). Binary Ninja is the core channel:
its errors propagate.

Heavy dependencies (capa / floss / tiers / binaryninja) are imported lazily
inside the driver, so `assemble_record` and its tests need none of them.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

CLEW_VERSION = "0.3.0"

# Site defaults for capa's rules/signatures. These are the pinned locations on
# the AFIT cluster: capa-rules is the checkout at CAPA_PINS["capa_rules_tag"]
# (be59710a), and the sigs come from the capa source tree (capa 9.4.0 ships them
# there, not in the installed package). Kept here -- a deployment/orchestration
# concern -- rather than in capa.py's CAPA_PINS, which records version identity
# (a git hash) not filesystem layout. Overridable per-machine via the CLEW_CAPA_*
# env vars, and per-run via --capa-rules / --capa-sigs.
DEFAULT_CAPA_RULES = "/home/shared/clew-env/capa-rules"
DEFAULT_CAPA_SIGS = "/home/shared/clew-env/capa-src/sigs"


def _default_capa_rules() -> str:
    return os.environ.get("CLEW_CAPA_RULES", DEFAULT_CAPA_RULES)


def _default_capa_sigs() -> str:
    return os.environ.get("CLEW_CAPA_SIGS", DEFAULT_CAPA_SIGS)


# --- pure record assembly (no heavy imports; fully offline-testable) ---------


def assemble_record(
    *,
    sample_sha256: str,
    sample_path: Optional[str],
    capa_techniques: list,
    derivation_status: Optional[str],
    bridge_candidates: list,
    clew_version: str = CLEW_VERSION,
    total_iterations: int = 1,
) -> dict:
    """Wrap the static outputs in the sample-level clew record envelope.

    The top-level fields are final; each candidate is the bridge's intermediate
    shape (missing the three derivation-owned fields). The record validates
    against `schema/clew_record.schema.json` only after the derivation stage
    completes each candidate.
    """
    return {
        "sample_sha256": sample_sha256,
        "sample_path": sample_path,
        "clew_version": clew_version,
        "capa_techniques": list(capa_techniques),
        "derivation_status": derivation_status,
        "total_iterations": total_iterations,
        "candidates": list(bridge_candidates),
    }


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    h.update(Path(path).read_bytes())
    return h.hexdigest()


# --- capa / tiers glue (lazy imports; runs wherever those modules exist) ------


def capa_techniques_and_status(capa_result) -> tuple:
    """(evasion technique names, derivation_status) from a CapaResult."""
    from clew import tiers
    from clew.channels.capa import filter_evasion_techniques

    rules_meta = (getattr(capa_result, "raw", None) or {}).get("rules", {})
    techniques = filter_evasion_techniques(capa_result.rule_names, rules_meta)
    return techniques, _derivation_status(capa_result, tiers)


def _derivation_status(capa_result, tiers) -> Optional[str]:
    """Call `tiers.classify` defensively across return shapes (tuple /
    dataclass / bare string).

    RECONCILE: confirm classify's exact signature/return on the first live run.
    The tiers docstring says classify returns the categorical alongside the list
    of unmapped rules; this pulls just the categorical, whichever shape it comes
    in. Only `derivation_status` has a schema home -- the unmapped list is a
    backlog-sizing aid the record does not carry.
    """
    result = tiers.classify(capa_result.rule_names)
    if isinstance(result, tuple):
        return result[0] if result else None
    for attr in ("derivation_status", "status", "value"):
        if hasattr(result, attr):
            return getattr(result, attr)
    return result if isinstance(result, str) else None


# --- the live driver (lazy imports of every heavy dependency) ----------------


def run_static_pipeline(
    sample: str | Path,
    *,
    capa_rules_path: Path,
    capa_sigs_path: Path,
    floss_sigs_path: Optional[Path] = None,
    capa_bin: str = "capa",
    include_unresolved: bool = True,
    run_license_checkout: bool = True,
    quiet_floss: bool = True,
    floss_cache_dir: Optional[Path] = None,
    use_floss_cache: bool = True,
    refresh_floss_cache: bool = False,
) -> dict:
    """Run the static channels over `sample`; return the intermediate record.

    capa and FLOSS run as ordinary subprocess/library calls; only the Binary
    Ninja stage takes the license checkout, and it opens + analyses the view
    exactly once for both Unit 3 and Unit 4.

    FLOSS output is cached (by default under `.floss_cache/`, keyed on
    sample+FLOSS-version+min_length+sigs+flags): a matching entry is reused
    verbatim (fast, silent, deterministic), a disagreeing entry raises
    FlossCacheStale rather than silently using stale strings. `use_floss_cache`
    disables it; `refresh_floss_cache` forces a re-run and overwrite.
    """
    sample = Path(sample)
    if not sample.exists():
        raise FileNotFoundError(f"sample not found: {sample}")
    sha = sha256_file(sample)
    cache_dir = Path(floss_cache_dir) if floss_cache_dir else Path(DEFAULT_FLOSS_CACHE)

    capa_techniques, derivation_status = _run_capa_stage(
        sample, capa_rules_path, capa_sigs_path, capa_bin
    )
    floss_index = _run_floss_stage(
        sample,
        sha,
        floss_sigs_path,
        cache_dir=cache_dir,
        use_cache=use_floss_cache,
        refresh=refresh_floss_cache,
        quiet=quiet_floss,
    )
    candidates = _run_bn_stage(sample, sha, floss_index, include_unresolved, run_license_checkout)

    return assemble_record(
        sample_sha256=sha,
        sample_path=str(sample),
        capa_techniques=capa_techniques,
        derivation_status=derivation_status,
        bridge_candidates=candidates,
    )


def _run_capa_stage(sample, rules_path, sigs_path, capa_bin):
    from clew.channels import capa

    try:
        result = capa.run_capa(
            sample, rules_path=rules_path, sigs_path=sigs_path, capa_bin=capa_bin
        )
    except capa.CapaError:
        return [], "no_capa_signal"  # capa error/timeout == no usable signal
    return capa_techniques_and_status(result)


# vivisect/FLOSS emit their emulator griping (parseOpcode errors, prehook
# failures, PC-restore warnings, incomplete-CFG warnings) via the standard
# logging tree. On adversarial code like al-khaser this is hundreds of lines of
# expected noise -- the emulator choking on junk-byte anti-disassembly, which
# FLOSS logs and works around. Raising these top-level trees suppresses their
# sub-loggers (envi.codeflow, vivisect.impemu.*, viv_utils.emulator_drivers,
# ...) by inheritance. `viv_utils` is FLARE's emulation-driver wrapper that
# FLOSS drives; it is a SEPARATE package from vivisect and needs naming
# explicitly (it emits the "hook failed to restore PC" / "incomplete control
# flow graph" warnings).
_FLOSS_NOISY_LOGGERS = ("floss", "vivisect", "viv_utils", "envi", "viv", "vtrace", "Elf", "PE")


@contextlib.contextmanager
def _quiet_floss_logging(level=logging.ERROR):
    """Temporarily raise vivisect/FLOSS loggers to `level`, restoring them after.

    Scoped and reversible: only the named trees are touched, so capa/BN/clew
    logging is unaffected (unlike logging.disable, which is a global kill
    switch). Default ERROR keeps genuine FLOSS errors visible while dropping the
    INFO/WARNING emulator chatter. Set level=logging.NOTSET-adjacent (e.g. via a
    verbose flag) to see everything again.
    """
    saved = {name: logging.getLogger(name).level for name in _FLOSS_NOISY_LOGGERS}
    for name in _FLOSS_NOISY_LOGGERS:
        logging.getLogger(name).setLevel(level)
    try:
        yield
    finally:
        for name, lvl in saved.items():
            logging.getLogger(name).setLevel(lvl)


class FlossCacheStale(Exception):
    """A FLOSS cache entry exists for this sample but its key disagrees with the
    current run (FLOSS version, min_length, sigs, or flags changed). Raised so a
    stale artifact can never silently poison downstream candidates; the operator
    must opt into regeneration with --refresh-floss-cache (or bypass caching with
    --no-cache). Deliberately NOT a floss.FlossError, so the FLOSS-degradation
    path can't swallow it into an empty index."""


FLOSS_MIN_LENGTH = 4  # the pipeline uses run_floss's default; in the key
DEFAULT_FLOSS_CACHE = ".floss_cache"


def _floss_version() -> str:
    """Installed flare-floss version (part of the cache key: a FLOSS upgrade can
    change emulation output, so it must invalidate)."""
    try:
        from importlib.metadata import version

        return version("flare-floss")
    except Exception:
        pass
    try:
        import floss

        return str(getattr(floss, "__version__", "unknown"))
    except Exception:
        return "unknown"


def _sigs_identity(sigs_path) -> str:
    """Content-shape fingerprint of the signatures used.

    Hashes sorted (relative-path, size) pairs -- NOT mtime (a git checkout or
    `cp -p` changes mtime without changing bytes, and must not trigger a false
    stale), and NOT the path string (same path, edited files must trigger one).
    `None` means FLOSS's bundled sigs, which are version-locked to the FLOSS
    version already in the key, so a stable sentinel is sufficient and correct.
    """
    if sigs_path is None:
        return "bundled"
    p = Path(sigs_path)
    entries = []
    if p.is_dir():
        entries = [
            (str(f.relative_to(p)), f.stat().st_size) for f in sorted(p.rglob("*")) if f.is_file()
        ]
    elif p.is_file():
        entries = [(p.name, p.stat().st_size)]
    h = hashlib.sha256()
    for rel, size in entries:
        h.update(f"{rel}:{size}\n".encode())
    return h.hexdigest()[:16]


def _floss_cache_key(sha, sigs_path) -> dict:
    return {
        "sample_sha256": sha,
        "floss_version": _floss_version(),
        "min_length": FLOSS_MIN_LENGTH,
        "sigs_identity": _sigs_identity(sigs_path),
        "flags": {"static": True, "stack": True, "tight": True, "decoded": True},
    }


def _key_diff(have: dict, want: dict) -> str:
    diffs = [
        f"{k}: cached={have.get(k)!r} current={want.get(k)!r}"
        for k in sorted(set(have) | set(want))
        if have.get(k) != want.get(k)
    ]
    return "; ".join(diffs) or "unknown difference"


def _floss_cache_read(sha, sigs_path, cache_dir):
    """Return a FlossResult on a valid hit, None on a miss (no entry).

    Raise FlossCacheStale if an entry exists but its stored key disagrees. The
    stale check runs BEFORE importing FLOSS, so it's exercised offline.
    """
    cache_dir = Path(cache_dir)
    data_path = cache_dir / f"{sha}.floss.json"
    key_path = cache_dir / f"{sha}.floss.key.json"
    if not data_path.exists() or not key_path.exists():
        return None  # miss
    want = _floss_cache_key(sha, sigs_path)
    try:
        have = json.loads(key_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise FlossCacheStale(
            f"FLOSS cache key for {sha[:12]} is unreadable: {e}; re-run with --refresh-floss-cache"
        ) from e
    if have != want:
        raise FlossCacheStale(
            f"FLOSS cache for {sha[:12]} is stale ({_key_diff(have, want)}). "
            f"Re-run with --refresh-floss-cache to regenerate, or --no-cache to bypass."
        )
    from clew.channels import floss  # only needed to actually load

    return floss.load_floss_results(data_path)


def _floss_cache_write(result, sha, sigs_path, cache_dir) -> None:
    """Persist FLOSS output as native `floss -j` JSON plus a key sidecar.
    Best-effort: a write failure warns but does not fail the pipeline."""
    from floss.render.json import render as render_floss_json

    cache_dir = Path(cache_dir)
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / f"{sha}.floss.json").write_text(render_floss_json(result.raw))
        (cache_dir / f"{sha}.floss.key.json").write_text(
            json.dumps(_floss_cache_key(sha, sigs_path), indent=2, sort_keys=True)
        )
    except OSError as e:
        logging.getLogger("clew.pipeline").warning("could not write FLOSS cache: %s", e)


def _run_floss_stage(
    sample,
    sha,
    floss_sigs_path,
    *,
    cache_dir=DEFAULT_FLOSS_CACHE,
    use_cache=True,
    refresh=False,
    quiet=True,
):
    from clew.analysis.dataflow import FlossIndex
    from clew.channels import floss

    # cache lookup (a stale entry raises FlossCacheStale -> halts the run by design)
    if use_cache and not refresh:
        cached = _floss_cache_read(sha, floss_sigs_path, cache_dir)
        if cached is not None:
            print(f"FLOSS: cache hit ({sha[:12]})", file=sys.stderr)
            return FlossIndex.from_floss_result(cached)

    # miss / refresh / disabled: run FLOSS (the slow, noisy, emulated path)
    note = (
        "refreshing cache"
        if (use_cache and refresh)
        else ("cache miss -- running" if use_cache else "cache disabled -- running")
    )
    print(f"FLOSS: {note}", file=sys.stderr)
    cm = _quiet_floss_logging() if quiet else contextlib.nullcontext()
    try:
        with cm:
            result = floss.run_floss(sample, sigs_path=floss_sigs_path)
    except floss.FlossError:
        return FlossIndex.empty()  # FLOSS is enrichment; BN-only static strings

    if use_cache:
        _floss_cache_write(result, sha, floss_sigs_path, cache_dir)
    return FlossIndex.from_floss_result(result)


def _run_bn_stage(sample, sha, floss_index, include_unresolved, run_license_checkout):
    import binaryninja

    from clew.analysis.dataflow import BNDataflow, bridge_with_view
    from clew.channels.bn_callsites import BNError, enumerate_with_view

    def _work():
        bv = binaryninja.load(str(sample))
        if bv is None:
            raise BNError(f"BN returned no view for {sample}")
        bv.update_analysis_and_wait()
        cs = enumerate_with_view(bv, sample_path=str(sample), sample_sha256=sha)
        bridged = bridge_with_view(bv, cs, floss_index)
        df = BNDataflow(
            sample_path=str(sample),
            sample_sha256=sha,
            bn_core_version=binaryninja.core_version(),
            bridged=bridged,
        )
        return df.to_partial_candidates(include_unresolved=include_unresolved)

    if run_license_checkout:
        from binaryninja.enterprise import LicenseCheckout

        with LicenseCheckout():
            return _work()
    return _work()


# --- CLI ---------------------------------------------------------------------


def main(argv=None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        description="Run the clew static pipeline over a sample and emit the "
        "intermediate clew record."
    )
    p.add_argument("sample")
    p.add_argument(
        "--capa-rules",
        type=Path,
        default=Path(_default_capa_rules()),
        help=f"capa rules dir (default: $CLEW_CAPA_RULES or {DEFAULT_CAPA_RULES})",
    )
    p.add_argument(
        "--capa-sigs",
        type=Path,
        default=Path(_default_capa_sigs()),
        help=f"capa signatures dir (default: $CLEW_CAPA_SIGS or {DEFAULT_CAPA_SIGS})",
    )
    p.add_argument("--floss-sigs", type=Path, default=None)
    p.add_argument("--capa-bin", default="capa")
    p.add_argument(
        "--no-license-checkout",
        action="store_true",
        help="assume a license is already checked out for this process",
    )
    p.add_argument(
        "--exclude-unresolved",
        action="store_true",
        help="omit located-but-unresolved call sites (the Channel 4 work list)",
    )
    p.add_argument(
        "--verbose-floss",
        action="store_true",
        help="don't suppress vivisect/FLOSS emulator logging (debugging FLOSS)",
    )
    p.add_argument(
        "--floss-cache",
        type=Path,
        default=None,
        help=f"FLOSS result cache directory (default: {DEFAULT_FLOSS_CACHE}/)",
    )
    p.add_argument(
        "--no-cache",
        action="store_true",
        help="disable the FLOSS result cache (always re-run FLOSS, don't read/write)",
    )
    p.add_argument(
        "--refresh-floss-cache",
        action="store_true",
        help="force a FLOSS re-run and overwrite the cache entry (use after a FLOSS/sigs change)",
    )
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the record JSON here (default: stdout)",
    )
    args = p.parse_args(argv)

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
        print(f"error: {e}", file=sys.stderr)
        return 2
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

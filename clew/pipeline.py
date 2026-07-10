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

import hashlib
import json
from pathlib import Path
from typing import Optional


CLEW_VERSION = "0.3.0"


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
    from clew.channels.capa import filter_evasion_techniques
    from clew import tiers

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
) -> dict:
    """Run the static channels over `sample`; return the intermediate record.

    capa and FLOSS run as ordinary subprocess/library calls; only the Binary
    Ninja stage takes the license checkout, and it opens + analyses the view
    exactly once for both Unit 3 and Unit 4.
    """
    sample = Path(sample)
    if not sample.exists():
        raise FileNotFoundError(f"sample not found: {sample}")
    sha = sha256_file(sample)

    capa_techniques, derivation_status = _run_capa_stage(
        sample, capa_rules_path, capa_sigs_path, capa_bin)
    floss_index = _run_floss_stage(sample, floss_sigs_path)
    candidates = _run_bn_stage(
        sample, sha, floss_index, include_unresolved, run_license_checkout)

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
        result = capa.run_capa(sample, rules_path=rules_path, sigs_path=sigs_path,
                               capa_bin=capa_bin)
    except capa.CapaError:
        return [], "no_capa_signal"   # capa error/timeout == no usable signal
    return capa_techniques_and_status(result)


def _run_floss_stage(sample, floss_sigs_path):
    from clew.analysis.dataflow import FlossIndex
    from clew.channels import floss
    try:
        result = floss.run_floss(sample, sigs_path=floss_sigs_path)
    except floss.FlossError:
        return FlossIndex.empty()     # FLOSS is enrichment; BN-only static strings
    return FlossIndex.from_floss_result(result)


def _run_bn_stage(sample, sha, floss_index, include_unresolved, run_license_checkout):
    import binaryninja
    from clew.channels.bn_callsites import enumerate_with_view, BNError
    from clew.analysis.dataflow import bridge_with_view, BNDataflow

    def _work():
        bv = binaryninja.load(str(sample))
        if bv is None:
            raise BNError(f"BN returned no view for {sample}")
        bv.update_analysis_and_wait()
        cs = enumerate_with_view(bv, sample_path=str(sample), sample_sha256=sha)
        bridged = bridge_with_view(bv, cs, floss_index)
        df = BNDataflow(sample_path=str(sample), sample_sha256=sha,
                        bn_core_version=binaryninja.core_version(), bridged=bridged)
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
                    "intermediate clew record.")
    p.add_argument("sample")
    p.add_argument("--capa-rules", required=True, type=Path)
    p.add_argument("--capa-sigs", required=True, type=Path)
    p.add_argument("--floss-sigs", type=Path, default=None)
    p.add_argument("--capa-bin", default="capa")
    p.add_argument("--no-license-checkout", action="store_true",
                   help="assume a license is already checked out for this process")
    p.add_argument("--exclude-unresolved", action="store_true",
                   help="omit located-but-unresolved call sites (the Channel 4 work list)")
    p.add_argument("-o", "--output", type=Path, default=None,
                   help="write the record JSON here (default: stdout)")
    args = p.parse_args(argv)

    record = run_static_pipeline(
        args.sample,
        capa_rules_path=args.capa_rules,
        capa_sigs_path=args.capa_sigs,
        floss_sigs_path=args.floss_sigs,
        capa_bin=args.capa_bin,
        include_unresolved=not args.exclude_unresolved,
        run_license_checkout=not args.no_license_checkout,
    )
    text = json.dumps(record, indent=2)
    if args.output:
        args.output.write_text(text)
        resolved = sum(1 for c in record["candidates"]
                       if any(v.get("value") is not None for v in c["candidate_values"]))
        print(f"wrote {args.output}: {len(record['candidates'])} candidates "
              f"({resolved} with values), "
              f"derivation_status={record['derivation_status']}, "
              f"{len(record['capa_techniques'])} capa techniques")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Stratified random sample selection from the VT Academic corpus.

Picks N samples from each of four archive dates, validates each is a
PE32 via libmagic, and writes paths to a manifest file.
"""

from __future__ import annotations

import argparse
import random
import subprocess
import sys
from pathlib import Path

CORPUS_ROOT = Path("/home/user/Documents/VirusTotal Academic Malware Samples")
ARCHIVE_DATES = [
    ("2017", "2017-10-20"),
    ("2017", "2017-11-20"),
    ("2020", "2020-05-06"),
    ("2021", "2021-11-03"),
]


def is_pe32(path: Path) -> bool:
    """Use libmagic via `file` to confirm PE32. Returns True for PE32 variants only."""
    try:
        proc = subprocess.run(
            ["file", "-b", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return "PE32" in proc.stdout and "PE32+" not in proc.stdout  # exclude 64-bit


def list_candidates(archive_dir: Path) -> list[Path]:
    """SHA-256-named binaries (no .json suffix) in the given Win32_EXE dir."""
    out = []
    for entry in archive_dir.iterdir():
        if entry.is_file() and not entry.name.endswith(".json"):
            # SHA-256 = 64 hex chars
            if len(entry.name) == 64 and all(c in "0123456789abcdef" for c in entry.name):
                out.append(entry)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--per-date", type=int, default=125, help="samples per archive date")
    ap.add_argument("--seed", type=int, default=42, help="RNG seed for reproducibility")
    ap.add_argument(
        "--output",
        type=Path,
        default=Path("results/channel0_at_scale/manifest.txt"),
    )
    ap.add_argument(
        "--validate-pe32",
        action="store_true",
        default=True,
        help="filter to PE32 32-bit only (default on)",
    )
    args = ap.parse_args()

    rng = random.Random(args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    chosen: list[Path] = []
    counts: dict[str, int] = {}

    for year, date in ARCHIVE_DATES:
        archive_dir = CORPUS_ROOT / year / date / "extracted" / "Win32_EXE"
        if not archive_dir.is_dir():
            print(f"WARN: missing {archive_dir}", file=sys.stderr)
            continue
        pool = list_candidates(archive_dir)
        rng.shuffle(pool)

        picked = []
        scanned = 0
        for candidate in pool:
            scanned += 1
            if not args.validate_pe32 or is_pe32(candidate):
                picked.append(candidate)
                if len(picked) >= args.per_date:
                    break
        counts[date] = len(picked)
        print(f"{date}: picked {len(picked)} / scanned {scanned} (target {args.per_date})")
        chosen.extend(picked)

    with args.output.open("w") as f:
        for p in chosen:
            f.write(f"{p}\n")
    print(f"\nWrote {len(chosen)} paths to {args.output}")
    print(f"Breakdown: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

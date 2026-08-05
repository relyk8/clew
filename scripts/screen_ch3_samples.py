#!/usr/bin/env python3
"""Rank corpus samples by how much of Channel 3's API set they import.

Channel 3 needs fixtures that both survive DynamoRIO *and* actually call the
environment-sensitive APIs. Clew's canonical fixture fails the first (al-khaser
yields no logs under DR at all) and the CAPE sample that does survive fails the
second (autoit3 touches five of the 88 in a two-minute run), so neither
demonstrates the channel.

Detonating to find out costs minutes per sample. The import table answers the
second question statically in milliseconds, so screen here and spend detonations
only on samples that could plausibly show something.

    python scripts/screen_ch3_samples.py --sample 4000 -o results/ch3_screen.json

What this can and cannot tell you:

- A high count means the sample *references* those APIs. It does not mean it
  calls them on the path a sandbox will take.
- A near-empty import table usually means packing, not innocence: the real
  imports get resolved at runtime. Those samples are reported with a `packed`
  hint rather than silently ranked last, because a packed sample that unpacks
  under DR is exactly where Channel 3 beats the static pass.
- Nothing here predicts whether DynamoRIO survives the sample. Only a detonation
  answers that.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import struct
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Machine-specific, so overridable. The default is this box's mount.
DEFAULT_CORPUS_ROOT = Path(
    os.environ.get("CLEW_CORPUS_ROOT", "/home/shared/virustotal")
)

# Below this many total imports, the import table is almost certainly a packer
# stub rather than the real program.
PACKED_IMPORT_THRESHOLD = 15

# The subset of TARGET_ENV_APIS a program has little reason to call *except* to
# characterise its environment. Ranking on all 88 buries the signal: CreateFileA,
# GetFileAttributesW, RegOpenKeyExA and FindFirstFileW appear in almost every
# Windows binary, so a high raw count mostly measures how big the program is.
# Screening the 3000-sample corpus slice on the full set produced three
# DR-surviving samples whose only observed calls were GetModuleHandleW resolving
# kernel32 -- ordinary dynamic linking, nothing environmental.
#
# These are the ones that answer "what am I running on": hardware and firmware
# probes, debugger queries, timing sources, display/network/disk enumeration, and
# process/window sweeps.
HIGH_SIGNAL_APIS = frozenset(
    {
        "CheckRemoteDebuggerPresent",
        "DeviceIoControl",
        "EnumDisplayDevicesW",
        "FindWindowA",
        "FindWindowExA",
        "FindWindowExW",
        "FindWindowW",
        "GetAdaptersAddresses",
        "GetAdaptersInfo",
        "GetCursorPos",
        "GetDiskFreeSpaceExA",
        "GetDiskFreeSpaceExW",
        "GetForegroundWindow",
        "GetKeyboardLayout",
        "GetNativeSystemInfo",
        "GetSystemFirmwareTable",
        "GetSystemInfo",
        "GetTickCount",
        "GetTickCount64",
        "GetVolumeInformationA",
        "GetVolumeInformationW",
        "GlobalMemoryStatusEx",
        "IsDebuggerPresent",
        "IsNativeVhdBoot",
        "IsProcessorFeaturePresent",
        "NtQueryDirectoryObject",
        "NtQueryInformationProcess",
        "NtQuerySystemInformation",
        "Process32First",
        "Process32FirstW",
        "Process32Next",
        "Process32NextW",
        "QueryPerformanceCounter",
        "SetupDiGetDeviceRegistryPropertyW",
        "WNetGetProviderNameA",
        "timeGetTime",
    }
)

IMAGE_FILE_MACHINE_I386 = 0x014C
PE32_MAGIC = 0x10B


def _quick_reject(path: Path) -> bool:
    """Cheap header check before paying for a full parse.

    True when the file is not a 32-bit x86 PE. pefile costs milliseconds per
    sample and the corpus has six figures of them, so most are rejected on ~64
    bytes read.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(0x40)
            if len(head) < 0x40 or head[:2] != b"MZ":
                return True
            pe_off = struct.unpack_from("<I", head, 0x3C)[0]
            fh.seek(pe_off)
            probe = fh.read(0x1A)
            if len(probe) < 0x1A or probe[:4] != b"PE\0\0":
                return True
            machine = struct.unpack_from("<H", probe, 4)[0]
            magic = struct.unpack_from("<H", probe, 24)[0]
            return machine != IMAGE_FILE_MACHINE_I386 or magic != PE32_MAGIC
    except OSError:
        return True


def screen_one(path_str: str) -> dict | None:
    """Imported target-API names for one sample, or None if not a PE32 x86."""
    import pefile

    path = Path(path_str)
    if _quick_reject(path):
        return None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except Exception:
        return None

    imported: set[str] = set()
    total = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports or []:
            total += 1
            if imp.name:
                imported.add(imp.name.decode("ascii", "replace"))
    pe.close()

    from clew.tiers import TARGET_ENV_APIS

    hits = sorted(imported & set(TARGET_ENV_APIS))
    high = sorted(imported & HIGH_SIGNAL_APIS)
    return {
        "path": path_str,
        "target_apis": hits,
        "target_api_count": len(hits),
        "high_signal_apis": high,
        "high_signal_count": len(high),
        "total_imports": total,
        "packed": total < PACKED_IMPORT_THRESHOLD,
    }


def iter_corpus(root: Path):
    """Every extracted Win32_EXE path under the corpus root."""
    for exe_dir in sorted(root.glob("*/*/extracted/Win32_EXE")):
        for entry in os.scandir(exe_dir):
            if entry.is_file():
                yield entry.path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus-root", type=Path, default=DEFAULT_CORPUS_ROOT)
    ap.add_argument(
        "--sample",
        type=int,
        default=4000,
        help="screen this many randomly-chosen files (0 = all; the corpus is ~157k)",
    )
    ap.add_argument("--seed", type=int, default=0, help="RNG seed, so a run is repeatable")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 4) - 2))
    ap.add_argument(
        "--min-apis",
        type=int,
        default=6,
        help="only report samples importing at least this many HIGH_SIGNAL_APIS "
        "(the environment-characterising subset, not all 88)",
    )
    ap.add_argument("-o", "--output", type=Path, default=None)
    args = ap.parse_args()

    if not args.corpus_root.is_dir():
        print(f"corpus root not found: {args.corpus_root}", file=sys.stderr)
        print("set CLEW_CORPUS_ROOT or pass --corpus-root", file=sys.stderr)
        return 1

    paths = list(iter_corpus(args.corpus_root))
    print(f"corpus: {len(paths)} files under {args.corpus_root}", file=sys.stderr)
    if args.sample and args.sample < len(paths):
        random.Random(args.seed).shuffle(paths)
        paths = paths[: args.sample]
        print(f"screening a random {len(paths)} (seed {args.seed})", file=sys.stderr)

    results = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for n, res in enumerate(pool.map(screen_one, paths, chunksize=64), 1):
            if res is not None:
                results.append(res)
            if n % 2000 == 0:
                print(f"  {n}/{len(paths)} screened", file=sys.stderr)

    pe32 = len(results)
    keep = [r for r in results if r["high_signal_count"] >= args.min_apis]
    keep.sort(key=lambda r: (-r["high_signal_count"], r["packed"], -r["target_api_count"]))

    print(
        f"\n{pe32} PE32/x86 of {len(paths)} screened; "
        f"{len(keep)} import >= {args.min_apis} high-signal APIs",
        file=sys.stderr,
    )
    for r in keep[:15]:
        flag = " [packed?]" if r["packed"] else ""
        print(
            f"  {r['high_signal_count']:>3} high-signal  {r['target_api_count']:>3} target  "
            f"{r['total_imports']:>4} imports{flag}  {Path(r['path']).name[:32]}",
            file=sys.stderr,
        )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(keep, indent=2))
        print(f"\nwrote {args.output} ({len(keep)} entries)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

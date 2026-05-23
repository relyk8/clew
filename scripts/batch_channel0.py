"""Batch-run Channel 0 against a manifest of PE32 paths.

Emits one JSONL record per sample with timing, status, and parsed rule info.
Resumable: re-running skips samples whose SHA-256 already appears in the
output file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import traceback
from pathlib import Path

# Ensure we can import clew without installing as editable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from clew.channels.capa import (
    run_capa,
    filter_evasion_techniques,
    CapaError,
    CapaNotFoundError,
    CapaRunError,
    CapaParseError,
)
from clew.tiers import classify


def sha256_of(path: Path) -> str:
    """Compute sha256 of file contents (used for benign control where filename != sha)."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def looks_like_sha256(name: str) -> bool:
    return len(name) == 64 and all(c in "0123456789abcdef" for c in name)


def archive_date_for(path: Path) -> str | None:
    """Walk path components for an archive-date directory name."""
    for part in path.parts:
        if part.startswith("20") and len(part) == 10 and part[4] == "-":
            return part
    return None


def load_completed_shas(output_path: Path) -> set[str]:
    """Read existing JSONL output, return set of sha256 strings already processed."""
    done: set[str] = set()
    if not output_path.exists():
        return done
    with output_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if "sha256" in rec:
                    done.add(rec["sha256"])
            except json.JSONDecodeError:
                continue
    return done


def process_one(
    sample_path: Path,
    *,
    rules_path: Path,
    sigs_path: Path,
    timeout: int,
) -> dict:
    """Run Channel 0 on one sample; return a JSONL-ready dict."""
    if looks_like_sha256(sample_path.name):
        sha = sample_path.name
    else:
        sha = sha256_of(sample_path)

    rec: dict = {
        "sha256": sha,
        "sample_path": str(sample_path),
        "filename": sample_path.name,
        "archive_date": archive_date_for(sample_path),
        "file_size_bytes": sample_path.stat().st_size if sample_path.exists() else None,
        "status": "ok",
        "error": None,
        "total_rules": 0,
        "evasion_rules": [],
        "num_evasion_rules": 0,
        "tier": None,
        "unmapped_rules": [],
        "started_at": None,
        "ended_at": None,
        "runtime_sec": None,
    }

    started = time.time()
    rec["started_at"] = started
    try:
        result = run_capa(
            sample_path,
            rules_path=rules_path,
            sigs_path=sigs_path,
            timeout=timeout,
        )
        rules_meta = result.raw.get("rules", {})
        evasion = filter_evasion_techniques(result.rule_names, rules_meta)
        tier, unmapped = classify(evasion)
        rec["total_rules"] = len(result.rule_names)
        rec["evasion_rules"] = sorted(evasion)
        rec["num_evasion_rules"] = len(evasion)
        rec["tier"] = tier
        rec["unmapped_rules"] = sorted(unmapped)
    except CapaNotFoundError as e:
        rec["status"] = "capa_not_found"
        rec["error"] = str(e)
    except CapaRunError as e:
        rec["status"] = "capa_error"
        rec["error"] = str(e)[:500]
    except CapaParseError as e:
        rec["status"] = "parse_error"
        rec["error"] = str(e)[:500]
    except CapaError as e:
        rec["status"] = "capa_error"
        rec["error"] = str(e)[:500]
    except Exception as e:
        # subprocess.TimeoutExpired surfaces here in some capa wrappers
        msg = str(e)
        if "timeout" in msg.lower() or "TimeoutExpired" in type(e).__name__:
            rec["status"] = "timeout"
        else:
            rec["status"] = "unexpected_error"
        rec["error"] = f"{type(e).__name__}: {msg[:500]}"
    finally:
        ended = time.time()
        rec["ended_at"] = ended
        rec["runtime_sec"] = round(ended - started, 3)
    return rec


def iter_targets(manifest: Path | None, directory: Path | None) -> list[Path]:
    """Resolve the source-of-paths argument to a list of Paths."""
    if manifest is not None:
        return [Path(line.strip()) for line in manifest.read_text().splitlines() if line.strip()]
    if directory is not None:
        out = []
        for entry in sorted(directory.iterdir()):
            if entry.is_file() and entry.suffix.lower() in {".exe", ".dll", ""}:
                out.append(entry)
        return out
    raise ValueError("must provide --manifest or --directory")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument("--manifest", type=Path, help="text file with one path per line")
    source.add_argument("--directory", type=Path, help="dir of binaries (for benign control)")
    ap.add_argument("--output", type=Path, required=True, help="JSONL output (append mode)")
    ap.add_argument("--rules-path", type=Path, required=True)
    ap.add_argument("--sigs-path", type=Path, required=True)
    ap.add_argument("--timeout", type=int, default=120, help="per-sample timeout in seconds")
    ap.add_argument("--limit", type=int, default=None, help="cap total samples (debug)")
    ap.add_argument("--no-resume", action="store_true", help="reprocess samples already in output")
    args = ap.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)

    targets = iter_targets(args.manifest, args.directory)
    if args.limit:
        targets = targets[: args.limit]

    if args.no_resume:
        done: set[str] = set()
    else:
        done = load_completed_shas(args.output)

    todo: list[Path] = []
    for t in targets:
        if looks_like_sha256(t.name) and t.name in done:
            continue
        if not looks_like_sha256(t.name):
            # benign control case; check by hashing
            try:
                if sha256_of(t) in done:
                    continue
            except OSError:
                pass
        todo.append(t)

    print(f"Total targets: {len(targets)}; already done: {len(done)}; to process: {len(todo)}",
          flush=True)

    run_started = time.time()
    n_ok = n_timeout = n_err = 0

    # Open in append mode (resumable)
    with args.output.open("a") as f:
        for i, sample in enumerate(todo, 1):
            rec = process_one(
                sample,
                rules_path=args.rules_path,
                sigs_path=args.sigs_path,
                timeout=args.timeout,
            )
            f.write(json.dumps(rec) + "\n")
            f.flush()
            os.fsync(f.fileno())  # crash-safe per-record

            status = rec["status"]
            if status == "ok":
                n_ok += 1
            elif status == "timeout":
                n_timeout += 1
            else:
                n_err += 1

            # Lightweight progress every 10 samples
            if i % 10 == 0 or i == len(todo):
                elapsed = time.time() - run_started
                rate = i / elapsed if elapsed else 0
                eta_sec = (len(todo) - i) / rate if rate else 0
                print(
                    f"[{i}/{len(todo)}] ok={n_ok} timeout={n_timeout} err={n_err}  "
                    f"elapsed={elapsed:.0f}s  rate={rate:.2f}/s  ETA={eta_sec:.0f}s",
                    flush=True,
                )

    total_elapsed = time.time() - run_started
    print(f"\nDone. Processed {len(todo)} in {total_elapsed:.1f}s "
          f"(ok={n_ok}, timeout={n_timeout}, error={n_err})", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted. Partial results preserved.", file=sys.stderr)
        sys.exit(130)
    except Exception:
        traceback.print_exc()
        sys.exit(1)

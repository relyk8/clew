"""Analyze Channel 0 batch results and write a markdown report + PNG charts.

Inputs: malware_results.jsonl, benign_results.jsonl
Outputs: docs/channel0_at_scale.md, results/channel0_at_scale/*.png, stats.csv
"""
from __future__ import annotations

import argparse
import collections
import json
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")  # headless
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from clew.tiers import classify  # noqa: E402


DERIVATION_STATUS_ORDER = [
    "fully_derivable",
    "partially_derivable",
    "not_derivable",
    "no_capa_signal",
]


@dataclass
class Stats:
    n_total: int
    n_ok: int
    n_timeout: int
    n_capa_error: int
    n_parse_error: int
    n_other_error: int
    runtimes_ok: list[float]
    evasion_counts: list[int]
    rule_freq: collections.Counter
    derivation_counts: collections.Counter
    unmapped_rule_counts: list[int]
    archive_counts: collections.Counter

    @property
    def total_runtime_sec(self) -> float:
        return sum(self.runtimes_ok)

    @property
    def runtime_p50(self) -> float:
        return statistics.median(self.runtimes_ok) if self.runtimes_ok else 0.0

    @property
    def runtime_p95(self) -> float:
        if not self.runtimes_ok:
            return 0.0
        s = sorted(self.runtimes_ok)
        return s[int(0.95 * (len(s) - 1))]

    @property
    def runtime_mean(self) -> float:
        return statistics.mean(self.runtimes_ok) if self.runtimes_ok else 0.0


def load_records(path: Path) -> list[dict]:
    records = []
    if not path.exists():
        return records
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def derivation_status_for(rec: dict) -> str:
    """Read derivation_status from record, or recompute from evasion_rules.

    Records produced by the pre-rename batch_channel0.py have a `tier` field
    with values tier_1..tier_4. Records produced by the post-rename batch
    have a `derivation_status` field with the new values. Either way, the
    canonical source of truth is `evasion_rules` — we recompute from that to
    avoid trusting the cached classification.
    """
    evasion = rec.get("evasion_rules") or []
    status, _unmapped = classify(evasion)
    return status


def compute_stats(records: list[dict]) -> Stats:
    rule_freq: collections.Counter = collections.Counter()
    derivation_counts: collections.Counter = collections.Counter()
    archive_counts: collections.Counter = collections.Counter()
    runtimes_ok: list[float] = []
    evasion_counts: list[int] = []
    unmapped_rule_counts: list[int] = []
    n_ok = n_timeout = n_capa_error = n_parse_error = n_other_error = 0

    for r in records:
        status = r.get("status")
        archive_counts[r.get("archive_date") or "unknown"] += 1
        if status == "ok":
            n_ok += 1
            rt = r.get("runtime_sec")
            if isinstance(rt, (int, float)):
                runtimes_ok.append(float(rt))
            evasion = r.get("evasion_rules") or []
            evasion_counts.append(len(evasion))
            for rule in evasion:
                rule_freq[rule] += 1
            ds = derivation_status_for(r)
            derivation_counts[ds] += 1
            unmapped = r.get("unmapped_rules") or []
            unmapped_rule_counts.append(len(unmapped))
        else:
            # Non-ok runs (timeout, capa_error, etc.) fold into no_capa_signal
            # in the categorical — capa returned no usable signal. The status
            # tallies below still track run-health separately.
            derivation_counts["no_capa_signal"] += 1
            if status == "timeout":
                n_timeout += 1
            elif status == "capa_error":
                n_capa_error += 1
            elif status == "parse_error":
                n_parse_error += 1
            else:
                n_other_error += 1

    return Stats(
        n_total=len(records),
        n_ok=n_ok,
        n_timeout=n_timeout,
        n_capa_error=n_capa_error,
        n_parse_error=n_parse_error,
        n_other_error=n_other_error,
        runtimes_ok=runtimes_ok,
        evasion_counts=evasion_counts,
        rule_freq=rule_freq,
        derivation_counts=derivation_counts,
        unmapped_rule_counts=unmapped_rule_counts,
        archive_counts=archive_counts,
    )


def evasion_bucket(n: int) -> str:
    if n == 0:
        return "0"
    if n == 1:
        return "1"
    if n == 2:
        return "2"
    if n == 3:
        return "3"
    if n == 4:
        return "4"
    if n <= 9:
        return "5-9"
    return "10+"


BUCKET_ORDER = ["0", "1", "2", "3", "4", "5-9", "10+"]


def render_evasion_histogram(stats: Stats, out: Path) -> None:
    buckets = collections.Counter(evasion_bucket(n) for n in stats.evasion_counts)
    xs = BUCKET_ORDER
    ys = [buckets.get(b, 0) for b in xs]
    plt.figure(figsize=(8, 5))
    bars = plt.bar(xs, ys, color="#4a7ab8")
    for bar, y in zip(bars, ys):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(ys) * 0.01,
                 str(y), ha="center", va="bottom", fontsize=9)
    plt.xlabel("Number of anti-analysis rules matched")
    plt.ylabel("Samples")
    plt.title(f"Channel 0 evasion-rule-count distribution (N={stats.n_ok} ok samples)")
    plt.tight_layout()
    plt.savefig(out, dpi=120)
    plt.close()


def render_derivation_distribution(stats: Stats, out: Path) -> None:
    labels = DERIVATION_STATUS_ORDER
    counts = [stats.derivation_counts.get(s, 0) for s in labels]
    plt.figure(figsize=(10, 5))
    # Color scheme:
    # green:   fully_derivable     (Clew acts today, no caveats)
    # yellow:  partially_derivable (Clew acts on the actionable portion)
    # orange:  not_derivable       (signal exists, can't act today)
    # blue-gray: no_capa_signal    (capa silent or didn't complete)
    colors = ["#2a9d8f", "#e9c46a", "#f4a261", "#577590"]
    bars = plt.bar(labels, counts, color=colors)
    max_c = max(counts) if counts else 1
    for bar, c in zip(bars, counts):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max_c * 0.01,
                 str(c), ha="center", va="bottom", fontsize=9)
    plt.xlabel("derivation_status (sample-level, Channel 0)")
    plt.ylabel("Samples")
    plt.title(f"Derivation-status distribution across malware corpus (N={stats.n_total})")
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    plt.savefig(out, dpi=120)
    plt.close()


def render_rule_frequency(stats: Stats, out: Path, top_n: int = 15) -> None:
    top = stats.rule_freq.most_common(top_n)
    if not top:
        plt.figure(figsize=(10, 6))
        plt.text(0.5, 0.5, "No evasion rules matched on any sample",
                 ha="center", va="center")
        plt.savefig(out, dpi=120)
        plt.close()
        return
    names = [name for name, _ in top][::-1]
    counts = [c for _, c in top][::-1]
    plt.figure(figsize=(10, max(5, 0.4 * len(names))))
    plt.barh(names, counts, color="#264653")
    plt.xlabel(f"# of samples (out of {stats.n_ok} ok)")
    plt.title(f"Top {len(top)} anti-analysis rules surfaced by Channel 0")
    plt.tight_layout()
    plt.savefig(out, dpi=120)
    plt.close()


def render_runtime_distribution(stats: Stats, out: Path) -> None:
    if not stats.runtimes_ok:
        plt.figure(figsize=(8, 5))
        plt.text(0.5, 0.5, "No runtime data", ha="center", va="center")
        plt.savefig(out, dpi=120)
        plt.close()
        return
    plt.figure(figsize=(8, 5))
    plt.hist(stats.runtimes_ok, bins=40, color="#6a994e", edgecolor="black", alpha=0.85)
    plt.axvline(stats.runtime_p50, color="orange", linestyle="--",
                label=f"P50 = {stats.runtime_p50:.1f}s")
    plt.axvline(stats.runtime_p95, color="red", linestyle="--",
                label=f"P95 = {stats.runtime_p95:.1f}s")
    plt.xlabel("Per-sample runtime (seconds)")
    plt.ylabel("Samples")
    plt.title(f"Channel 0 runtime distribution (N={len(stats.runtimes_ok)} ok)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out, dpi=120)
    plt.close()


def render_benign_vs_malware(malware: Stats, benign: Stats, out: Path) -> None:
    # 2 grouped bars: % with >=1 evasion, mean evasion count, P50 runtime
    metrics = ["% with >=1 evasion", "Mean evasion count", "P50 runtime (s)"]

    def stat_values(s: Stats) -> list[float]:
        if s.n_ok == 0:
            return [0, 0, 0]
        pct_evasive = 100.0 * sum(1 for n in s.evasion_counts if n >= 1) / s.n_ok
        mean_evasion = statistics.mean(s.evasion_counts) if s.evasion_counts else 0
        return [pct_evasive, mean_evasion, s.runtime_p50]

    m_vals = stat_values(malware)
    b_vals = stat_values(benign)

    import numpy as np
    x = np.arange(len(metrics))
    width = 0.35
    plt.figure(figsize=(9, 5))
    plt.bar(x - width / 2, m_vals, width, label=f"Malware (N={malware.n_ok})", color="#bc4749")
    plt.bar(x + width / 2, b_vals, width, label=f"Benign (N={benign.n_ok})", color="#386641")
    plt.xticks(x, metrics)
    plt.title("Specificity reference: malware vs benign on Channel 0")
    plt.legend()
    for i, (mv, bv) in enumerate(zip(m_vals, b_vals)):
        plt.text(i - width / 2, mv, f"{mv:.1f}", ha="center", va="bottom", fontsize=9)
        plt.text(i + width / 2, bv, f"{bv:.1f}", ha="center", va="bottom", fontsize=9)
    plt.tight_layout()
    plt.savefig(out, dpi=120)
    plt.close()


def load_vt_tags(sample_path: Path) -> list[str]:
    """Pull AV-engine detection labels and tags from the companion VT JSON."""
    vt_json = sample_path.with_suffix(sample_path.suffix + ".json") \
        if sample_path.suffix else sample_path.parent / (sample_path.name + ".json")
    if not vt_json.exists():
        return []
    try:
        with vt_json.open() as f:
            data = json.load(f)
    except Exception:
        return []
    # VT report shape varies; pull a few common fields conservatively
    tags: set[str] = set()
    if isinstance(data, dict):
        for k in ("tags", "type_tags", "popular_threat_classification"):
            v = data.get(k)
            if isinstance(v, list):
                tags.update(str(x) for x in v)
            elif isinstance(v, str):
                tags.add(v)
            elif isinstance(v, dict):
                sn = v.get("suggested_threat_label")
                if sn:
                    tags.add(str(sn))
                cats = v.get("popular_threat_category")
                if isinstance(cats, list):
                    for c in cats:
                        if isinstance(c, dict) and c.get("value"):
                            tags.add(c["value"])
        scans = data.get("scans")
        if isinstance(scans, dict):
            for engine, info in list(scans.items())[:8]:
                if isinstance(info, dict):
                    result = info.get("result")
                    if isinstance(result, str) and result:
                        tags.add(f"{engine}: {result[:60]}")
    return sorted(tags)[:20]


def pick_spotlights(records: list[dict]) -> tuple[dict | None, dict | None]:
    ok = [r for r in records if r.get("status") == "ok"]
    if not ok:
        return None, None
    rich = max(ok, key=lambda r: len(r.get("evasion_rules") or []))
    empty_candidates = [r for r in ok if len(r.get("evasion_rules") or []) == 0]
    empty = empty_candidates[0] if empty_candidates else min(ok, key=lambda r: len(r.get("evasion_rules") or []))
    return rich, empty


def write_csv(stats: Stats, out: Path) -> None:
    rows = []
    rows.append({"metric": "total_records", "value": stats.n_total})
    rows.append({"metric": "n_ok", "value": stats.n_ok})
    rows.append({"metric": "n_timeout", "value": stats.n_timeout})
    rows.append({"metric": "n_capa_error", "value": stats.n_capa_error})
    rows.append({"metric": "n_parse_error", "value": stats.n_parse_error})
    rows.append({"metric": "n_other_error", "value": stats.n_other_error})
    rows.append({"metric": "total_runtime_ok_sec", "value": round(stats.total_runtime_sec, 2)})
    rows.append({"metric": "runtime_p50_sec", "value": round(stats.runtime_p50, 2)})
    rows.append({"metric": "runtime_p95_sec", "value": round(stats.runtime_p95, 2)})
    rows.append({"metric": "runtime_mean_sec", "value": round(stats.runtime_mean, 2)})
    if stats.runtimes_ok:
        rows.append({"metric": "runtime_max_sec", "value": round(max(stats.runtimes_ok), 2)})
        rows.append({"metric": "runtime_min_sec", "value": round(min(stats.runtimes_ok), 2)})
    for ds in DERIVATION_STATUS_ORDER:
        rows.append({"metric": f"derivation_{ds}_count", "value": stats.derivation_counts.get(ds, 0)})
    rows.append({"metric": "derivation_partition_total", "value": sum(stats.derivation_counts.values())})
    if stats.unmapped_rule_counts:
        rows.append({
            "metric": "samples_with_unmapped_rules",
            "value": sum(1 for n in stats.unmapped_rule_counts if n > 0),
        })
        rows.append({
            "metric": "total_unmapped_rule_hits",
            "value": sum(stats.unmapped_rule_counts),
        })
    pd.DataFrame(rows).to_csv(out, index=False)


def write_report(
    *,
    malware: Stats,
    benign: Stats,
    rich_sample: dict | None,
    empty_sample: dict | None,
    out: Path,
    chart_dir_rel: str,
) -> None:
    lines: list[str] = []
    w = lines.append

    w("# Channel 0 at scale — 500-sample corpus characterization\n")
    w(f"_Generated by `scripts/analyze_channel0.py`._\n")

    w("## 1. Methodology\n")
    w(f"- **Corpus**: VirusTotal Academic PE32 samples across four archive dates (2017-10-20, 2017-11-20, 2020-05-06, 2021-11-03).")
    w(f"- **Sampling**: stratified random — `--per-date 125`, seed `42`, validated as 32-bit PE32 via libmagic.")
    w(f"- **N (malware)**: {malware.n_total} processed records.")
    w(f"- **Benign control**: {benign.n_total} binaries from `~/CAPEv2/analyzer/windows/` (signed Microsoft utilities, CAPE analysis tools).")
    w(f"- **Per-sample timeout**: 120s.")
    w(f"- **Versions pinned**: flare-capa 9.4.0, capa-rules @ `be59710a`, capa sigs @ `46188228`. (Pin drift will change matches.)")
    w(f"- **Framing**: this report characterizes **what Channel 0 (capa-wrapper) sees**, not evasion ground truth. Specificity is referenced against the benign control set.")
    w("")

    w("## 2. Execution overhead\n")
    w(f"| metric | malware | benign |")
    w(f"|---|---:|---:|")
    w(f"| samples processed | {malware.n_total} | {benign.n_total} |")
    w(f"| ok | {malware.n_ok} | {benign.n_ok} |")
    w(f"| timeout | {malware.n_timeout} | {benign.n_timeout} |")
    w(f"| capa_error | {malware.n_capa_error} | {benign.n_capa_error} |")
    w(f"| parse_error | {malware.n_parse_error} | {benign.n_parse_error} |")
    w(f"| other_error | {malware.n_other_error} | {benign.n_other_error} |")
    w(f"| total ok runtime (s) | {malware.total_runtime_sec:.1f} | {benign.total_runtime_sec:.1f} |")
    w(f"| P50 runtime (s) | {malware.runtime_p50:.2f} | {benign.runtime_p50:.2f} |")
    w(f"| P95 runtime (s) | {malware.runtime_p95:.2f} | {benign.runtime_p95:.2f} |")
    w(f"| mean runtime (s) | {malware.runtime_mean:.2f} | {benign.runtime_mean:.2f} |")
    if malware.runtimes_ok:
        w(f"| max runtime (s) | {max(malware.runtimes_ok):.2f} | {max(benign.runtimes_ok or [0]):.2f} |")
    w("")
    # Extrapolation
    if malware.runtime_mean > 0:
        full_corpus = 78515
        est_seconds = full_corpus * malware.runtime_mean
        est_hours = est_seconds / 3600.0
        w(f"**Extrapolation:** at the observed malware mean of {malware.runtime_mean:.2f}s/sample, "
          f"processing the full {full_corpus:,}-sample VT corpus would take "
          f"~{est_hours:.1f} hr single-threaded (~{est_hours/4:.1f} hr at 4-way parallelism).")
    w("")
    w(f"![runtime distribution]({chart_dir_rel}/runtime_distribution.png)\n")

    w("## 3. What Channel 0 sees at scale\n")
    bucket_counts = collections.Counter(evasion_bucket(n) for n in malware.evasion_counts)
    w("Evasion-rule-count distribution across `ok` samples:\n")
    w("| # of anti-analysis rules matched | samples | % of ok |")
    w("|---|---:|---:|")
    for b in BUCKET_ORDER:
        cnt = bucket_counts.get(b, 0)
        pct = (100.0 * cnt / malware.n_ok) if malware.n_ok else 0.0
        w(f"| {b} | {cnt} | {pct:.1f}% |")
    w("")
    w(f"![evasion count histogram]({chart_dir_rel}/evasion_count_histogram.png)\n")

    w("Derivation-status mix (sample-level field `derivation_status` from `clew/tiers.py`; "
      "this is **not** the defeatability tier from the evasion taxonomy):\n")
    w("| derivation_status | count | % of N | meaning |")
    w("|---|---:|---:|---|")
    meanings = {
        "fully_derivable": "every matched rule is actionable — Clew acts on this sample today, no caveats",
        "partially_derivable": "mix — at least one matched rule is actionable, at least one is not",
        "not_derivable": "no matched rules are actionable (all unmapped, or all outside-target, or any mix of those failure modes)",
        "no_capa_signal": "no matched anti-analysis rules at all — includes capa-silent samples AND non-ok runs (timeouts, errors)",
    }
    for ds in DERIVATION_STATUS_ORDER:
        cnt = malware.derivation_counts.get(ds, 0)
        pct = (100.0 * cnt / malware.n_total) if malware.n_total else 0.0
        w(f"| `{ds}` | {cnt} | {pct:.1f}% | {meanings[ds]} |")
    w("")
    n_with_unmapped = sum(1 for n in malware.unmapped_rule_counts if n > 0)
    pct_with_unmapped = (100.0 * n_with_unmapped / malware.n_ok) if malware.n_ok else 0.0
    w(f"**Unmapped-rule backlog (orthogonal to `derivation_status`):** "
      f"{n_with_unmapped} samples ({pct_with_unmapped:.1f}% of `ok`) had at least one matched capa "
      f"rule that isn't yet in `CAPA_RULE_TO_APIS`. These are queue work for week-9 derivation "
      f"and do *not* lower the sample's `derivation_status` — a sample can be `fully_derivable` "
      f"on its mapped portion while still carrying unmapped rules.\n")
    w(f"![derivation status distribution]({chart_dir_rel}/derivation_status_distribution.png)\n")

    w("## 4. Top techniques surfaced\n")
    w("These are the most frequent anti-analysis rules Channel 0 matched across the corpus. "
      "They're the prioritization input for Channel 1 (FLOSS) and Channel 2 (Binary Ninja):\n")
    w("| rank | rule | matches | % of ok |")
    w("|---:|---|---:|---:|")
    for rank, (name, count) in enumerate(malware.rule_freq.most_common(15), 1):
        pct = (100.0 * count / malware.n_ok) if malware.n_ok else 0.0
        w(f"| {rank} | `{name}` | {count} | {pct:.1f}% |")
    w("")
    w(f"![top rule frequency]({chart_dir_rel}/rule_frequency.png)\n")

    w("## 5. Specificity floor (benign control)\n")
    w("**Important framing first.** The benign control set is intentionally a *tools in your "
      "sandbox* set, not a random benign baseline. The 11 binaries are pulled from "
      "`~/CAPEv2/analyzer/windows/` — Microsoft-signed utilities **and CAPE's own analysis "
      "tools**. CAPE analyzer tools *are* analysis tools, so capa's `reference analysis tools "
      "strings` and related anti-analysis rules firing on them is correct behavior, not a "
      "false-positive signal against the rules. The table below is therefore not a true "
      "specificity floor — it characterizes the worst-case adversarial benign population: "
      "binaries that look like analysis tooling. A proper specificity floor would require a "
      "random benign baseline (signed third-party utilities, OS components excluded), which "
      "this run does not have.\n")
    w("With that caveat: the table reports the rate of anti-analysis rules firing on each "
      "population. Higher rates on the benign control are *expected* given the construction "
      "above, and do **not** indicate that capa's anti-analysis rules are broken.\n")
    if benign.n_ok > 0:
        pct_evasive_b = 100.0 * sum(1 for n in benign.evasion_counts if n >= 1) / benign.n_ok
    else:
        pct_evasive_b = 0.0
    if malware.n_ok > 0:
        pct_evasive_m = 100.0 * sum(1 for n in malware.evasion_counts if n >= 1) / malware.n_ok
    else:
        pct_evasive_m = 0.0
    w(f"| population | N (ok) | % with >=1 evasion rule | mean evasion count |")
    w(f"|---|---:|---:|---:|")
    mean_b = statistics.mean(benign.evasion_counts) if benign.evasion_counts else 0
    mean_m = statistics.mean(malware.evasion_counts) if malware.evasion_counts else 0
    w(f"| malware corpus | {malware.n_ok} | {pct_evasive_m:.1f}% | {mean_m:.2f} |")
    w(f"| benign control | {benign.n_ok} | {pct_evasive_b:.1f}% | {mean_b:.2f} |")
    w("")
    w(f"![benign vs malware]({chart_dir_rel}/benign_vs_malware.png)\n")

    w("## 6. Spotlight pair\n")
    if rich_sample:
        w("### A — capa-rich sample\n")
        w(f"- **SHA-256**: `{rich_sample.get('sha256')}`")
        w(f"- **Archive**: `{rich_sample.get('archive_date')}`")
        w(f"- **Total capa rules matched**: {rich_sample.get('total_rules')}")
        w(f"- **Anti-analysis rules** ({len(rich_sample.get('evasion_rules') or [])}): "
          + ", ".join(f"`{r}`" for r in (rich_sample.get('evasion_rules') or [])))
        w(f"- **derivation_status**: `{derivation_status_for(rich_sample)}`")
        unmapped = rich_sample.get("unmapped_rules") or []
        if unmapped:
            w(f"- **Unmapped rules (backlog)** ({len(unmapped)}): "
              + ", ".join(f"`{r}`" for r in unmapped))
        w(f"- **Runtime**: {rich_sample.get('runtime_sec'):.2f}s")
        vt_tags = load_vt_tags(Path(rich_sample.get("sample_path", "")))
        if vt_tags:
            w(f"- **VT descriptive tags**: " + ", ".join(f"`{t}`" for t in vt_tags[:10]))
        w("")
    if empty_sample:
        empty_count = len(empty_sample.get("evasion_rules") or [])
        is_truly_empty = empty_count == 0
        label = "capa-empty sample" if is_truly_empty else "low-coverage sample"
        w(f"### B — {label}\n")
        w(f"- **SHA-256**: `{empty_sample.get('sha256')}`")
        w(f"- **Archive**: `{empty_sample.get('archive_date')}`")
        w(f"- **Total capa rules matched**: {empty_sample.get('total_rules')}")
        if is_truly_empty:
            w(f"- **Anti-analysis rules**: 0 (capa found no evasion signal)")
        else:
            evasion_list = empty_sample.get("evasion_rules") or []
            w(f"- **Anti-analysis rules** ({empty_count}): " + ", ".join(f"`{r}`" for r in evasion_list))
            w(f"- _Note: no truly capa-empty sample existed in this run; this is the lowest-coverage `ok` sample available._")
        w(f"- **derivation_status**: `{derivation_status_for(empty_sample)}`")
        unmapped = empty_sample.get("unmapped_rules") or []
        if unmapped:
            w(f"- **Unmapped rules (backlog)** ({len(unmapped)}): "
              + ", ".join(f"`{r}`" for r in unmapped))
        w(f"- **Runtime**: {empty_sample.get('runtime_sec'):.2f}s")
        vt_tags = load_vt_tags(Path(empty_sample.get("sample_path", "")))
        if vt_tags:
            w(f"- **VT descriptive tags**: " + ", ".join(f"`{t}`" for t in vt_tags[:10]))
            if is_truly_empty:
                w(f"- **Interpretation note**: AV engines (above) report on this sample independently of capa. "
                  f"If the descriptive tags suggest evasion-flavored behavior but Channel 0 caught nothing, "
                  f"this sample is a candidate for Channels 1 (FLOSS) and 2 (BN) to fill in. "
                  f"AV labels are noisy and used here only for context, not as ground truth.")
            else:
                w(f"- **Interpretation note**: even Channel 0's lower-coverage samples surface *some* anti-analysis "
                  f"signal in this corpus, which is itself informative — every `ok` sample matched at least "
                  f"one rule. The downstream gap is in *depth* (per-call-site detail) rather than *breadth* "
                  f"(detection of evasion at all).")
        else:
            w(f"- **Interpretation note**: VT metadata absent; we can't characterize this sample "
              f"beyond what capa returned.")
        w("")

    w("## 7. Implications for Channel 1 (FLOSS) and beyond\n")
    top_rules = [r for r, _ in malware.rule_freq.most_common(5)]
    n_zero = sum(1 for n in malware.evasion_counts if n == 0)
    pct_zero = (100.0 * n_zero / malware.n_ok) if malware.n_ok else 0.0
    if top_rules:
        w(f"- **Capa's most-frequent anti-analysis hits** ({', '.join(f'`{r}`' for r in top_rules)}) "
          f"are the high-volume techniques in this corpus. Channel 1 (FLOSS) and Channel 2 (BN) "
          f"should treat these as priority targets for per-call-site enrichment, since these are "
          f"where the downstream fuzzer will see the most call sites.")
    if n_zero > 0:
        w(f"- **{pct_zero:.1f}% of `ok` samples ({n_zero} samples) matched zero anti-analysis rules.** "
          f"These are the candidates for Channel 1 to surface evasion that's expressed via "
          f"decoded/stackstring data capa can't decode statically — the breadth-gap for FLOSS.")
    else:
        w(f"- **No `ok` samples in this run matched zero anti-analysis rules.** Channel 0 surfaced "
          f"at least one rule on every clean run. The gap is therefore in *depth* (per-call-site "
          f"precision and concrete candidate values), which is exactly what Channels 1, 2, and 4 "
          f"add. FLOSS expands the candidate-string pool; BN connects strings to call sites; "
          f"DRIO captures runtime cmp/test operands.")
    n_total = malware.n_total or 1
    n_fully = malware.derivation_counts.get("fully_derivable", 0)
    if n_fully > 0:
        w(f"- **{n_fully} samples ({100.0*n_fully/n_total:.1f}%) are `fully_derivable`** — every "
          f"matched capa rule is actionable. This is the honest \"Clew handles these today\" "
          f"number.")
    n_partial = malware.derivation_counts.get("partially_derivable", 0)
    if n_partial > 0:
        w(f"- **{n_partial} samples ({100.0*n_partial/n_total:.1f}%) are `partially_derivable`** — "
          f"some matched rules are actionable, others are not (unmapped or APIs outside target). "
          f"Clew acts on the actionable portion; the rest is derivation backlog.")
    n_not_derivable = malware.derivation_counts.get("not_derivable", 0)
    if n_not_derivable > 0:
        w(f"- **{n_not_derivable} samples ({100.0*n_not_derivable/n_total:.1f}%) are "
          f"`not_derivable`** — capa surfaced anti-analysis rules but none are actionable yet. "
          f"Sized derivation work in this module: extend `CAPA_RULE_TO_APIS` and these flip to "
          f"`fully_derivable` or `partially_derivable`.")
    n_no_signal = malware.derivation_counts.get("no_capa_signal", 0)
    if n_no_signal > 0:
        w(f"- **{n_no_signal} samples ({100.0*n_no_signal/n_total:.1f}%) are `no_capa_signal`** — "
          f"capa returned no anti-analysis rules (truly silent, or didn't successfully complete). "
          f"Channel 0 has nothing on these; FLOSS / BN / DRIO must surface what capa missed.")
    n_timeouts = malware.n_timeout
    if n_timeouts > 0:
        pct_to = 100.0 * n_timeouts / malware.n_total
        w(f"- **Timeout rate: {pct_to:.1f}% ({n_timeouts} samples)** hit the 120s ceiling. These are "
          f"capa-pathological samples — likely heavy packers, large overlays, or control-flow "
          f"obfuscation that defeats capa's analysis budget. **Not automatically Channel 4 territory:** "
          f"DRIO carries 3-5x baseline-detonation overhead per the README, so a sample capa can't "
          f"complete in 120s probably won't yield to dynamic analysis on a reasonable budget either. "
          f"Treat these as scope-limit findings, not as a queue handed to another channel.")
    w("")

    w("## 8. Honest limitations\n")
    w(f"- **No ground truth.** Channel 0's spec is \"what capa sees\". This report characterizes that. "
      f"We did not validate per-sample whether capa was right or wrong.")
    w(f"- **N=500 isn't \"the malware ecosystem.\"** Stratified random across 4 dates spanning 2017–2021 "
      f"on VT Academic samples; descriptive only.")
    w(f"- **Capa is a black box at the pinned versions.** Rule drift in `mandiant/capa-rules` would change these numbers.")
    w(f"- **Benign control is small (N={benign.n_total}) and biased** toward Microsoft-signed analysis "
      f"tools; not a representative random benign baseline.")
    w(f"- **VT metadata is noisy.** AV-engine labels are vendor-dependent and used here only for "
      f"descriptive context in the spotlight pair, never as a ground-truth label.")
    w("")
    w(f"---")
    w(f"\n_Source data: `results/channel0_at_scale/malware_results.jsonl` "
      f"({malware.n_total} records), `results/channel0_at_scale/benign_results.jsonl` "
      f"({benign.n_total} records). Stats CSV: `results/channel0_at_scale/stats.csv`._")

    out.write_text("\n".join(lines))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--malware-jsonl", type=Path, required=True)
    ap.add_argument("--benign-jsonl", type=Path, required=True)
    ap.add_argument("--results-dir", type=Path, required=True,
                    help="dir for PNGs and stats.csv")
    ap.add_argument("--report", type=Path, required=True, help="markdown report output")
    args = ap.parse_args()

    args.results_dir.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)

    malware_records = load_records(args.malware_jsonl)
    benign_records = load_records(args.benign_jsonl)
    malware_stats = compute_stats(malware_records)
    benign_stats = compute_stats(benign_records)

    print(f"Loaded malware records: {len(malware_records)}; benign records: {len(benign_records)}")
    print(f"  malware ok/timeout/err = {malware_stats.n_ok}/{malware_stats.n_timeout}/"
          f"{malware_stats.n_capa_error + malware_stats.n_parse_error + malware_stats.n_other_error}")
    print(f"  benign ok/timeout/err = {benign_stats.n_ok}/{benign_stats.n_timeout}/"
          f"{benign_stats.n_capa_error + benign_stats.n_parse_error + benign_stats.n_other_error}")

    render_evasion_histogram(malware_stats, args.results_dir / "evasion_count_histogram.png")
    render_derivation_distribution(malware_stats, args.results_dir / "derivation_status_distribution.png")
    render_rule_frequency(malware_stats, args.results_dir / "rule_frequency.png")
    render_runtime_distribution(malware_stats, args.results_dir / "runtime_distribution.png")
    render_benign_vs_malware(malware_stats, benign_stats, args.results_dir / "benign_vs_malware.png")
    write_csv(malware_stats, args.results_dir / "stats.csv")

    rich, empty = pick_spotlights(malware_records)
    write_report(
        malware=malware_stats,
        benign=benign_stats,
        rich_sample=rich,
        empty_sample=empty,
        out=args.report,
        chart_dir_rel="../results/channel0_at_scale",
    )
    print(f"\nReport written to {args.report}")
    print(f"Charts in {args.results_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

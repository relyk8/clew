# Plan: rename `tier_classification` → `derivation_status`

**Date:** 2026-05-23
**Status:** Implemented, committed, and force-pushed. Migration applied to existing JSONLs (no capa re-execution). New numbers landed in `docs/channel0_at_scale.md`: 202 (42.4%) `fully_derivable`, 274 (57.6%) `no_mapped_signal`, 0 `partially_derivable` (structural), 183 (38.4%) carrying unmapped-rule backlog. Work-laptop smoke test outstanding; resync command: `git fetch origin && git reset --hard origin/main`.

## Context

The repo had two unrelated meanings of "tier" living under the same name:

1. **Defeatability tier** (the taxonomy): a property of an **evasion technique**, classifying how hard it is to defeat from an API-hooking fuzzer. `Tier 1 = single-call defeatable`, `Tier 2 = multi-call coordination`, `Tier 3–4 = crypto/timing/infeasible`. Lives in `README.md`, `docs/context/evasion-taxonomy.md`, `docs/context/defcon-slide-outline.md`.
2. **API-coverage tier** (the code): a property of a **sample**, classifying whether the APIs implied by its matched capa rules sit inside Pfuzzer's 68. `tier_1 = all inside`, `tier_2 = mixed`, `tier_3 = at least one rule unmapped`, `tier_4 = not capa-detectable`. Lives in `clew/tiers.py`, `docs/schema.md`, `docs/schema_v2_notes.md`, and now `docs/channel0_at_scale.md`.

They classify different objects against different criteria but share names. A reader bouncing between docs would interpret the same number two ways. The 500-sample scale writeup made this concrete: `61.6% tier_1, 38.4% tier_3` reads as "61.6% single-call defeatable, 38.4% infeasible" under the taxonomy framing, while it actually means "61.6% have all APIs inside Pfuzzer-68, 38.4% have at least one capa rule we haven't written derivation logic for."

A secondary problem: `classify()` short-circuited on any unmapped rule. The `tier_2` (mixed) branch was never reached on the 500-sample corpus, not because malware doesn't have mixed-API samples, but because most samples that would land there also hit at least one unmapped rule and got pushed to `tier_3` first. And even with the short-circuit removed, every API in the current `CAPA_RULE_TO_APIS` is inside `PFUZZER_68_APIS` — so the mixed bucket is *structurally* unreachable under the current data.

## Goal

1. Eliminate the name collision. The two tier concepts should be addressable independently.
2. Stop the short-circuit. Mapped-rule classification should not be hijacked by the presence of unmapped rules.
3. Produce honest categorical buckets that a slide audience can read at a glance, without footnotes explaining what "tier_3" means in this particular document.

## Approach (chosen — Option B from the design conversation)

### Sample-level field

Rename `tier_classification` → `derivation_status`. New enum:

| Value | When |
|---|---|
| `fully_derivable` | At least one matched capa rule is in `CAPA_RULE_TO_APIS`, AND every implied API is in `PFUZZER_68_APIS`. |
| `partially_derivable` | At least one matched capa rule is mapped, AND at least one implied API is outside `PFUZZER_68_APIS`. Structurally empty under the current rule map; reachable once the map adds rules implying outside-68 APIs. |
| `no_mapped_signal` | No matched capa rule is in `CAPA_RULE_TO_APIS`. Subsumes both "zero capa rules" and "only unmapped rules." |
| `not_capa_detectable` | Decided outside this module — sample uses techniques capa cannot detect. Unchanged role; not produced by `classify()`. |

`classify()` no longer short-circuits. It separates the "do we have any mapped rule" check from the "is the implied API set inside the target list" check.

The `unmapped_rules` list is still returned as the second element of the tuple. A `fully_derivable` sample can carry a non-empty `unmapped_rules` list — that's the actionable signal for week-9 derivation work.

### Per-candidate field

`evasion_tier` per candidate **stays unchanged in name and enum**. Its semantics are now explicit in `docs/schema.md`: this is the **defeatability tier of the technique this candidate addresses**, drawn from the taxonomy in `docs/context/evasion-taxonomy.md` (`tier_1 = single-call defeatable`, etc.). It is *not* the API-coverage concept. Existing fixtures keep their `evasion_tier: tier_1` values because `IsDebuggerPresent` and the al-khaser DLL-fingerprint loop are both correctly tier_1 under the defeatability semantics.

This bifurcation is the load-bearing fix: the two tier concepts now live in different fields with different names. `derivation_status` is "where is Clew with this sample today?" and `evasion_tier` is "how hard is this specific check to defeat?"

## File changes in this commit

| File | Change |
|---|---|
| `clew/tiers.py` | Rewrite `classify()` per the new semantics. Drop the short-circuit. Update docstring. |
| `clew/channels/capa.py` | Add `CAPA_PINS` module-level constants (flare-capa version, capa-rules tag, capa sigs commit) so the pinning lives in code, not just in writeups. |
| `schema/clew_record.schema.json` | Rename top-level field, add new enum `DerivationStatus`. Keep `Tier` enum for per-candidate `evasion_tier`. |
| `docs/schema.md` | Rewrite the `tier_classification` section as `derivation_status`. Add a clarifying note to the `evasion_tier` section. Update both example records (now `"derivation_status": "fully_derivable"`). |
| `docs/schema_v2_notes.md` | Update §3 (tier-classification derivation) to refer to `derivation_status` and the new semantics. |
| `scripts/batch_channel0.py` | Rename output field `tier` → `derivation_status`. |
| `scripts/analyze_channel0.py` | Rename field reads, update the distribution chart to show new categories, rewrite §3 + §7 report templates so the language matches the new semantics. |
| `tests/test_tiers.py` | Update test cases. New cases for `fully_derivable`, `no_mapped_signal`, `partially_derivable` (with synthetic outside-68 API), and `fully_derivable` with non-empty `unmapped_rules`. |
| `tests/fixtures/1fe91674eb8d_01.expected.json` | Rename field; value becomes `fully_derivable`. |
| `tests/fixtures/1fe91674eb8d_02.expected.json` | Same. |

## Out of scope for this commit

These are real follow-up items from yesterday's audit but bundled separately to keep this commit reviewable:

- Expanding `PFUZZER_68_APIS` from the current 19 entries to the full 68 from the Pfuzzer paper.
- Adding `GetUserNameA`/`GetComputerNameA`/`RegQueryValueEx` to the target list (currently the canonical DEFCON example API isn't in the code).
- Adding the `api_knowledge/` signature-shape lookup table.
- Calling out CPUID/RDTSC/direct-PEB techniques as explicitly out of scope.
- Three-stages vs five-channels reconciliation.
- Consolidation/derivation step design doc.
- `select_samples.py` and `batch_channel0.py` hardcoded paths → argparse defaults.

## What got run on the home machine (this commit)

No capa re-execution. The existing JSONLs already store `evasion_rules` per record, and the new `classify()` is a pure function of those rule names. The expensive capa step (7,476 sec on the prior run) does not repeat.

Steps that happened here before commit:

1. Schema/tier tests validated inline (pytest not globally available; the test logic was exercised via direct invocation of `classify()` plus a `jsonschema.Draft202012Validator` pass over `schema/clew_record.schema.json` and both fixture records and both `docs/schema.md` example records).
2. `results/channel0_at_scale/malware_results.jsonl` and `benign_results.jsonl` migrated in place: each record's stale `tier` field dropped, `derivation_status` field added by re-running the new `classify()` against the stored `evasion_rules`. Migration is deterministic and idempotent.
3. `scripts/analyze_channel0.py` re-run against the migrated JSONLs. New chart `results/channel0_at_scale/derivation_status_distribution.png` rendered; old `tier_distribution.png` removed. `docs/channel0_at_scale.md` regenerated.

## Numbers under the new schema

For audit (matches what's in the regenerated `docs/channel0_at_scale.md` §3):

| derivation_status | N | % of ok (476) |
|---|---:|---:|
| `fully_derivable` | 202 | 42.4% |
| `partially_derivable` | 0 | 0.0% |
| `no_mapped_signal` | 274 | 57.6% |
| `not_capa_detectable` | 0 | 0.0% |

Orthogonal: 183 samples (38.4% of `ok`) carry at least one unmapped capa rule as derivation backlog — this is independent of the categorical above.

Reconciliation with the previous numbers:
- Old `tier_1` 293 = 195 zero-rule + 98 truly-derivable (the conflation).
- New `fully_derivable` 202 = 98 truly-derivable + 104 previously-short-circuited-to-tier_3 (samples with at least one mapped rule and at least one unmapped rule).
- New `no_mapped_signal` 274 = 195 zero-rule + 79 samples whose entire evasion-rules set was unmapped.
- Total still 476 `ok`. ✓

## Work-laptop test plan

The work laptop's job under the new workflow is a quick smoke test, not a full re-run:

```bash
git pull

# 1. Smoke test: the batch script should produce records with the new field.
python scripts/batch_channel0.py \
  --directory ~/CAPEv2/analyzer/windows/ \
  --output /tmp/smoke_test.jsonl \
  --rules-path <capa-rules dir> \
  --sigs-path <capa-sigs dir> \
  --timeout 60 \
  --limit 5

# Confirm each record has a `derivation_status` field and no `tier` field.
python3 -c "
import json
for line in open('/tmp/smoke_test.jsonl'):
    rec = json.loads(line)
    assert 'derivation_status' in rec, 'missing derivation_status'
    assert 'tier' not in rec, 'stale tier field present'
    print(rec['sha256'][:12], rec['status'], rec.get('derivation_status'))
"

# 2. If the smoke test passes, no further action required — the migrated
#    JSONLs and regenerated report are already in this commit.
```

Wall-clock cost on the work laptop: ~5 minutes for the 5-sample smoke test.

## Why this is the right move pre-Tuesday and pre-DEFCON

- Tuesday status report: the new naming gives three clean numbers (42.4% fully_derivable, 57.6% no_mapped_signal, 38.4% with unmapped-rule backlog) that map directly to slide phrasing.
- DEFCON Demo Lab: per-candidate `evasion_tier` now unambiguously matches the defeatability tier in the taxonomy + slide outline. No cross-doc semantic collision.
- The expensive part of the existing test (capa execution) does not repeat — the migration re-derives from cached rule names.

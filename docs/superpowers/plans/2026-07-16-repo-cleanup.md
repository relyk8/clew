# Repo Cleanup for Public Release — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare the Clew repository for public, DefCon-ready release through enforced formatting, audience-organized docs, a reader-facing README, and clean metadata — with zero behavior changes.

**Architecture:** Five sequential stages, one commit each: (1) add ruff tooling and run a one-time lint/format pass; (2) move process/history docs into `docs/notes/` and promote two docs, updating every reference; (3) rewrite README and extract the old one; (4) fix metadata (commit CLAUDE.md, sync version, add an enforcing test); (5) a publishability sweep with user sign-off. Each stage keeps the offline `pytest` suite green.

**Tech Stack:** Python 3.10+ (dev interpreter is 3.13), ruff 0.15.x, pytest, git.

## Global Constraints

- **No behavior changes.** Formatting and organization only. A lint fix that would alter semantics gets a justified `# noqa` instead of a rewrite.
- **Offline `pytest` suite green after every stage** — run `pytest` (the default offline set; do not set `BN_INTEGRATION`, `CAPA_RULES_PATH`, or `CAPA_SIGS_PATH`).
- **Every doc move is `git mv`** followed by a grep-driven reference update; a move is done only when `grep -rn` for the old path returns zero hits outside `docs/notes/` history prose.
- **Ruff config:** `line-length = 100`, `target-version = "py310"`, lint = ruff defaults plus `I` (import sorting).
- **Version of record:** `CLEW_VERSION = "0.3.0"` in `clew/pipeline.py:41` is authoritative; `pyproject.toml` follows it.
- Nothing is deleted; process/history material is relocated, not removed.

---

### Task 1: Ruff tooling + one-time lint/format pass

**Files:**
- Modify: `pyproject.toml` (add ruff to `dev` extra; add `[tool.ruff]` block)
- Modify (lint fixes): `clew/cape_client.py:166`, `clew/channels/bn_callsites.py:53,55`, `clew/channels/floss.py:230`, `scripts/analyze_channel0.py:15`, `tests/test_bn_dataflow.py:28`, `tests/test_floss.py:23,26`
- Modify (noqa): `scripts/batch_channel0.py:22,30`
- Modify (semicolons): `clew/analysis/dataflow.py:914,917`
- Format: whole repo (`ruff format`)

**Interfaces:**
- Consumes: nothing (first task).
- Produces: a clean `ruff check .` and `ruff format --check .` for all later tasks; a `[tool.ruff]` config block other contributors rely on.

- [ ] **Step 1: Add ruff to dev extra and configure it in `pyproject.toml`**

Change the `dev` extra and append a ruff config block:

```toml
[project.optional-dependencies]
dev = ["pytest>=7", "jsonschema>=4", "ruff>=0.15"]
analysis = ["matplotlib>=3.8", "pandas>=2.0"]
```

```toml
[tool.ruff]
line-length = 100
target-version = "py310"

[tool.ruff.lint]
extend-select = ["I"]
```

- [ ] **Step 2: Confirm the baseline finding count before changing code**

Run: `ruff check .`
Expected: `Found 50 errors.` (45 auto-fixable). This is the pre-fix baseline that Steps 3–6 drive to zero.

- [ ] **Step 3: Auto-fix the mechanical findings**

Run: `ruff check --fix .`
This removes unused imports (`cape_client.py` `json`; `bn_callsites.py` `asdict`, `Iterable`; `analyze_channel0.py` `Any`; `test_bn_dataflow.py` `CONF_OBFUSCATED_ASSOC`; `test_floss.py` `FlossString`, `_adapt_result_document`), strips extraneous `f` prefixes (`scripts/analyze_channel0.py` f-strings without placeholders), and sorts imports.
Expected after: the only remaining findings are 1× F401 in `floss.py:230`, 2× E402 in `batch_channel0.py`, 2× E702 in `dataflow.py`.

- [ ] **Step 4: Hand-fix the non-auto-fixable findings**

`clew/channels/floss.py:230` — remove the unused alias import. The line `import floss.results as fr` is dead: `fr` is never used, and the very next line already imports the concrete names from `floss.results`, so it is redundant for the ImportError availability guard too. Delete only that line:

```python
    try:
        import floss.main as fm
        from floss.results import Analysis, Metadata, ResultDocument
    except ImportError as e:
        raise FlossImportError("flare-floss is not installed") from e
```

`clew/analysis/dataflow.py:914,917` — split the semicolon statements (E702), preserving exact logic:

```python
    run = [slots[base_storage]]
    s = base_storage + stride
    while s in slots:
        run.append(slots[s])
        s += stride
    s = base_storage - stride
    while s in slots:
        run.insert(0, slots[s])
        s -= stride
    return run
```

`scripts/batch_channel0.py:22,30` — the two E402s are caused by the deliberate `sys.path.insert` shim at lines 19–20 that must run before importing `clew`. Annotate rather than reorder. Add `# noqa: E402` to both module-level import statements below the shim:

```python
from clew.channels.capa import (  # noqa: E402  (import follows sys.path shim above)
    run_capa,
    filter_evasion_techniques,
    CapaError,
    CapaNotFoundError,
    CapaRunError,
    CapaParseError,
)
from clew.tiers import classify  # noqa: E402  (import follows sys.path shim above)
```

- [ ] **Step 5: Verify lint is clean**

Run: `ruff check .`
Expected: `All checks passed!`

- [ ] **Step 6: Run the one-time formatter pass**

Run: `ruff format .`
Then: `ruff format --check .`
Expected: `format --check` reports all files already formatted.

- [ ] **Step 7: Verify the offline test suite still passes**

Run: `pytest`
Expected: PASS (same passed/skipped counts as before this task — no new failures). If any test fails, a format/lint change altered behavior; revert that specific change and use `# noqa` instead.

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml clew/ scripts/ tests/
git commit -m "Add ruff tooling and run one-time lint/format pass"
```

---

### Task 2: Docs reorganization by audience

**Files:**
- Create dir: `docs/notes/`
- `git mv` (promote): `docs/week_04_bn_dataflow.md` → `docs/bn_dataflow.md`; `docs/context/evasion-taxonomy.md` → `docs/evasion-taxonomy.md`
- `git mv` (to notes): `docs/week_01_retrospective.md`, `docs/week_02_retrospective.md`, `docs/week_03_bn_callsites.md`, `docs/week_03_floss.md`, `docs/plan_derivation_rename.md`, `docs/context/CONTEXT.md`, `docs/context/clew-brainstorm.md`, `docs/context/defcon-slide-outline.md`, `docs/context/defcon-submission.txt` → `docs/notes/`
- Modify (reference updates): `CLAUDE.md`, `clew/analysis/dataflow.py`, `clew/tiers.py`, `clew/channels/bn_callsites.py`, `clew/channels/capa.py`, `clew/channels/floss.py`, `tests/test_floss.py`, `docs/schema.md`, `docs/schema_v2_notes.md`, `docs/static_pipeline.md`, `docs/pilot_results.md`, `schema/clew_record.schema.json`, and any moved doc that references another moved doc

**Interfaces:**
- Consumes: clean tree from Task 1.
- Produces: final doc paths that Task 3 (README reading guide) and Task 4 (CLAUDE.md pointers) link to — canonical names are `docs/bn_dataflow.md` and `docs/evasion-taxonomy.md`.

- [ ] **Step 1: Create the notes directory and move files with git**

```bash
mkdir -p docs/notes
git mv docs/week_04_bn_dataflow.md docs/bn_dataflow.md
git mv docs/context/evasion-taxonomy.md docs/evasion-taxonomy.md
git mv docs/week_01_retrospective.md docs/notes/
git mv docs/week_02_retrospective.md docs/notes/
git mv docs/week_03_bn_callsites.md docs/notes/
git mv docs/week_03_floss.md docs/notes/
git mv docs/plan_derivation_rename.md docs/notes/
git mv docs/context/CONTEXT.md docs/notes/
git mv docs/context/clew-brainstorm.md docs/notes/
git mv docs/context/defcon-slide-outline.md docs/notes/
git mv docs/context/defcon-submission.txt docs/notes/
```

- [ ] **Step 2: Confirm `docs/context/` is now empty and remove it**

Run: `ls docs/context/ 2>/dev/null; rmdir docs/context 2>/dev/null; echo done`
Expected: no files listed; directory removed (git tracks the moves, the now-empty dir is untracked).

- [ ] **Step 3: Inventory every reference to a moved path**

Run:
```bash
grep -rn --exclude-dir=.git -e 'week_04_bn_dataflow' -e 'docs/context/' \
  -e 'week_03_bn_callsites' -e 'week_03_floss' -e 'week_01_retro' \
  -e 'week_02_retro' -e 'plan_derivation_rename' -e 'clew-brainstorm' \
  -e 'defcon-slide-outline' -e 'defcon-submission' -e 'context/CONTEXT' \
  -e 'context/evasion-taxonomy' .
```
Expected: a hit list. Every non-history hit must be updated in the next step. This is the checklist for Step 4.

- [ ] **Step 4: Update all references to the new paths**

Apply these path substitutions across the hit list (both prose links and docstring citations):
- `docs/week_04_bn_dataflow.md` → `docs/bn_dataflow.md`
- `docs/context/evasion-taxonomy.md` → `docs/evasion-taxonomy.md`
- `docs/context/CONTEXT.md` → `docs/notes/CONTEXT.md`
- `docs/context/clew-brainstorm.md` → `docs/notes/clew-brainstorm.md`
- `docs/context/defcon-slide-outline.md` → `docs/notes/defcon-slide-outline.md`
- `docs/context/defcon-submission.txt` → `docs/notes/defcon-submission.txt`
- `docs/week_01_retrospective.md` → `docs/notes/week_01_retrospective.md` (and week_02, week_03_* likewise)
- `docs/plan_derivation_rename.md` → `docs/notes/plan_derivation_rename.md`

Known citers to check specifically:
- `schema/clew_record.schema.json:66` — the `EvasionTier` `description` string cites `docs/context/evasion-taxonomy.md`. Change only that description string; the machine contract is otherwise untouched (no behavior change — the description is non-functional).
- `clew/tiers.py`, `clew/analysis/dataflow.py`, `clew/channels/bn_callsites.py`, `clew/channels/capa.py`, `clew/channels/floss.py` — docstring path citations.
- `tests/test_floss.py` — comment citing `docs/schema_v2_notes.md` (unmoved — no change needed; verify it isn't a moved path).
- `docs/schema.md`, `docs/schema_v2_notes.md`, `docs/static_pipeline.md`, `docs/pilot_results.md` — prose links.
- `CLAUDE.md` — handled in Task 4; if edited here, keep consistent.
- Within `docs/notes/`, references from one moved file to another moved file (e.g. retrospectives citing `schema_v2_notes.md` which did NOT move, or citing each other) get updated where the reference functions as a link; pure historical narration ("we created X") is left as-is.

- [ ] **Step 5: Verify no stale references remain**

Run the Step 3 grep again.
Expected: zero hits for `docs/context/` and `week_04_bn_dataflow`; remaining hits for the `week_0*`/`plan_derivation`/etc. names are only inside `docs/notes/` history prose (not functioning links). Manually confirm each surviving hit is history narration, not a broken link.

- [ ] **Step 6: Verify offline tests still pass**

Run: `pytest`
Expected: PASS (docstring/comment edits don't affect behavior; this catches any accidental code edit).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "Reorganize docs by audience: promote canonical docs, move history to docs/notes/"
```

---

### Task 3: README rewrite + extract original

**Files:**
- Create: `docs/notes/original-plan.md` (verbatim copy of the current README with a one-line header)
- Modify: `README.md` (full rewrite as public front door)

**Interfaces:**
- Consumes: canonical doc paths from Task 2 (`docs/schema.md`, `docs/static_pipeline.md`, `docs/bn_dataflow.md`).
- Produces: the public README; no downstream task consumes it.

- [ ] **Step 1: Copy the entire current README to the notes archive**

```bash
cp README.md docs/notes/original-plan.md
```
Then prepend a one-line header to `docs/notes/original-plan.md` (above its existing `# Clew — Pilot Study and Tech Setup` title):

```markdown
> **Archived original proposal (2026-07).** This is the repository's first
> README — the pilot-study plan and 12-week schedule. The actual layout
> diverged (`clew/channels/` not `clew/extractors/`; `pipeline.py`
> orchestrates directly). Kept for the research trail; not current
> documentation.

```

- [ ] **Step 2: Write the new `README.md`**

Overwrite `README.md` with the public front door. Use this structure and content (fill technique/pitch text from `docs/schema.md` and CLAUDE.md; keep the "Locked design decisions" table verbatim from the archived original):

```markdown
# Clew

Clew is a per-sample candidate-extraction pipeline for environment-sensitive
malware analysis. It runs once over a PE32 sample and emits a structured JSON
record of candidate API return/argument values that a downstream fuzzer
(Pfuzzer) uses as seeds to reach evasion-gated execution paths. It replaces
Pfuzzer's hand-coded, sample-agnostic retarget lists with candidates derived
from the binary itself.

## The channel model

Work is organized as numbered **channels**, each owning a disjoint slice of the
output record:

| # | Channel | Produces | Status |
|---|---|---|---|
| 0 | capa | sample-level technique detection, derivation status | static |
| 1 | FLOSS | string values (static, stackstring, tightstring, decoded) | static |
| 2 | Binary Ninja | API call sites + MLIL-SSA dataflow joining sites to values | static |
| 4 | DynamoRIO cmp-logging (in CAPE) | comparison operands after API returns | dynamic (not yet integrated) |
| 5 | CAPE config extractors | family-specific config (C2, keys) | dynamic (not yet integrated) |

The output contract lives in `docs/schema.md` (human-readable) and
`schema/clew_record.schema.json` (machine-checkable).

## Prerequisites

- **Core channel (Binary Ninja):** Binary Ninja `4.2.6455 Ultimate` with an
  Enterprise license is required to run the pipeline over a real sample.
- **capa rules/sigs:** supply paths via `CLEW_CAPA_RULES` and `CLEW_CAPA_SIGS`.
  The built-in defaults point at internal cluster paths and will not exist on a
  fresh checkout.
- **Without a license:** the offline, fixture-driven test suite runs clean on a
  bare checkout — see [Running tests](#running-tests). This is the recommended
  way to explore Clew's behavior without BN or capa.

## Install

```bash
pip install -e '.[dev,analysis]'
```

## Quickstart

```bash
# Full static pipeline over a sample (BN license + capa rules/sigs required)
export CLEW_CAPA_RULES=/path/to/capa-rules
export CLEW_CAPA_SIGS=/path/to/capa-sigs
python -m clew.pipeline tests/fixtures/al-khaser_x86.exe -o /tmp/al.clew.json
```

There is no console-script entry point; the CLI is `python -m clew.pipeline`.

## Locked design decisions

Not re-opened without cause.

| Decision | Choice |
|---|---|
| LLM enrichment | Out of v1 |
| capa preprocessing | In as explicit stage |
| Target API list | Pfuzzer's 68 for v1 |
| Packaging | Standalone Clew CLI; Channel 4 uses CAPE via REST API |
| Channel 3 status | Folded into Channel 2 as enrichment |
| Iterative mode | Deferred to v2; schema and orchestration built iteration-ready |
| Scope tiers | Tier 1 full, Tier 2 partial, Tier 3–4 triage-only |

## Running tests

```bash
# Offline suite (no BN license, no capa rules — the default CI-able set)
pytest
```

Expensive/licensed tests are opt-in via environment variables:

- `BN_INTEGRATION=1` — enables the licensed real Binary Ninja analysis tests
  (needs a BN Enterprise license and the fixture `.exe` present).
- `CAPA_RULES_PATH` + `CAPA_SIGS_PATH` — enables capa integration tests.

Tests also skip when a required fixture hasn't been generated, so a clean
checkout runs a reduced-but-green suite.

## Reading guide

- `docs/schema.md` — the record contract (read first).
- `docs/static_pipeline.md` — the orchestrator in depth (canonical architecture doc).
- `docs/bn_dataflow.md` — the dataflow bridge internals and reproducibility investigation.
- `docs/evasion-taxonomy.md` — the defeatability-tier taxonomy.
- `docs/notes/` — research trail: retrospectives, planning notes, the original proposal.
```

- [ ] **Step 3: Verify all README links resolve**

Run:
```bash
for f in docs/schema.md docs/static_pipeline.md docs/bn_dataflow.md docs/evasion-taxonomy.md docs/notes; do test -e "$f" && echo "OK $f" || echo "MISSING $f"; done
```
Expected: all `OK`.

- [ ] **Step 4: Verify offline tests still pass**

Run: `pytest`
Expected: PASS (no code touched).

- [ ] **Step 5: Commit**

```bash
git add README.md docs/notes/original-plan.md
git commit -m "Rewrite README as public front door; archive original proposal to docs/notes/"
```

---

### Task 4: Metadata hygiene

**Files:**
- Modify: `pyproject.toml` (version `0.1.0` → `0.3.0`)
- Modify: `CLAUDE.md` (update moved-doc pointers), then track it
- Create: `tests/test_version.py` (enforce package version == CLEW_VERSION)

**Interfaces:**
- Consumes: `CLEW_VERSION` constant at `clew/pipeline.py:41`; final doc paths from Task 2.
- Produces: an offline test guarding version drift.

- [ ] **Step 1: Sync the package version**

In `pyproject.toml`, change:
```toml
version = "0.1.0"
```
to:
```toml
version = "0.3.0"
```

- [ ] **Step 2: Write the failing version-sync test**

Create `tests/test_version.py`:

```python
"""Guard: the packaged version must match the record/schema version of record.

The pyproject `version` drifted from CLEW_VERSION once already because nothing
enforced the pairing. This test makes the offline suite enforce it.
"""
from importlib.metadata import version

from clew.pipeline import CLEW_VERSION


def test_package_version_matches_clew_version():
    assert version("clew") == CLEW_VERSION
```

- [ ] **Step 3: Run the test to confirm it passes with the synced version**

Run: `pytest tests/test_version.py -v`
Expected: PASS. (If the editable install still reports `0.1.0`, reinstall metadata with `pip install -e . --no-deps` and re-run; the installed dist metadata must reflect the new version.)

To prove the guard bites, temporarily revert `pyproject.toml` to `0.1.0`, reinstall, and confirm the test FAILS; then restore `0.3.0` and reinstall. (Optional but recommended.)

- [ ] **Step 4: Update `CLAUDE.md` doc pointers to the post-move layout**

In `CLAUDE.md`, update every reference to a moved doc:
- `docs/week_04_bn_dataflow.md` → `docs/bn_dataflow.md` (both the reproducibility-section pointer and the "Where to read next" entry)
- `docs/context/evasion-taxonomy.md` → `docs/evasion-taxonomy.md`

Run to confirm none remain:
```bash
grep -n -e 'week_04_bn_dataflow' -e 'docs/context/' CLAUDE.md
```
Expected: no output.

- [ ] **Step 5: Verify offline tests pass**

Run: `pytest`
Expected: PASS, including the new `tests/test_version.py`.

- [ ] **Step 6: Commit (this is where CLAUDE.md enters version control)**

```bash
git add pyproject.toml CLAUDE.md tests/test_version.py
git commit -m "Sync package version to 0.3.0, add version-drift guard, track CLAUDE.md"
```

---

### Task 5: Publishability sweep + user sign-off

**Files:**
- Read-only sweep across everything that ships; no code changes unless the user directs one.

**Interfaces:**
- Consumes: the fully reorganized tree from Tasks 1–4.
- Produces: a findings list for user decision. This task does not resolve findings unilaterally.

- [ ] **Step 1: Scan for internal infrastructure and sensitive content**

Run:
```bash
grep -rn --exclude-dir=.git -iE '/home/shared|afit|cluster|password|secret|token|api[_-]?key|@[a-z0-9.-]+\.(mil|edu)|10\.[0-9]+\.|192\.168\.' . | grep -v '\.git/'
```
Also review by hand the highest-risk files: `docs/notes/CONTEXT.md` (advisor/process narration), `docs/notes/defcon-submission.txt`, `docs/notes/clew-brainstorm.md`, and `clew/pipeline.py:50-51` (cluster-path defaults).

- [ ] **Step 2: Cross-check the already-decided dispositions**

The spec pre-decided these ship as-is; confirm nothing new contradicts them:
- `clew/pipeline.py:50-51` cluster-path defaults — stay (changing them is a behavior change; documented in README Prerequisites).
- `CLAUDE.md` AFIT-cluster mention — stays (accurate operational context).
- `docs/notes/` and `docs/superpowers/` — ship publicly (research trail).

- [ ] **Step 3: Produce the findings list and get user sign-off**

Write a short list: each hit → file:line, what it is, recommended disposition (redact / move out of repo / accept). Present it to the user. Do NOT redact or delete anything unilaterally — each flagged item is resolved by the user's decision.

- [ ] **Step 4: Apply only user-approved resolutions, then commit if anything changed**

If the user approves redactions/moves, apply exactly those, run `pytest` to confirm green, then:
```bash
git add -A
git commit -m "Publishability sweep: apply user-approved redactions"
```
If the user accepts everything as-is, no commit is needed; record the sign-off in the PR/branch description instead.

---

## Self-Review Notes

- **Spec coverage:** §1 ruff → Task 1; §2 docs reorg (incl. schema.json ref, superpowers disposition) → Task 2; §3 README + full extraction + prerequisites + design-decisions table → Task 3; §4 metadata + version-sync test → Task 4; §5 publishability audit + sign-off → Task 5. All sections mapped.
- **Non-goals honored:** `.gitignore`, `results/`, `docs/cape_integration/`, and code restructuring are untouched by every task.
- **Type consistency:** the one new symbol is `test_package_version_matches_clew_version` in `tests/test_version.py`, importing the existing `CLEW_VERSION` from `clew.pipeline`.

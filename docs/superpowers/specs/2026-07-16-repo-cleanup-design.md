# Repo Cleanup for Public Release — Design

**Date:** 2026-07-16
**Goal:** Make the Clew repository presentable as a public, DefCon-ready
artifact: enforced formatting, docs organized by audience, a reader-facing
README, and clean metadata. No behavior changes; the offline test suite stays
green throughout.

## Motivation

Clew targets a DefCon submission as a standalone tool. The code and docs are
substantively strong but carry solo-research-repo artifacts: no lint/format
tooling (a trial `ruff check` finds 50 issues, 45 auto-fixable), a flat `docs/`
mixing contract docs with week retrospectives and planning notes, a README
still holding the original strawman schema and a 12-week plan whose "Proposed
repo structure" no longer matches reality, an untracked `CLAUDE.md`, and a
package version (`0.1.0`) out of sync with `CLEW_VERSION` (`0.3.0`).

## Constraints

- **Docs are load-bearing.** Code docstrings (`clew/channels/floss.py`,
  `clew/analysis/dataflow.py`, `clew/channels/bn_callsites.py`,
  `clew/channels/capa.py`, `clew/tiers.py`), tests (`tests/test_floss.py`),
  other docs (`docs/schema.md`, `docs/pilot_results.md`, retrospectives), and
  `CLAUDE.md` all cite doc paths. Every file move must be paired with a
  reference-update pass and verified by grep.
- **No behavior changes.** This is formatting and organization only. Lint
  fixes that would alter semantics (e.g. "fixing" a deliberately deferred
  import) get a justified `# noqa` instead.
- **Offline `pytest` suite must pass after every stage.**

## 1. Lint/format tooling (ruff)

- Add `ruff` to the `dev` optional-dependency extra in `pyproject.toml`.
- Add a `[tool.ruff]` config block: `line-length = 100`,
  `target-version = "py310"`, lint rules = ruff defaults plus `I` (import
  sorting).
- One-time cleanup pass:
  - `ruff check --fix` for the mechanical findings (f-strings without
    placeholders, unused imports, import sorting).
  - Hand-review the remainder. The two `E402` (module import not at top of
    file) hits are suspect-deliberate: this codebase defers heavy imports
    (Binary Ninja, capa) by design so `assemble_record()` stays
    offline-testable. If deliberate, annotate `# noqa: E402` with a one-line
    reason; only genuinely accidental cases get moved.
  - `ruff format` once over the whole repo (one-time diff noise accepted
    pre-publication).
- Enforcement stays manual (`ruff check .`, `ruff format --check .`); no
  pre-commit hooks or CI in this pass.

## 2. Docs reorganization by audience

Nothing is deleted; files split into reader-facing vs. process/history.

**`docs/` top level (reader-facing):**

| File | Action |
|---|---|
| `schema.md` | stays |
| `static_pipeline.md` | stays |
| `schema_v2_notes.md` | stays — cited by code docstrings; a living contract log |
| `binary_ninja_headless_setup.md` | stays |
| `channel0_at_scale.md` | stays |
| `pilot_results.md` | stays |
| `week_04_bn_dataflow.md` | rename → `bn_dataflow.md` (canonical bridge-internals doc) |
| `context/evasion-taxonomy.md` | promote → `docs/evasion-taxonomy.md` (taxonomy of record, cited by `schema.md` and `tiers.py`) |

**`docs/notes/` (process/history — new directory):**

| File | Action |
|---|---|
| `week_01_retrospective.md`, `week_02_retrospective.md` | move |
| `week_03_bn_callsites.md`, `week_03_floss.md` | move (superseded by module docstrings + canonical docs) |
| `plan_derivation_rename.md` | move |
| `context/CONTEXT.md`, `context/clew-brainstorm.md`, `context/defcon-slide-outline.md`, `context/defcon-submission.txt` | move; `docs/context/` is then removed |
| README's strawman schema + 12-week plan | extracted → `docs/notes/original-plan.md` (see §3) |

**Unchanged:** `docs/cape_integration/` stays intact, including
`exe_drcov.py` — it is a self-contained integration record and the script is
documentation-adjacent evidence cited by `pilot_results.md`, not pipeline code.

**Mechanics:** every move/rename is `git mv`, followed by a grep-driven update
of all references in code docstrings, tests, docs, and `CLAUDE.md`. Done when
`grep -rn` for each old path returns zero hits outside `docs/notes/` history
context (references *within* moved retrospectives to other moved files are
updated too; prose that narrates history, e.g. "we created
docs/schema_v2_notes.md", is updated only where it functions as a link).

## 3. README rewrite

Rewrite `README.md` as the public front door:

1. What Clew is — the one-paragraph pitch (per-sample candidate extraction for
   environment-sensitive malware, seeds for Pfuzzer).
2. The channel model at a glance (channels 0/1/2 static, 4/5 dynamic; who owns
   which record fields).
3. Install (`pip install -e '.[dev,analysis]'`) and CLI quickstart
   (`python -m clew.pipeline …`).
4. Running tests, including the gating model (`BN_INTEGRATION=1`,
   `CAPA_RULES_PATH`/`CAPA_SIGS_PATH`, fixture-driven offline default).
5. Reading guide into `docs/` (schema first, then static_pipeline, then
   bn_dataflow).

The current README's strawman schema and 12-week plan move verbatim to
`docs/notes/original-plan.md` with a one-line header noting it is the original
proposal and that the layout diverged.

## 4. Metadata hygiene

- Commit `CLAUDE.md`, after updating its doc paths ("Where to read next",
  reproducibility pointers) to the post-move layout.
- Sync `pyproject.toml` `version` from `0.1.0` to `0.3.0`, matching
  `CLEW_VERSION` in `clew/pipeline.py`. Going forward the package version and
  schema/record version move together.

**Non-goals (deliberate):**

- `.gitignore` — the full GitHub Python template stays; harmless and standard.
- `results/` — committed evidence artifacts for the submission; untouched.
- Code restructuring — `dataflow.py` (1066 lines) is large but cohesive and
  heavily documented; splitting it is out of scope for a
  formatting/organization pass.
- Pre-commit hooks / CI — not in this pass.

## Verification

- Offline `pytest` suite green after each stage and at the end.
- `ruff check .` and `ruff format --check .` clean.
- Zero grep hits for any old doc path (`week_04_bn_dataflow`,
  `docs/context/`, moved filenames) outside `docs/notes/`.
- All relative links in README and reader-facing docs resolve to existing
  files.

## Suggested staging (one commit per stage)

1. Ruff config + one-time lint/format pass.
2. Docs moves + reference updates.
3. README rewrite + `original-plan.md` extraction.
4. Metadata: CLAUDE.md commit + version sync.

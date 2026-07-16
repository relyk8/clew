# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Clew is

Clew is a per-sample candidate-extraction pipeline for environment-sensitive
malware analysis. It runs once over a PE32 sample and emits a structured JSON
record of candidate API return/argument values that a downstream fuzzer
(Pfuzzer) uses as seeds to reach evasion-gated execution paths. It replaces
Pfuzzer's hand-coded, sample-agnostic retarget lists with candidates derived
from the binary itself. Target for a DefCon submission as a standalone tool.

The output contract lives in two files that everything else produces against:
`docs/schema.md` (human-readable, field-by-field) and
`schema/clew_record.schema.json` (machine-checkable JSON Schema). Read
`docs/schema.md` before touching any code that emits or consumes records.

## Commands

```bash
# Install (editable, with dev + analysis extras)
pip install -e '.[dev,analysis]'

# Run the full static pipeline over a sample (capa rules/sigs default to the
# AFIT cluster paths; override with $CLEW_CAPA_RULES / $CLEW_CAPA_SIGS)
python -m clew.pipeline tests/fixtures/al-khaser_x86.exe -o /tmp/al.clew.json

# There is no console-script entry point; the CLI is `python -m clew.pipeline`.

# Offline test suite (no BN license, no capa rules — the default CI-able set)
pytest

# A single test / file
pytest tests/test_pipeline.py::test_assemble_record_envelope
pytest tests/test_pipeline.py
```

### Test gating (important)

Most tests are **offline and run against saved intermediate JSON fixtures**
(`tests/fixtures/*.bn_callsites.json`, `*.floss.json`, `*.capa.json`). The
expensive/licensed tests are skipped unless you opt in via environment
variables:

- `BN_INTEGRATION=1` — enables the slow, licensed real Binary Ninja analysis
  tests (`tests/test_bn_callsites.py`, `tests/test_oracle_grade.py`). Needs a
  BN Enterprise license and the fixture `.exe` present.
- `CAPA_RULES_PATH` + `CAPA_SIGS_PATH` — enables capa integration tests
  (`conftest.py::capa_paths`).
- Tests also `pytest.skip` when a fixture file hasn't been generated, so a
  clean checkout runs a reduced-but-green suite.

There is **no live end-to-end pytest** (it would need capa rules/sigs and a BN
license simultaneously). Drive the pipeline via the CLI, then grade its output
against the hand-built oracles with `tests/test_oracle_grade.py`.

## Architecture

### The channel model

Work is organized as numbered **channels**, each owning a disjoint slice of a
record. This separation is load-bearing — respect it when editing:

- **Channel 0 (capa)** — `clew/channels/capa.py`: sample-level technique
  detection. Feeds `capa_techniques` and (via `tiers.py`) `derivation_status`.
- **Channel 1 (FLOSS)** — `clew/channels/floss.py`: string *values* (static,
  stackstring, tightstring, decoded). Never call sites.
- **Channel 2 (Binary Ninja)** — call *sites* and the dataflow that joins them
  to values. Split into two units:
  - `clew/channels/bn_callsites.py` (Unit 3): enumerate every Windows-API call
    site, classify `api_resolution` (`import`/`getprocaddress`/`ordinal`).
  - `clew/analysis/dataflow.py` (Unit 4): the MLIL-SSA **bridge** — for each
    call site, trace arguments backward through SSA def-use chains to string
    constants, corroborating against FLOSS. This is the research core.
- **Channel 4 (DynamoRIO cmp-logging, inside CAPE)** and **Channel 5 (CAPE
  config extractors)** are dynamic/runtime and not yet integrated into the
  static pipeline. `clew/cape_client.py` and `clew/novelty.py` are the CAPE
  submission/validation helpers reused from the AriadneX repo.

### The pipeline and the "intermediate record" boundary

`clew/pipeline.py` is the static-side orchestrator (`run_static_pipeline`). Its
single most important design property:

- **Binary Ninja analyses the sample exactly once.** The view is opened and
  `update_analysis_and_wait()`-ed inside one Enterprise `LicenseCheckout`, and
  both Unit 3 (`enumerate_with_view`) and Unit 4 (`bridge_with_view`) run on
  that shared view. Never reintroduce a second `update_analysis_and_wait` pass.

The pipeline emits an **intermediate record**, not a schema-complete one. It
fills every statically-available field but deliberately leaves three
candidate fields absent: `evasion_tier`, `iteration_number`, and
`coordination_constraint` (owned by a downstream *derivation* stage), plus the
Channel-4 comparison operands. A record only validates against the schema after
that derivation stage adds those fields. `assemble_record()` is a pure function
with no heavy imports — keep it that way so it stays offline-testable.

When editing code near this boundary, consult `clew/analysis/oracle_grade.py`:
it encodes exactly which fields are **bridge-owned (graded)** vs.
**derivation/Channel-4-owned (report-only, never a failure)**. Do not make the
bridge emit derivation-owned fields.

### Degradation model

capa and FLOSS are **enrichment**: on failure the pipeline degrades rather than
aborts (capa error → `derivation_status = "no_capa_signal"`, empty techniques;
FLOSS error → empty `FlossIndex`, BN-only static strings). Binary Ninja is the
**core** channel — its errors propagate.

### FLOSS caching and determinism

FLOSS emulation (stack/tight/decoded strings) is nondeterministic on
adversarial code and slow (~10 min on al-khaser); its static strings are
deterministic. To make runs reproducible, FLOSS output is cached under
`.floss_cache/` (on by default). The cache **key** — sample sha256 + FLOSS
version + min_length + a content-shape sigs fingerprint + category flags — is
what guarantees correctness. A key *mismatch* raises `FlossCacheStale` and
**halts the run** (exit 2) rather than silently using stale strings; a *missing*
entry is a clean miss. Regenerate intentionally with `--refresh-floss-cache`,
or bypass with `--no-cache`. `FlossCacheStale` is deliberately not a
`FlossError` so the degradation path cannot swallow it.

Residual BN nondeterminism on anti-analytic code is measured, bounded (<1%),
and outside every validated case — see the reproducibility sections of
`docs/static_pipeline.md` and `docs/bn_dataflow.md`.

## Version pinning

Reproducibility rests on pinned inputs; each producing module records its pins:

- Binary Ninja core `4.2.6455 Ultimate` — `BN_PINS` in `bn_callsites.py`.
- capa `9.4.0`, capa-rules `be59710a`, sigs `46188228` — `CAPA_PINS` in
  `capa.py`. Bump all three together; mismatches silently change which rules fire.
- FLOSS `3.1.1` — pinned per-sample by the result cache.
- Schema / `clew_version` `0.3.0` — `CLEW_VERSION` in `pipeline.py`.

## Where to read next

- `docs/schema.md` — the record contract (read first).
- `docs/static_pipeline.md` — the orchestrator in depth (this is the canonical
  architecture doc; the module docstrings are unusually thorough too).
- `docs/bn_dataflow.md` — the dataflow bridge internals and the
  reproducibility investigation.
- `docs/evasion-taxonomy.md` — the defeatability-tier taxonomy (distinct
  from `derivation_status`, which is a pipeline-progress categorical, not a tier).
- The strawman schema and 12-week project plan live in `README.md`; note the
  actual layout diverged from its "Proposed repo structure" (`clew/channels/`
  not `clew/extractors/`, `pipeline.py` orchestrates directly).

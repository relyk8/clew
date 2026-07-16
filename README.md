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
  Copy `.env.example` to `.env`, fill in your paths, and load it
  (`set -a; source .env; set +a`). The built-in defaults are placeholders and
  will not exist on a fresh checkout.
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
clew tests/fixtures/al-khaser_x86.exe -o /tmp/al.clew.json
```

Installing the package provides the `clew` console command (entry point
`clew.cli:main`); `python -m clew.pipeline` is an equivalent alias. The pipeline
logs per-stage progress to stderr as it runs — add `-v` for debug detail or `-q`
to quiet it to warnings/errors. `clew --help` lists all options.

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
- `docs/floss.md` — Channel 1: FLOSS string extraction.
- `docs/bn_callsites.md` — Channel 2 / Unit 3: Binary Ninja call-site enumeration.
- `docs/bn_dataflow.md` — Channel 2 / Unit 4: the dataflow bridge internals and reproducibility investigation.
- `docs/evasion-taxonomy.md` — the defeatability-tier taxonomy.

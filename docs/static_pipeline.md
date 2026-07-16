# The clew static pipeline

`clew/pipeline.py` is the static-side orchestrator. It runs clew's three static
channels over one sample and assembles a single, sample-level *intermediate*
clew record: capa (Channel 0/1) for technique classification, FLOSS (Channel 1)
for string recovery, and Binary Ninja (Channel 2 -- Unit 3 call-site
enumeration plus Unit 4 the dataflow bridge) for the evasion-check candidates.
It is the entry point that turns "a PE on disk" into "the static portion of a
clew record, ready for the derivation stage."

This document covers the orchestrator specifically. The Unit 4 dataflow bridge
it drives is documented separately in `bn_dataflow.md`; that record
covers the MLIL-SSA walk, resolution cases, confidence model, the derivation
boundary, and the reproducibility investigation in detail. Read this document
for how the channels are wired together and how to run the pipeline; read
`bn_dataflow.md` for what the bridge does internally.

## What it produces

The pipeline emits one intermediate clew record per sample. "Intermediate"
because the static channels fill only the fields they own, leaving the
derivation stage (Person B) and Channel 4 to complete each candidate. Concretely
the record carries the sample-level envelope -- `sample_sha256`, `sample_path`,
`clew_version`, `capa_techniques`, `derivation_status`, `total_iterations`
(always 1 in v1) -- and a `candidates` array. Each candidate is exactly the
bridge's `to_partial_candidates()` output: call site, API identity, parameter
index, recovered values, and evidence (string source, VA, dataflow path,
channels), with the three derivation-owned fields (`evasion_tier`,
`iteration_number`, `coordination_constraint`) and the Channel-4 comparison
operands deliberately absent. This is the same boundary the oracle grader
validated against hand-built ground truth (see `bn_dataflow.md`): a
bridge candidate plus those three fields is a schema-valid candidate, and the
pipeline's own test suite confirms the assembled record validates against
`schema/clew_record.schema.json` once a simulated derivation stage adds them.

On the al-khaser reference fixture the pipeline produces ~967 candidates, ~271
of them resolved to concrete values, with `derivation_status = partially_derivable`
and 25 capa evasion techniques.

## Architecture: one analysis, three channels

The load-bearing design decision is that Binary Ninja analyses the sample
**exactly once**. Unit 3 (enumeration) and Unit 4 (the bridge) each used to open
and analyse their own `BinaryView`, which meant two `update_analysis_and_wait()`
passes -- and on a ~600 KB sample that is roughly two minutes, doubled. The
pipeline instead opens one view inside one Enterprise license checkout, analyses
it once, and runs both units on that shared view via their `*_with_view`
entry points:

- `bn_callsites.enumerate_with_view(bv, ...)` -- Unit 3 against an
  already-analysed view (the shared-view companion to `run_bn_callsites`).
- `dataflow.bridge_with_view(bv, call_sites, floss_index)` -- Unit 4 against the
  same view.

A useful consequence of the bridge's design removes what would otherwise be a
merge step: Unit 4 already emits a record for *every* schema-emittable call site
-- resolved ones with values, unresolved ones as located stubs -- so
`to_partial_candidates(include_unresolved=True)` already spans all call sites.
The pipeline's candidate list is just that call; there is no separate "reconcile
Unit 3 stubs with Unit 4 output" pass.

capa and FLOSS run as ordinary subprocess/library calls outside the license
checkout; only the Binary Ninja stage needs the checkout. The three stages are
independent up to the point of assembly: capa yields `capa_techniques` and
`derivation_status`, FLOSS yields the `FlossIndex` that the bridge consumes for
corroboration, and Binary Ninja yields the candidates. `assemble_record()` --
a pure function with no heavy imports, fully offline-testable -- wraps them in
the record envelope.

## Stage 1: capa (Channel 0/1)

capa is run via `channels/capa.run_capa(sample, rules_path=, sigs_path=,
capa_bin=)`, returning a `CapaResult` (`rule_names`, `rule_matches`, `raw`). The
pipeline derives two things from it. The evasion technique list is
`filter_evasion_techniques(capa_result.rule_names, capa_result.raw["rules"])` --
capa's own rule metadata (namespace `anti-analysis/...`, plus a small override
set) decides which matched rules count as evasion techniques. The
`derivation_status` categorical comes from `tiers.classify(...)`, which rolls
per-rule actionability (is the rule in `CAPA_RULE_TO_APIS`, and are its implied
APIs all in the pfuzzer-68 set) up to one of four sample-level buckets:
`fully_derivable`, `partially_derivable`, `not_derivable`, `no_capa_signal`.

capa is enrichment, so the stage degrades rather than fails: any `CapaError`
(binary missing, run failure, parse failure, timeout) is caught and the record
gets `derivation_status = "no_capa_signal"` with an empty technique list -- the
same operational outcome as a sample where zero anti-analysis rules fired.

capa provenance is pinned and verifiable: capa 9.4.0, with capa-rules at commit
`be59710a` (`v9.4.0+2`, 2026-05-07), recorded in `capa.py`'s `CAPA_PINS`. See
the runbook below for the one-time `git safe.directory` step needed to verify
the rules checkout on the shared cluster.

## Stage 2: FLOSS (Channel 1)

FLOSS is run via `channels/floss.run_floss(sample, sigs_path=)`, returning a
`FlossResult`, which the bridge consumes as a `FlossIndex` built by
`FlossIndex.from_floss_result()`. The index serves two roles inside the bridge:
static FLOSS strings *corroborate* BN-recovered static values (lifting them from
`["bn_xref"]`/0.7 to `["bn_xref","floss"]`/0.9), and obfuscated strings
(stack/tight/decoded), keyed by their decoding/containing function, supply
values for arguments BN cannot resolve statically. On al-khaser this yields ~336
FLOSS-corroborated values across the record. FLOSS is optional enrichment: if it
fails (`FlossError`), the stage falls back to `FlossIndex.empty()` and the bridge
proceeds BN-only.

Two operational concerns are handled in this stage, both of which surfaced
during integration and are worth understanding.

### FLOSS result caching

FLOSS's string *emulation* (the stack/tight/decoded categories) is
nondeterministic on adversarial code -- the emulator makes slightly different
progress run-to-run through anti-disassembly -- and it is slow (~10 minutes on
al-khaser). Its *static* strings (the bulk, ~3900 on al-khaser) are
deterministic and cheap. To make the pipeline reproducible and fast on re-runs,
FLOSS output is cached.

The cache is **on by default** under `.floss_cache/` (override with
`--floss-cache DIR`, disable with `--no-cache`). Each entry is two files: the
raw FLOSS output as native `floss -j` JSON (`{sha}.floss.json`, written via
FLOSS's own `floss.render.json.render` and read back via
`floss.results.read`/`load_floss_results`, so no pydantic coupling and the file
is inspectable with any FLOSS tooling), plus a key sidecar (`{sha}.floss.key.json`)
recording the full cache key for audit.

The cache **key** is what guarantees correctness: `sample_sha256` + FLOSS
version + `min_length` + signatures identity + the enable-category flags. The
signatures identity is a hash of the sigs directory's sorted (relative-path,
size) pairs -- deliberately *not* mtime (a `git checkout` or `cp -p` changes
mtime without changing bytes, and must not trigger a false stale) and *not* the
path string (edited sigs at the same path must trigger one). Bundled sigs use a
`"bundled"` sentinel, which is safe because a FLOSS upgrade changes the FLOSS
version already in the key.

Lookup is strict about the difference between a miss and a stale entry, because
a stale hit silently poisoning downstream candidates is worse than no cache. No
entry present is a clean **miss** (run FLOSS, write the entry). A present entry
whose stored key matches is a **hit** (load the JSON, skip FLOSS entirely --
fast and silent). A present entry whose key *disagrees* is **stale**: it raises
`FlossCacheStale`, naming exactly which key field changed, and halts the run
(exit code 2 from the CLI) rather than using stale strings. `--refresh-floss-cache`
forces a re-run and overwrite for when the change is intended (e.g. after a
deliberate FLOSS upgrade). The miss-vs-stale logic and the field-naming on
mismatch are covered by the offline test suite.

For thesis reproducibility the intended workflow is to generate the cache once
and archive it alongside results: re-runs are then fast, silent, and reuse
byte-identical FLOSS output. (Caching makes results *reproducible* -- identical
after the first run -- not *canonical*; a different first run would have cached
slightly different emulated strings. That is standard for nondeterministic
analysis and worth one sentence in a methods section.)

### FLOSS log suppression

vivisect/FLOSS emit their emulator griping -- `parseOpcode error`, `Emulator
prehook failed`, `hook failed to restore PC`, incomplete-CFG warnings -- via the
standard logging tree, and on adversarial code this is hundreds of lines of
expected noise. The pipeline suppresses it with a scoped context manager
(`_quiet_floss_logging`) that raises the relevant logger trees (`floss`,
`vivisect`, `viv_utils`, `envi`, `viv`, `vtrace`, `Elf`, `PE`) to `ERROR` around
the `run_floss` call and restores them afterward. Two deliberate properties:
the suppression is *scoped* to those named trees (not `logging.disable`, which
would also silence capa, BN, and clew's own logging), and it uses `ERROR` rather
than full silence so genuine FLOSS errors remain visible. `viv_utils` is named
explicitly because it is a separate package from vivisect (FLARE's emulation
driver) and does not inherit the `vivisect` logger. `--verbose-floss` restores
the full output when debugging FLOSS itself.

## Stage 3: Binary Ninja (Channel 2)

The Binary Ninja stage opens the view once inside `LicenseCheckout`, analyses
it, runs `enumerate_with_view` (Unit 3) then `bridge_with_view` (Unit 4) on that
one view, wraps the result in a `BNDataflow`, and returns
`to_partial_candidates(include_unresolved=...)`. `run_license_checkout=False`
(CLI `--no-license-checkout`) assumes a license is already checked out for the
process. Binary Ninja is the core channel, not enrichment, so its errors
propagate rather than degrading to an empty result. The BN core version is
pinned at `4.2.6455 Ultimate` (`BN_PINS` in `bn_callsites.py`); on al-khaser the
stage finds 884 call sites.

`include_unresolved` defaults to `True`. The unresolved call sites -- API calls
the bridge located but could not statically resolve a value for, including
return-value checks like `IsDebuggerPresent` -- are precisely Channel 4's work
list, so dropping them would lose that hand-off. `--exclude-unresolved` omits
them if a consumer wants only resolved candidates.

## The intermediate record and the boundary

The record `assemble_record()` produces is deliberately incomplete in a precise
way. The pipeline fills every sample-level field that is statically available
(including `derivation_status`, which is a capa rollup and therefore
static-time) and every bridge-owned candidate field. It leaves the three
derivation-owned candidate fields absent. One schema detail worth recording for
the derivation stage: `coordination_constraint` is a *required object*
(`{gate_group_id, description}`, both nullable) -- the "no constraint" case is
that object with null fields, not `null` -- so derivation must always emit it.

## Reproducibility summary

The bridge and enumeration are deterministic; residual run-to-run variance is
confined to enrichment (FLOSS, pinned by caching) and to Binary Ninja's analysis
of deliberately anti-analytic code. The BN variance is measured, bounded (<1%:
roughly 7 of ~967 candidates, 2 of ~271 resolved), confined to al-khaser's
obfuscated `0x0047xxxx` region, and outside every validated case (the twelve-DLL
indicator loop resolves 12/12, `IsDebuggerPresent` is located, both oracles pass
on every run). Pinning `analysis.limits.workerThreadCount` to 1 stabilises
candidate *membership* but not all field-level content; it is offered as a knob,
not a default. The full investigation -- what was ruled out (clew's code, Python
hash order, function discovery) and what remains -- is in
`bn_dataflow.md`'s reproducibility section. The pragmatic v1 stance is to
report results with the measured variance bound stated.

## Running it

With `$CLEW_CAPA_RULES` / `$CLEW_CAPA_SIGS` set (see `.env.example`), the common
invocation needs only a sample:

```
clew tests/fixtures/al-khaser_x86.exe -o /tmp/al.clew.json
```

The entry point is `clew/cli.py` (installed as the `clew` console command;
`python -m clew.pipeline` is an equivalent alias). `cli.py` owns argument parsing
and logging setup; the analysis is `clew.pipeline.run_static_pipeline`.

Without `-o` the record JSON goes to stdout; with `-o` a one-line summary
(candidate counts, `derivation_status`, technique count) goes to stdout and the
record to the file. Per-stage progress (capa → FLOSS → Binary Ninja, with
elapsed timings and FLOSS cache status) is logged to stderr via the `logging`
module, keeping stdout clean for piping.

Flags: `--capa-rules DIR` / `--capa-sigs DIR` (default to `$CLEW_CAPA_RULES` /
`$CLEW_CAPA_SIGS`, then placeholder paths); `--floss-sigs DIR` (default: FLOSS's
bundled sigs); `--capa-bin` (default `capa`); `--floss-cache DIR` /`--no-cache`
/`--refresh-floss-cache` (FLOSS caching); `--verbose-floss` (unsuppress emulator
logging); `--exclude-unresolved` (omit the Channel 4 work list);
`--no-license-checkout` (a license is already held); `-v/--verbose` (debug
logging, repeatable) / `-q/--quiet` (warnings and errors only).

### Site setup (capa rules/sigs)

The built-in defaults are placeholders (`/path/to/capa-rules`,
`/path/to/capa-src/sigs`) that won't exist on any machine. Point them at a real
checkout by setting `CLEW_CAPA_RULES` and `CLEW_CAPA_SIGS` — copy `.env.example`
to `.env` and load it (`set -a; source .env; set +a`), or export them in the
shell profile. capa 9.4.0 ships its sigs in its source tree, not the installed
package.

The AFIT cluster layout is one such site config: capa-rules at
`$CLEW_CAPA_RULES` (a root-owned git checkout), capa sigs at `$CLEW_CAPA_SIGS`.
When capa-rules is owned by another user, git refuses to read it until it is
marked trusted. To verify the pinned ruleset:

```
git config --global --add safe.directory "$CLEW_CAPA_RULES"
git -C "$CLEW_CAPA_RULES" rev-parse HEAD   # be59710a...
```

## Testing

Offline tests (`tests/test_pipeline.py`, no BN or license) cover the pure
assembly (`assemble_record` envelope, input copying, `include_unresolved`),
`sha256_file`, the FLOSS log-suppression context manager (scoped, restores on
exception, does not touch other loggers), the FLOSS cache key/sigs-identity and
the miss-vs-stale safety logic, the capa path defaults (env-overridable), and a
schema-validation test that assembles the record, adds the derivation-owned
fields, and validates against `schema/clew_record.schema.json` -- confirming the
pipeline emits exactly the intermediate shape the boundary calls for. The
capa/tiers glue test is guarded on `clew.channels.capa`/`clew.tiers` and runs
where those exist. There is no live pipeline pytest (it needs capa rules/sigs
and a BN license); drive the pipeline via the CLI, and grade its output against
the oracles via `tests/test_oracle_grade.py` (BN-gated).

## Provenance and pins

The static pipeline's reproducibility rests on pinning every input:

- Binary Ninja core `4.2.6455 Ultimate` (`BN_PINS`, `bn_callsites.py`).
- capa `9.4.0`; capa-rules `be59710a` (`v9.4.0+2`, 2026-05-07;
  `CAPA_PINS["capa_rules_tag"]`, `capa.py`), verifiable via `git rev-parse`.
- capa sigs from the capa `9.4.0` source tree.
- FLOSS `3.1.1`, output pinned per-sample via the `.floss_cache/` result cache.
- clew record schema `v0.3.0`; `clew_version` `0.3.0`.

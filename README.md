# Clew — Pilot Study and Tech Setup

This document walks through the work for the first two weeks: locking the output schema, acquiring fixture samples, running a single-channel pilot on each of the five extraction channels, and writing the proposal. Every section below is concrete work to do — what to install, what to run, what to confirm — not a plan to negotiate.

## What Clew is

An automated per-sample candidate extraction pipeline for environment-sensitive malware analysis. Clew runs once per PE32 sample and emits a structured set of candidate API return values that downstream fuzzers use as seeds for exploring hidden execution paths. It replaces Pfuzzer's hand-coded, sample-agnostic retarget value lists with per-sample candidates derived from the binary itself.

DefCon submission is Clew as a standalone tool. AriadneX (the Gym/RL work) is parked in a separate repo.

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

## The five channels

Collapsed from the brainstorm's six — Channel 3 absorbed into Channel 2, Channel 6 (LLM) removed.

| # | Channel | What it produces |
|---|---|---|
| 0 | capa preprocessing | Per-sample list of detected evasion techniques and tier classification |
| 1 | FLOSS (static strings) | Plaintext and deobfuscated strings with VA and source category |
| 2 | Binary Ninja (imports + call-site xrefs + dataflow bridge + nearby constants) | Per-call-site records linking APIs to the parameter values they're compared against |
| 4 | DynamoRIO comparison logging (runs inside CAPE) | `cmp`/`test` operands observed after API returns during one baseline detonation |
| 5 | CAPE config extractors | Family-specific config data (C2 IPs, keys) for known families |

Channel 3 from the brainstorm (binary constants near call sites) is an enrichment step on Channel 2's output, not a standalone channel.

## Reusable from AriadneX repo

None of this is Clew code. Two components are reusable when Channel 4 or validation work reaches the point of needing CAPE detonations:

- `CapeClient` from `ariadne_env.py` — submits binaries to CAPE, polls, fetches reports.
- `novelty.py` — `extract_iocs`, `noise_filtered_novelty`, stable-baseline logic. Reusable for validating that extracted candidates actually unlock hidden behavior.

## Days 1–2 — Schema lock

The schema is the contract every channel produces against. It goes first because the alternative — picking the schema to fit whatever FLOSS and Binary Ninja naturally emit — leaves integration problems for week four that are cheap to prevent on day one.

### Deliverables

Create a new `clew/` repo with the following two files. No channel code yet.

**`docs/schema.md`** — human-readable, field-by-field description of the output format. Every field gets a paragraph explaining what it represents, what values are valid, and what it looks like in practice. Include at least two full example records: one for a straightforward string-comparison case (like `GetModuleHandleW("SbieDll.dll")`) and one for a dynamically-resolved API case (like a `GetProcAddress` result being compared).

**`schema/clew_record.schema.json`** — machine-checkable [JSON Schema](https://json-schema.org/). This is what validates every automated channel's output during testing.

### Decisions to resolve in writing during these two days

These are the design questions the schema has to encode. Each one is an hour or two of whiteboard work; don't start the JSON Schema file until they're settled.

1. **How dynamically-resolved APIs are represented.** The `api_resolution` enum — what values does it take? At minimum: `import`, `getprocaddress`, `ordinal`. Decide whether `hashed` belongs (API name hash tables, FormBook-style) or whether those cases are scoped out of v1.

2. **How stackstrings differ from static strings.** FLOSS recovers strings constructed on the stack at runtime. These don't have a stable rdata VA the way static strings do — they only exist in the context of a specific function's stack frame. The `evidence.string_source` enum needs to distinguish `static`, `stackstring`, `tightstring`, and `decoded`, and the `string_va` field needs to be nullable or replaced by a function-context identifier for stackstring cases.

3. **What a gate group is and how it's represented.** When two environment checks are AND-gated (for example, "proceed only if not in a VM AND not in a debugger"), the downstream fuzzer needs to know to flip both at once, not one at a time. Decide what structural information `coordination_constraint` carries — at minimum a `gate_group_id` string that's shared across co-gated candidates, plus human-readable `description`. Static identification of gate groups is hard and v1 may punt on it entirely, but the schema field has to exist now so that v2 can populate it without a schema break.

4. **How to encode iteration readiness.** Every candidate record carries `iteration_number`. In v1 this is always `0`. Top-level `total_iterations` is always `1`. The schema accepts these fields from day one so that v2 can fill them without breaking consumers.

### Strawman

Reproduced for convenience. Refine during the two days; this is not what you submit.

```json
{
  "sample_sha256": "...",
  "sample_path": "...",
  "clew_version": "0.1.0",
  "capa_techniques": ["anti-vm", "anti-debug", "check-for-sandbox"],
  "tier_classification": "tier_1",
  "total_iterations": 1,
  "candidates": [
    {
      "call_site_va": "0x401234",
      "function_va": "0x401200",
      "api_name": "GetModuleHandleW",
      "api_resolution": "import",
      "parameter_index": 0,
      "comparison_operator": "equality",
      "evasion_tier": "tier_1",
      "iteration_number": 0,
      "candidate_values": [
        {
          "value": "SbieDll.dll",
          "represents": "sandbox_detected",
          "retarget_to": null,
          "confidence": 0.9,
          "source_channels": ["floss", "bn_xref"]
        }
      ],
      "coordination_constraint": {
        "gate_group_id": null,
        "description": null
      },
      "evidence": {
        "channels": ["floss", "bn_xref"],
        "string_source": "static",
        "string_va": "0x404020",
        "dataflow_path": ["0x401220", "0x401228", "0x401234"],
        "cmp_operand_a": null,
        "cmp_operand_b": null
      }
    }
  ]
}
```

## Days 3–4 — Fixture acquisition and hand-built records

Without ground truth, no channel pilot can be evaluated as pass or fail. These two days produce that ground truth.

### Deliverables

- Three to five evasive PE32 samples from Pfuzzer's public dataset (or another public evasive-malware corpus with documented environment checks).
- For each sample, an expected-output JSON file matching the schema — produced by hand, by reading the sample in Binary Ninja yourself.

### Work

1. **Pick fixture samples.** Go to Pfuzzer's GitHub repository ([github.com/Sap4Sec/pfuzzer](https://github.com/Sap4Sec/pfuzzer)) and find samples where the paper documents which environment checks the sample performs. The best fixtures are ones where the Pfuzzer authors name specific API calls and comparison values — this gives a concrete target for what Clew must extract. Aim for a spread: at least one sample with string-comparison checks (easy case), at least one with numeric-threshold checks (like CPU count), and at least one with dynamically-resolved APIs.

2. **Resolve sample licensing.** Confirm what can be redistributed. Pfuzzer's repo samples are typically public; expected-output JSON files you write yourself are your own work. If sample redistribution is restricted, the `tests/fixtures/` directory should hold only the sha256 hashes and expected JSON, with a README explaining how to source the binaries.

3. **Set up Binary Ninja for manual analysis.** Install BN (commercial license required for headless, which is separate from interactive use — you already have access). Open each fixture sample.

4. **Produce hand-built records, one sample at a time.** For each sample:
   - Identify every API call site involved in environment checks (the Pfuzzer paper tells you where to look for the samples it documents).
   - Read the surrounding code to determine: what parameter carries the check value, what string or numeric constant it's compared against, what the comparison operator is, what the "clean" vs "detected" outcomes are.
   - Write this out as a JSON file matching the schema from Days 1–2. File naming: `tests/fixtures/<sha256_short>.expected.json`.

These hand-built records are the gradeable target for every pilot that follows. If FLOSS on Day 6 recovers the string `SbieDll.dll` and the hand-built record lists `SbieDll.dll` as a candidate value, the pilot passes for that sample.

Updated 2026-04-29: completed 2 al-khaser-derived fixtures (1fe91674eb8d_01.expected.json for IsDebuggerPresentAPI, 1fe91674eb8d_02.expected.json for the 12-DLL loaded_dlls loop) covering the structural shapes the schema needs to validate. Real-malware fixtures (originally planned for Pfuzzer-corpus samples) deferred to Channel 2 evaluation phase — initial sourcing attempts revealed that hand-built ground-truth oracles aren't tractable for samples with helper-router patterns (Delphi RTL, Pony stealer's dispatch), and the schema itself doesn't need real malware to be exercised. See git log of tests/fixtures/SOURCES.md for samples evaluated and rejected.

### Open items to close during Days 1–4

Don't let these drift past Day 4:

1. **32-bit only or 32+64?** Most modern malware is 64-bit. Supporting both adds BN work but is probably required. Default: both. Confirm fixtures include at least one 64-bit sample.
2. **Packed sample handling.** Assume pre-unpacked for v1, document the limitation. Confirm fixtures are either not packed or have known pre-unpacked versions.
3. **Binary Ninja license for distribution.** Affects how the public release is packaged. Not a v1 blocker but settle the answer before DefCon submission.

## Days 5–9 — Pilot study, one channel per day

The goal is not to build the channel — just to confirm it runs at all, against at least one fixture, and that the tooling is compatible with this machine. If a pilot succeeds, you've de-risked that channel for the 12-week schedule. If a pilot fails, the proposal's risks section accounts for it with a workaround or scope reduction.

One day reserved at the end (Day 9) to absorb whichever channel runs long.

### Day 5 — capa preprocessing pilot

capa is Mandiant's tool for identifying capabilities in a binary. Used in Clew as the preprocessing step that decides which other channels are worth running for each sample, and produces the tier classification.

**Install.**

```bash
pip install flare-capa
```

**Run against all fixtures.**

```bash
capa --json <fixture.exe> > fixtures/<sha256>.capa.json
```

**Confirm.** The output JSON should list rules matched for each fixture. For fixtures the Pfuzzer paper documents as containing anti-VM or anti-debug checks, capa should identify those techniques. If capa finds zero evasion techniques in a sample the paper says is evasive, flag it — this means the sample uses techniques capa doesn't cover and Clew will have to depend on Channels 1, 2, and 4 to find them.

**Keep.** Save one capa output JSON per fixture. These become regression targets for the eventual `clew/preprocess/capa_runner.py`.

### Day 6 — FLOSS pilot

FLOSS is Mandiant's tool for extracting obfuscated strings from malware — static strings, stackstrings, tightstrings, and strings recovered via limited emulation.

**Install.**

```bash
pip install flare-floss
```

**Run against one fixture.** Start with the string-comparison fixture from Day 4.

```bash
floss --json <fixture.exe> > fixtures/<sha256>.floss.json
```

**Confirm.** At least one string from that fixture's hand-built expected JSON should appear in FLOSS's output. Check the `strings.static_strings`, `strings.stack_strings`, `strings.tight_strings`, and `strings.decoded_strings` sections.

**Document.** If FLOSS takes more than ten minutes per sample, note it. If it crashes on any fixture, note the sample's characteristics (packed? unusual section names?). These become entries in the proposal's risks section.

### Day 7 — Binary Ninja headless pilot

This is the smallest possible version of Channel 2: load a fixture, enumerate imports, walk MLIL for one specific function known to contain an environment check, confirm the call site from the hand-built record is identifiable. No dataflow bridge yet.

**Set up BN headless.**

```bash
pip install binaryninja  # inside BN's Python environment
```

BN headless requires a commercial license with headless enabled; confirm this is active for this install before burning time debugging.

**Write a short script.**

```python
import binaryninja

with binaryninja.open_view("<fixture.exe>") as bv:
    # List imports
    for sym in bv.get_symbols_of_type(binaryninja.SymbolType.ImportedFunctionSymbol):
        print(f"{hex(sym.address)}  {sym.name}")

    # Find the call site from the hand-built record
    target_api = "GetModuleHandleW"
    for ref in bv.get_code_refs(bv.get_symbol_by_raw_name(target_api).address):
        print(f"call site: {hex(ref.address)}  in function {hex(ref.function.start)}")
```

**Confirm.** The script's "call site" output should include the address listed in the hand-built record's `call_site_va` field. If it doesn't, investigate whether the hand-built record's address is wrong or BN's reference analysis missed it.

**Walk MLIL for one function.** Pick the function containing that call site and print its MLIL instructions:

```python
func = bv.get_function_at(ref.function.start)
for insn in func.mlil.instructions:
    print(insn)
```

This is purely a sanity check that BN's MLIL is usable for the dataflow work coming in weeks 5–7.

### Day 8 — DynamoRIO comparison logging pilot inside CAPE

The riskiest channel. Confirms the infrastructure works before you commit to Channel 4 being in scope. Channel 4 runs inside CAPE via REST API submission, not a separate DBI sandbox.

**Option A — drcov first.** drcov is the coverage client that ships with DynamoRIO. It produces basic block coverage, not `cmp` operands, but running it first confirms that DynamoRIO can be invoked inside CAPE's analysis VM at all — which is the thing most likely to fail.

1. Install DynamoRIO on the CAPE analysis VM. Download from [dynamorio.org](https://dynamorio.org/), extract to `C:\dynamorio` in the guest snapshot.
2. Confirm `drrun.exe -c drcov.dll -- <target.exe>` works inside the guest manually.
3. Submit a fixture to CAPE with options that instruct CAPE's analyzer to launch the target under `drrun`. Check CAPE's `exe.py` analysis package or write a custom package variant that wraps the launch.
4. Fetch the resulting `.log` file from the CAPE report and confirm it contains basic block records.

**Option B — custom cmp-logging client.** Once drcov works, the cmp-logging client is a DynamoRIO client DLL that hooks `cmp` and `test` instructions after specified API returns. Writing this from scratch is multiple days of work and is out of scope for the pilot. For Day 8, the pass criterion is: drcov runs inside CAPE and produces a file we can parse. The cmp-specific client is week 8 work.

**Confirm.** drcov log file exists, parseable. Note DynamoRIO's per-sample overhead (expect 3–5x baseline detonation time, which at ~3 min baseline means 10–15 min per Channel 4 run).

**Known risk.** Sophisticated malware detects DynamoRIO. Pfuzzer's paper identifies 19 such samples. Those samples are explicitly out of Clew's scope — document this, don't try to fix it.

### Day 9 — Buffer / Channel 5 pilot

If Days 5–8 all ran clean, use this day for the CAPE config extractor pilot. Otherwise it absorbs overruns from any earlier pilot.

**CAPE config extractor pilot (if time).**

CAPE ships with config extractors for ~300 malware families. They run automatically as part of CAPE's processing pipeline.

1. Submit one fixture to CAPE, let it run through full processing.
2. Fetch the report JSON from `/apiv2/tasks/get/report/<task_id>/json/`.
3. Look for the `CAPE.configs` field in the report.

**Confirm.** Either the field contains family-specific config data (C2 IPs, keys, etc.) or it's empty — meaning the fixture isn't a known family. Both outcomes are fine; Channel 5 only contributes for samples from known families, and the schema already treats it as optional.

## Days 10–12 — Write the proposal

With schema and pilot results in hand, the proposal has concrete substance rather than speculation. Suggested structure:

1. **Problem statement.** Pfuzzer's hand-coded retarget lists, the 5.75% unreachable-sample gap, why per-sample automated extraction is the right answer.
2. **Approach.** Five channels, capa preprocessing, candidate derivation stage, tier classification.
3. **Architecture.** The schema (reference `docs/schema.md` rather than pasting it), pipeline orchestration, the CAPE-integrated model for Channel 4.
4. **Scope.** Explicit tiering. v1 is single-shot; iterative mode is v2 with scaffolding already in the schema.
5. **Evaluation plan.** Benchmark against Pfuzzer on overlapping samples (the 68 APIs). Claim: Clew extracts per-sample candidates that Pfuzzer's hand-coded lists miss.
6. **Pilot results.** One paragraph per channel, citing the Day 5–9 findings. Concrete numbers beat hedged predictions.
7. **Timeline.** The 12-week schedule below.
8. **Risks.** Binary Ninja dataflow complexity, Channel 4 DBI detection, Tier 2 recall ceiling, fixture licensing — whichever of these the pilot exposed as real.

## Days 13–14 — Proposal revision

Buffer for revisions. Don't eat this buffer by starting Binary Ninja work early; genuinely reserve it for writing.

## Twelve-week project schedule

What the proposal's timeline section reflects.

| Weeks | Milestone |
|---|---|
| 1–2 | Schema locked, fixtures chosen, all five channels piloted, proposal submitted |
| 3–4 | FLOSS integration (Channel 1) and BN import/call-site enumeration (Channel 2, structural half) complete with tests against fixtures |
| 5–7 | BN dataflow bridge (Channel 2, the research piece) — trivial case, register reuse, stack spills, stackstrings in that order |
| 8 | capa preprocessing stage and CAPE config integration (Channels 0 and 5); DynamoRIO comparison logging client (Channel 4) complete |
| 9 | Candidate derivation stage (per-API comparison semantics, top ~20 evasion APIs hand-coded) |
| 10 | End-to-end pipeline and CLI; full-fixture end-to-end tests passing |
| 11 | Evaluation against Pfuzzer dataset, benchmark numbers |
| 12 | Writeup, DefCon demo prep |

Weeks 5–7 are the highest-risk stretch. The dataflow bridge is where the actual research lives and where compiler optimizations turn "trivial case" into "three days of rabbit hole." Budget honestly.

## Proposed repo structure

```
clew/
├── clew/
│   ├── __init__.py
│   ├── cli.py
│   ├── pipeline.py
│   ├── derivation.py
│   ├── preprocess/
│   │   └── capa_runner.py
│   ├── extractors/
│   │   ├── floss_extractor.py
│   │   ├── bn_callsites.py
│   │   └── cape_config.py
│   ├── analysis/
│   │   └── dataflow.py
│   ├── dynamic/
│   │   └── drio_cmp_logger.py
│   └── api_knowledge/
│       ├── __init__.py
│       ├── debugger_apis.py
│       ├── module_apis.py
│       └── registry_apis.py
├── schema/
│   └── clew_record.schema.json
├── docs/
│   ├── schema.md
│   ├── proposal.md
│   ├── dataflow_design.md
│   └── api_coverage.md
├── tests/
│   ├── fixtures/
│   │   ├── <sha256>.sha256
│   │   ├── <sha256>.expected.json
│   │   ├── <sha256>.capa.json
│   │   └── <sha256>.floss.json
│   ├── test_capa.py
│   ├── test_floss.py
│   ├── test_bn_callsites.py
│   ├── test_dataflow.py
│   ├── test_drio_cmp.py
│   └── test_e2e.py
├── README.md
└── pyproject.toml
```

## What success looks like at DefCon

A demo where someone hands over an evasive PE32 binary and Clew produces, in a few minutes, a JSON artifact listing the specific environment checks that sample performs and the values to feed back to bypass them. A benchmark table showing Clew extracts candidates Pfuzzer's hand-coded lists miss, on N samples from Pfuzzer's own published dataset.

The contribution claim is precise: Pfuzzer requires hand-coded retarget lists; Clew automates that step per-sample, closing the "if a sample checks for something not on the list, the fuzzer can never find it" failure mode.

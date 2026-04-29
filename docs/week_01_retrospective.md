# Week 1 Retrospective

Days 1-4 of the 12-week Clew plan. Schema and validation harness completed; two hand-built ground-truth fixtures completed; a meaningful set of design decisions resolved.

## Deliverables completed

- **`schema/clew_record.schema.json`** — JSON Schema (draft 2020-12), strict (`additionalProperties: false`), with reusable `$defs` for VA, Tier, Channel, ApiResolution, ComparisonOperator, Represents, StringSource, ScalarValue, ChannelArray, CandidateValue, CoordinationConstraint, Evidence, Candidate. v0.1.0 schema id.
- **`docs/schema.md`** — field-by-field human-readable specification, including two complete normative examples (`GetModuleHandleW("SbieDll.dll")` Sandboxie check; `GetProcAddress`-resolved `IsDebuggerPresent` via stackstring), and a documented "Open questions deferred to v2" section.
- **`tests/test_schema.py`** — pytest harness validating the schema is well-formed, all inline JSON examples in `docs/schema.md` validate, and all `tests/fixtures/*.expected.json` files validate. Auto-discovers fixtures via filesystem glob.
- **`tests/fixtures/1fe91674eb8d_01.expected.json`** — record #1: al-khaser `IsDebuggerPresentAPI`, single candidate, single return-value boolean check.
- **`tests/fixtures/1fe91674eb8d_02.expected.json`** — record #2: al-khaser `loaded_dlls`, single candidate with 12 values, parameter-fingerprint check across heterogeneous evasion types.
- **`tests/fixtures/record_01_candidate.md`**, **`record_02_candidate.md`** — analyst notes documenting source-to-schema mapping, criteria evaluation, schema decisions, and runner-up candidates for each fixture.
- **`tests/fixtures/SOURCES.md`** — fixture provenance manifest, including rejected/deferred samples and their reasons.

End-state pytest output: 5 passed (1 well-formed check, 2 doc examples, 2 fixtures).

## Schema shapes exercised by the fixtures

Record #1 covers: single-candidate, single-value, return-value boolean check (`parameter_index: -1`), no string evidence, two-channel attribution.

Record #2 adds: multi-value `candidate_values` (12 entries), heterogeneous `represents` within one candidate (3 distinct types), `parameter_index >= 0` (input-parameter fingerprint), `string_source: "static"` path, and `string_va: null` as an explicit acknowledgment that v1 cannot represent multi-value VAs.

Together these two fixtures cover the structural axes the schema needs to validate at v1. Further fixtures would exercise variations of these shapes, not new shapes.

## Design decisions resolved

### `parameter_index = -1` as the return-value sentinel

The schema needed to distinguish "the check is on parameter N (a buffer/string passed to the API)" from "the check is on the API's return value." Considered: a separate `check_target` enum, overloading `parameter_index = 0` to mean return value, or using `-1` as an explicit sentinel.

Chose `-1`. Avoids adding an enum field for a single-value distinction. `>=0` is parameter index, `-1` is return. The cost is one minor wart (`-1` is not a "real" index) but it's locally legible.

### `comparison_operator` semantics for return-value checks

Discovered during record #1 BN work: when `parameter_index == -1`, the physical `test`/`cmp`/`jz` instruction lives in the *caller* of the API-wrapping function, not at `call_site_va` itself. The schema's `comparison_operator` needed clarification.

Resolved by adding to `docs/schema.md`: when `parameter_index == -1`, `comparison_operator` describes how a consumer should interpret the return value, not the location of the physical comparison instruction. `equality` means "consider the check fired when the return matches `value`." This is a documentation change, not a schema change — the field's type is unaltered.

### One candidate with N values vs. N candidates AND-gated

Record #2's loop over 12 DLL fingerprints raised: should this be one candidate with 12 values, or 12 candidates linked by `coordination_constraint.gate_group_id`?

Chose one-candidate-N-values. Reasoning:
- Physically there is one `call GetModuleHandleW` instruction in the compiled loop body, executed 12 times. `call_site_va` is therefore one address, not twelve.
- The schema's `candidate_values` array exists for exactly this purpose.
- `coordination_constraint.gate_group_id` is documented as v1-null-only, and its semantic ("all candidates with the same id must be flipped together") implies AND-gating, not the OR-gating that loop-over-array represents. Using it would actively misrepresent the coordination semantics.

### Source channels for hand-built fixtures

Hand-built `expected.json` records aren't produced by Clew channels — they're produced by an analyst reading the binary and recording ground truth. So who do we attribute as the `source_channels` value?

Chose to populate `source_channels` and `evidence.channels` with the channels that *should* find this candidate when Clew runs against the fixture. That makes the oracle double as a channel-grading prediction: a channel "passes" for a record if it produces a candidate matching the oracle's `value` and is listed in the oracle's `source_channels`. For records #1 and #2 that's `["capa", "bn_xref"]` — capa for the rule match (`check for debugger via API`, `check for sandbox files via API`), bn_xref for the call-site identification.

### `evidence.string_va = null` for multi-value candidates

Record #2's 12 fingerprint strings live at 12 different `.rdata` addresses, but the schema has one `string_va` field per candidate. Considered three options: (1) point at the array's base, (2) populate with the first string's VA, (3) emit `null`.

Chose `null`. Options 1 and 2 are misleading — option 1 points at a pointer table (not a string), option 2 conceals the existence of the other 11. Option 3 is honest about the schema's limitation. The grading consequence is that Channel 2 evaluation will compare against `value` content rather than `string_va` for this fixture, which is what it would have to do anyway.

## Open questions deferred to v2

These are surfaced in `docs/schema.md`'s "Open questions deferred to v2" section. Listed here as the issue inventory for v2 design.

1. **Hashed API resolution.** The `hashed` enum value in `api_resolution` is reserved but unused in v1. Channel 2 doesn't detect hash-based resolution; v2 will.
2. **Static gate-group detection.** `coordination_constraint.gate_group_id` is always null in v1. v2 should detect AND-gates statically and populate.
3. **Iterative refinement.** `iteration_number` and `total_iterations` are scaffolding-only in v1.
4. **Compound output parameters.** Sub-field selection within structs (e.g. `SYSTEM_INFO.dwNumberOfProcessors`) is handled in `clew/api_knowledge/`, not by the schema. v2 may introduce a `parameter_path` field.
5. **Multi-comparison call sites.** v1 splits these into multiple candidate records; v2 may collapse.
6. **Confidence calibration.** v1's `confidence` is heuristic and uncalibrated.
7. **Per-value provenance fields.** v1 places `string_source`, `string_va`, `string_function_va` in the per-candidate `evidence` block, which cannot represent multi-value candidates where each value's literal lives at a different address. v2 should move these three fields into each `candidate_values` entry.
8. **OR-gate semantics.** Loop-over-array checks ("any one match means detected") aren't expressible in v1. `coordination_constraint.gate_group_id` is documented for AND-gating. v2 should consider whether a parallel OR-gate field is needed, or whether `candidate_values` array semantics implicitly cover it.
9. **API-knowledge channel provenance.** Values like "GetModuleHandleW return == NULL is clean state" come from Clew's API knowledge base, not from any channel that found the call site. v1 attributes them to the call-site-finding channel; v2 may add an `api_knowledge` channel for explicit provenance.
10. **Compiler-emission variance.** Debug builds construct stack-local pointer arrays for fingerprint string lists; Release builds emit `.rdata` blobs. Channel 2's static analysis must handle both. The schema doesn't constrain this directly, but Channel 2's design must.
11. **Compiler-instrumentation in `dataflow_path`.** Debug builds insert `__CheckForDebuggerJustMyCode`, `__RTC_CheckEsp`, stack canary fills between source and sink. v1 records exclude these as noise. v2 should formalize a "compiler-inserted instrumentation should not appear in dataflow_path" rule.
12. **Time-based stalling vs. fingerprint comparison.** Stalling loops (`while (GetTickCount() % 10 != 5)`) are env-sensitive but aren't fingerprint comparisons. v1 records exclude them as out of scope. v2 may introduce a separate candidate type for timing-based evasion.

## Methodology lessons (what changed in the plan)

Three findings during week 1 caused changes to the project plan:

### Real-malware fixtures are deferred to channel evaluation, not used for schema validation

Original plan: 3-5 hand-built fixtures from Pfuzzer's annotated corpus. Actual outcome: 2 al-khaser-derived fixtures, with real-malware fixtures deferred to Channel 2 piloting in week 5+.

Reason: real malware aggressively wraps API calls in helpers (Delphi RTL routers, Pony stealer dispatch tables, NSIS extraction layers). The call site and the comparison site are typically in different functions, requiring multi-frame manual RE per fixture. Hand-built ground truth at this complexity isn't tractable in the time budget for fixture work, and the schema doesn't need real malware to be validated.

When Channel 2 is implemented, evaluation against real malware will use qualitative grading against published RE writeups rather than `expected.json` oracles. The deferred samples (`269aff53...` rebhip, `68644c...` Pony) become the test set for that work.

### Pfuzzer's annotations don't replace reverse engineering

Original assumption: Pfuzzer's `notes.txt` files would shortcut the ground-truth construction by pre-identifying which call sites are env-sensitive. Actual finding: most `notes.txt` files are templated trace summaries with little manual content. The non-empty cases use Pfuzzer's "Mutations applied in the best run (N)" section, which lists API call sites whose output Pfuzzer mutated to bypass checks — useful as candidate-set hints, but the actual `value` fingerprints (the strings the malware compares against) still require reading the binary in BN.

Pfuzzer is also limited to 32-bit samples, with x64 in the "Discarded" group. Mutation values logged are Pfuzzer's synthetic retarget targets (e.g. `testuser`, `Office`, `Window - Window`), not the original strings the malware was checking against.

### Sample availability is a hard constraint that should gate sample selection

Original sourcing approach: pick samples for analytical fit, then attempt to download. Actual finding: Pfuzzer's curated dataset isn't freely downloadable per-SHA-256 from any single source. Pfuzzer's authors built their corpus from VirusTotal Academic feed and bulk VX Underground monthly Bazaar drops — neither supports targeted single-sample download. MalwareBazaar's coverage is biased toward recent, AV-named, frequently-submitted samples; Pfuzzer's 2018-2022 long tail is mostly absent.

Updated approach: check availability first (free auth-keyed Bazaar API, then Hybrid Analysis, then VT Academic if applied for), pick from what's available. Don't burn time on samples we can't get.

## Things to think about going into week 2

Three open items, in priority order:

### Channel 0 (capa) integration is the next concrete deliverable

Week 2's planned work is Channel 0: integrating capa for capability detection and using it for tier classification. The schema's `capa_techniques` and `tier_classification` fields are already populated by hand in records #1 and #2 — Channel 0 will produce these automatically. Both fixtures pre-document what the expected capa output should be for their respective binaries, which gives Channel 0 a grading target on day one.

### v2 schema design should start informally during channel work

The 12 deferred questions accumulate as channel implementation proceeds, because each channel surfaces edge cases the schema doesn't cleanly handle. Recommend keeping a `docs/schema_v2_notes.md` (or similar) where new findings get appended as they appear, rather than batch-designing v2 at the end. Several v2 questions (per-value provenance, OR-gate semantics, compiler-instrumentation in dataflow_path) are already concrete enough to draft.

### VT Academic application status

Submitting the VT Academic application in week 2 unblocks the deferred Pfuzzer fixtures for Channel 2 evaluation. Turnaround is typically 1-2 weeks. If access doesn't come through, Channel 2 evaluation falls back entirely to the qualitative-grading path against published RE writeups for the deferred samples — workable, but VT Academic is the cleaner path.

## What not to do in week 2

- **Don't add more al-khaser fixtures.** The schema is exercised. Further al-khaser fixtures have diminishing returns.
- **Don't try to source more real-malware fixtures.** Channel 2 evaluation is where real malware comes back in, with different (and lighter) ground-truth requirements.
- **Don't fight v2 schema changes.** If a Channel 0 implementation hits a schema gap, document it in `docs/schema_v2_notes.md` and work around it in v1. Stability of v1 matters more than completeness during channel implementation.

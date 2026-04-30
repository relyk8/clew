# Week 2 Retrospective

Days 5–7 of the 12-week Clew plan, repurposed from the original "single-day per-channel pilot" schedule into a full Channel 0 implementation. Capa preprocessing implemented end-to-end: subprocess wrapper, JSON parser, evasion-technique filter, tier classifier, with unit and integration tests against the al-khaser fixture. Pulled forward from the original week 8 slot to give `tier_classification` real data from week 2 onward.

## Deliverables completed

- **`clew/channels/capa.py`** — `run_capa()` (subprocess wrapper around capa CLI, requires explicit `rules_path` and `sigs_path`), `_parse_capa_json()` (independently testable), `filter_evasion_techniques()` (namespace-prefix + override-list filter), `CapaResult` dataclass (`rule_names`, `rule_matches`, `raw`), and a typed error hierarchy (`CapaError`, `CapaNotFoundError`, `CapaRunError`, `CapaParseError`).
- **`clew/tiers.py`** — `PFUZZER_68_APIS` (starter set; expansion deferred to week 9), `CAPA_RULE_TO_APIS` (partial mapping for currently-needed rules), `classify()` returning `(tier, unmapped_rules)`. Unmapped rules deterministically degrade to tier_3 and surface as the second return value.
- **`tests/test_capa.py`** — 4 tests: 2 unit (parse saved JSON, filter evasion techniques) and 2 integration (full capa run, missing-binary error path), env-var-gated.
- **`tests/test_tiers.py`** — 4 tests covering tier_1, tier_2 (mixed-coverage via monkeypatch), tier_3 (unmapped rule), and empty input.
- **`tests/conftest.py`** — `capa_paths` fixture (skips integration tests if `CAPA_RULES_PATH`/`CAPA_SIGS_PATH` not set), `fixtures_dir` fixture.
- **`tests/fixtures/al-khaser_x86.capa.json`** — saved capa output (1.3 MB, 106 rules) committed for deterministic offline unit tests.
- **`tests/fixtures/al-khaser_x86.capa_techniques.json`** — canonical 25-entry evasion-relevant filter target. Both fixtures' `capa_techniques` arrays read against this.
- **`docs/schema_v2_notes.md`** — four findings appended (Channel 0 boundary, 8/12 coverage gap, `tier_classification` derivation choice, capa attribution rule).
- Updated both `*.expected.json` fixtures' `capa_techniques` to the canonical 25-entry list. No other field touched.
- **`pyproject.toml`** — added `flare-capa>=9.4.0,<10`, plus `[tool.pytest.ini_options] pythonpath = ["."]` workaround for the venv-vs-system-python state (see methodology lessons).

End-state pytest output: 13 passed with env vars set; 11 passed + 2 skipped without. Integration test runtime ~86s (one full capa invocation against al-khaser).

## Design decisions resolved

### capa is a sample-level / feature-level signal, not a per-call-site signal

Discovered while reconciling fixture #2's `capa_techniques` against actual capa output. Predicted rule name `check for sandbox files via API` doesn't exist in capa's rule library — that was a hand-guessed value that didn't survive contact with reality. The al-khaser GetModuleHandleW fingerprint loop has no rule matching at the call site at all. capa only sees the literal DLL strings via `reference anti-VM strings`' string-feature regexes hitting `.rdata` offsets.

Compare with fixture #1: `check for debugger via API` fires inside the IsDebuggerPresent caller because there's a dedicated rule for that API pattern.

So Channel 0 contributes in two distinct ways:
1. **call-site match** — a capa rule's match address falls inside the candidate's function VA (record #1)
2. **value-feature match** — a capa rule's regex captures match the candidate's values (record #2)

Both count for `source_channels` attribution under Channel 0. Neither is fundamentally better; they're different evidence types. The schema can't currently distinguish them — flagged in `docs/schema_v2_notes.md` as a candidate for a v2 `capa_match_kind` field.

### `capa_techniques` is sample-level; both fixtures carry identical arrays

Re-reading the schema clarified that `capa_techniques` lives at the record root, not inside `candidates[]`. Both al-khaser fixtures therefore must carry the same `capa_techniques` array — one rule list per sample, regardless of which candidate the record describes. This wasn't true of the week-1 fixture state (record #1 had `["check for debugger via API"]`, record #2 had `["check for sandbox files via API"]`). Fixed.

The remaining choice was what subset of capa's 106 fired rules to include. Three options considered:

- **All 106** — faithful but noisy. Most are unrelated to evasion (file I/O, networking, crypto). Field becomes a long array; downstream consumers must filter.
- **`anti-analysis/*` namespace only** — cleaner but excludes obviously-evasive rules in other namespaces (`find graphical window`, `check process job object`, `acquire debug privileges`).
- **Filtered to evasion-relevant: `anti-analysis/*` + override list** — matches `tier_classification`'s view of the sample.

Chose option 3. Same 25-rule canonical list goes into both fixtures and drives tier classification. The override list (`EVASION_NAME_OVERRIDES`) lives in `clew/channels/capa.py` and is small enough to maintain by hand.

Edge cases left for later: rules like `connect to WMI namespace via WbemLocator` and `enumerate disk properties` — al-khaser uses these for evasion but their capa namespaces are non-evasion. Currently excluded from the override list; revisit when a non-al-khaser sample exposes the issue.

### Tier classifier: namespace-prefix + override list, not rule-name table

Initial sketch was a `CAPA_RULE_TO_APIS` dict keyed on every rule name. After seeing capa's 100+ rules across 50+ namespaces, that's an unmaintainable amount of hand-curation. Settled on:

- `EVASION_NAME_OVERRIDES` (in `capa.py`) — small name-keyed exception set to the namespace rule.
- `CAPA_RULE_TO_APIS` (in `tiers.py`) — partial rule-to-API mapping. Unmapped rules deterministically degrade to tier_3.
- `classify()` returns `(tier, unmapped_rules)`. The unmapped list is the work queue.

Single rule for tier promotion: a sample is tier_1 only if every fired rule is mapped *and* every implied API is inside Pfuzzer's 68. Any unmapped rule forces tier_3; mixed-coverage forces tier_2. Empty input → tier_1 (no evidence of evasion isn't a degradation signal at this layer; tier_4 is decided elsewhere).

### `tier_classification` derived from capa output, not from `candidates[]`

The schema doc says "the sample-level `tier_classification` is the worst tier among its candidates." That's clean once derivation logic exists, but ambiguous when non-extractable checks come up (do they emit tier_3 placeholder candidates or get skipped?). v1 short-circuits by deriving `tier_classification` directly from capa's rule output — sample-level field, sample-level input. Per-candidate `evasion_tier` can still be set by candidate derivation later. v2 must reconcile.

### capa attribution rule for `source_channels`

Strict reading of fixture #2: capa didn't find this candidate (no rule matches at the call site). Loose reading: capa identified the values via `reference anti-VM strings`. Picked loose. Documented rule:

> capa is credited in `source_channels` when capa detected either (a) the API pattern via a rule that matches at the candidate's call site / function, or (b) any of the candidate's values via any rule's string-feature regex.

This keeps the channel-grading principle from week 1 intact: the test that runs Channel 0 against al-khaser asserts that some capa output supports the candidate, by either path. Both fixtures stay at `["capa", "bn_xref"]`.

## What week 2 surfaced for v2

Appended to `docs/schema_v2_notes.md`. Listed here as the v2 issue inventory delta from week 1.

13. **`capa_match_kind` field.** v1 attributes capa for both call-site and value-feature matches but doesn't distinguish them. v2 may want to. Concrete examples in v1: fixture #1 is call-site match; fixture #2 is value-feature match. Same `["capa", "bn_xref"]` attribution today, different evidence types underneath.

14. **The 8/12 value coverage gap is concrete v2 motivation.** al-khaser's `loaded_dlls` candidate has 12 fingerprint strings. capa's `reference anti-VM strings` rule covers 8 (`avghookx.dll`, `avghooka.dll`, `snxhk.dll`, `pstorec.dll`, `vmcheck.dll`, `wpespy.dll`, `cmdvrt64.dll`, `cmdvrt32.dll`) and misses 4 (`dbghelp.dll`, `sbiedll.dll`, `api_log.dll`, `dir_watch.dll`). This is the worked-example justification for FLOSS (week 3) and BN (weeks 3–7) — capa alone cannot enumerate values even when its anti-VM rules fire on the sample.

15. **`tier_classification` derivation ambiguity.** v1 derives from capa output; v2 must decide what role `candidates[]` plays.

## Methodology lessons (what changed in the plan)

### Hand-built fixtures must be reconciled against real tool output before tests are written against them

Fixture #1's predicted capa rule name was right verbatim. Fixture #2's was wrong — `check for sandbox files via API` doesn't exist in capa's rule library. The fix was small (regenerate `capa_techniques` from the canonical filtered list) but only because it was caught before any test code was written against the predicted value.

Generalizable rule for future channels: when a hand-built fixture predicts external-tool output, run the tool and reconcile the prediction first. Don't build the test harness on guessed values.

### capa has three coupled version artifacts, not two

Earlier planning treated `(flare-capa, capa-rules)` as one unit to pin. It's actually three: `(flare-capa, capa-rules, capa-src/sigs)`. The PyPI install gives neither rules nor sigs. Rules live in the separate [capa-rules](https://github.com/mandiant/capa-rules) repo. Sigs live in `capa/sigs/` inside the main capa source repo, not in capa-rules — a non-obvious distinction that cost ~30 minutes to discover during installation. Mismatches across the three silently change which rules fire.

Documented in `clew/channels/capa.py`'s module docstring. When pinning for production, all three artifacts need version coordination.

### Timeline shift: capa pulled from week 8 to week 2

The original 12-week schedule had capa preprocessing in week 8 alongside CAPE config and DRIO comparison logging. Week 1's retrospective surfaced the dependency: `tier_classification` is hand-populated in fixtures, but Channel 0 is what populates it from real data. Without capa wired up, every record's `tier_classification` is a placeholder until week 8.

Pulling capa to week 2 means tier classification has real ground truth from now until project end, and week 2 had a concrete deliverable (the channel) that exercises the schema and tier system together. Week 8 now has slack for whichever earlier channel slipped — most likely the BN dataflow bridge in weeks 5–7.

This was a good call. The pattern (pull forward channels with cross-cutting dependencies on schema fields) is worth applying again if a similar dependency shows up in week 3 or 4.

### Channel 0 is structurally simple. The harder channels are still ahead.

Worth naming explicitly so it's calibrated honestly going into week 3. Channel 0 is a subprocess wrapper around a tool that already does the work. Channel 1 (FLOSS) is similar — a Python API directly, no rules+sigs tangle, simpler output shape. Channels 2 (BN dataflow) and 4 (DynamoRIO inside CAPE) are where the actual research lives. The README's "weeks 5–7 are the highest-risk stretch" remains true; nothing in week 2 changed that risk profile.

## Things to think about going into week 3

### FLOSS integration is the next concrete deliverable

Week 3's planned work is Channel 1: FLOSS for static and deobfuscated string extraction. Cleaner than capa in three ways: Python API directly (no subprocess), no separate rules/sigs config, and the schema's `string_source` enum (`static`, `stackstring`, `tightstring`, `decoded`) was designed to mirror FLOSS's output categories. Target shape: `clew/channels/floss.py` mirroring `capa.py` (typed errors, dataclass result, env-var-gated integration test).

The al-khaser fixtures already exercise FLOSS-relevant content. Record #2's 12 DLL fingerprints live at static `.rdata` addresses, all easy targets for FLOSS' static-string extraction. Channel 1's grading target on day one: extract those 12 values, plus the static strings backing record #1's debugger-detection paths if any exist.

### Decide venv-vs-system-python now, not later

Current state is awkward: repo's `.venv` has flare-capa but not pytest/jsonschema; system Python 3.12 has those but doesn't see `clew/` without the `pythonpath = ["."]` workaround in `pyproject.toml`. Two clean paths:

- **Editable install in venv.** Add `[project.optional-dependencies] dev = ["pytest", "jsonschema"]` to `pyproject.toml`. Run `pip install -e ".[dev]"` into `.venv`. Remove the `pythonpath` workaround. `CAPA_RULES_PATH`/`CAPA_SIGS_PATH` stay env-var-gated.
- **System-wide.** Drop `.venv`, install everything to system Python with `pip install --user -e ".[dev]"`. Simpler but pollutes system Python.

Editable-in-venv is the standard pattern. Recommend doing this on day one of week 3, before FLOSS adds more dependencies.

### Don't over-build `CAPA_RULE_TO_APIS`

`clew/tiers.py` has placeholder mappings for ~10 rules. Tempting to spend a day filling out the full table from the canonical 25-entry list. Don't. Week 9 (candidate derivation) is where API-level mappings get real, and the table will need to be redone against derivation logic. Leave the TODO comments as the work queue; let unmapped rules degrade to tier_3.

## What not to do in week 3

- **Don't expand `CAPA_RULE_TO_APIS` preemptively.** Wait for derivation work in week 9. The unmapped-rule list out of `classify()` is the canonical work queue for that table.
- **Don't pull more channels forward.** Week 2's pull-forward was justified by tier classification needing real data. Channels 1, 2, 4, 5 don't have similar cross-cutting dependencies — they each populate their own evidence fields independently.
- **Don't add new fixtures yet.** The two al-khaser fixtures still exercise the structural axes the schema needs. FLOSS evaluation against existing fixtures is sufficient for week 3. Real-malware fixtures stay deferred to Channel 2 piloting in week 5+.
- **Don't fight schema changes.** Same rule as week 2: if FLOSS surfaces a schema gap, append to `docs/schema_v2_notes.md` and work around it in v1. Stability of v1 still matters more than completeness during channel implementation.

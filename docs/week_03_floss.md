# Week 3 Session: Channel 1 (FLOSS) setup + implementation

**Date:** 2026-06-09
**Box:** `ml-cluster-01`, `/home/shared/clew-env/clew` (shared `research` group; venv is `root:research`, setgid)
**Outcome:** Channel 1 (FLOSS) implemented, tested end-to-end, and committed. `clew/channels/floss.py` + `tests/test_floss.py` pass 3 unit + 3 integration tests against the al-khaser fixture. Day-one grading target met: all 12 record-#2 DLL fingerprints extracted, including the 4 capa misses.

---

## 0. Setup & run (for other researchers / a fresh box)

The venv migrated from box #2 was subtly broken — it was built at a path that no longer exists, so it never actually activated, and several console scripts had dead shebangs. If you're setting up on a fresh or migrated box, these are the steps that get FLOSS (and the rest of the env) working. Skip any that don't apply.

### Verify / repair the venv

```bash
cd /home/shared/clew-env/clew

# 1. Is the venv actually live? Activate and check sys.prefix points INTO .venv.
source .venv/bin/activate
python3 -c "import sys; print(sys.prefix)"   # must be .../clew/.venv, NOT /usr
```

If `sys.prefix` is `/usr` (or activation silently fell through), the venv was built at a stale path. Rebuild the scaffolding **in place** — this regenerates `pyvenv.cfg`/`activate` without wiping installed packages:

```bash
python3 -m venv /home/shared/clew-env/clew/.venv
source .venv/bin/activate
python3 -c "import sys; print(sys.prefix)"   # confirm it's now inside .venv
```

### Install (always use `python3 -m pip`, not bare `pip`)

Bare `pip`/`capa`/`floss` console scripts may carry stale shebangs from the old path (`cannot execute: required file not found`). `python3 -m pip` ignores the shebang and runs the package directly — and reinstalling through it regenerates the broken scripts as a side effect.

```bash
# clew itself, editable, with dev extras (pytest, jsonschema)
python3 -m pip install -e ".[dev]"

# FLOSS — exact pin (see §3.6). NB: this downgrades networkx 3.6.x -> 3.1
# to satisfy FLOSS; that's expected and capa still passes (verified).
python3 -m pip install "flare-floss==3.1.1"

# If the `capa` CLI script is broken (stale shebang), regenerate it:
python3 -m pip install --force-reinstall --no-deps flare-capa
```

### Run the tests

```bash
# Fast: unit tests only (capa/tiers/floss adapters; no tool runs)
python3 -m pytest -q -k "not integration"

# Full FLOSS run (~5-10 min on a loaded box):
FLOSS_INTEGRATION=1 python3 -m pytest -q tests/test_floss.py

# Full capa run needs the rules/sigs env vars (sigs live in the capa SOURCE repo):
export CAPA_RULES_PATH=/home/shared/clew-env/capa-rules
export CAPA_SIGS_PATH=/home/shared/clew-env/capa-src/sigs
python3 -m pytest -q
```

### Regenerate the FLOSS unit-test fixture (if needed)

The offline unit tests read a saved `floss -j` dump. To regenerate:

```bash
floss -j tests/fixtures/al-khaser_x86.exe > tests/fixtures/al-khaser_x86.floss.json
```

(Uses the bare `floss` CLI, whose shebang is correct once the env is repaired.)

---

## 1. What got built

- **`clew/channels/floss.py`** — Channel 1. Mirrors `capa.py` conventions (future-annotations, `FLOSS_PINS`, four-level error hierarchy, frozen dataclass result, independently-testable adapter, keyword-only args).
  - `run_floss(sample_path, *, min_length=4, sigs_path=None, enable_*=True, save_workspace=False)` — drives FLOSS's extractor functions in-process, in `floss.main.main()`'s order, returning a `FlossResult`.
  - `load_floss_results(path)` — loads a saved FLOSS JSON via `floss.results.read` for offline unit tests (mirrors capa's saved-JSON pattern).
  - `FlossString` dataclass — one string tagged by `source` (schema `string_source` enum value) with that category's **native location fields preserved, not normalized**.
  - `FlossResult` dataclass — four category lists + `min_length` + `raw` (the `ResultDocument`), plus `all_strings()` / `values()` helpers.
  - Error hierarchy: `FlossError`, `FlossImportError`, `FlossRunError`, `FlossParseError`.
- **`tests/test_floss.py`** — 3 unit (offline, fixture-driven adapter checks) + 3 integration (`FLOSS_INTEGRATION`-gated live runs). Integration asserts the 12 DLLs and, sharply, the exact 4 capa-misses.
- **`tests/fixtures/al-khaser_x86.floss.json`** — saved `floss -j` output, committed for offline unit tests (same pattern as the capa fixture).

**Test end-state:** `3 passed, 3 skipped` without `FLOSS_INTEGRATION`; `6 passed` with it. Integration runtime ~626s for the two full-analysis tests (box under load; the fixture generation alone took 304s vs the pilot's 113s).

**Environment changes made this session** (committed): venv rebuilt in place (was pointing at box #2's path, never activating); stale console-script shebangs fixed via module-pip reinstalls; `clew` now editable-installed; `flare-floss==3.1.1` added; networkx moved 3.6.1→3.1 to satisfy FLOSS; `pythonpath` pytest workaround removed (redundant after editable install); full suite (16 capa/tiers + 6 floss) green. See §0 for the reproducible steps. Note for `relyk8`/`capeadmin`: the shared `.venv` changed (floss added, networkx downgraded).

---

## 2. Environment findings (the "why" behind §0)

Detail on each repair, in case a future migration repeats the failure modes.

### 2.1 The venv was built at a dead path and never actually activated
- `.venv/pyvenv.cfg` showed `command = /usr/bin/python3 -m venv /home/user/Desktop/clew-env/clew/.venv` — the **box #2 creation path**, which doesn't exist on `ml-cluster-01`.
- venvs are **not relocatable**: `activate` and the `bin/` console-script shebangs hardcode the creation path. So `source .venv/bin/activate` silently fell through to system Python (confirmed: `which python` resolved to `/usr/bin`, imports hit system `site-packages`).
- The migration doc's "venv survived relocation" was only half true — the `/srv/shared`→`/home/shared` symlink doesn't cover a venv built against `/home/user/Desktop/...`.
- **Fix:** `python3 -m venv <path>` is idempotent — regenerates `pyvenv.cfg`/`activate`/scaffolding **without** wiping `site-packages`.

### 2.2 Console-script shebangs stayed stale after the venv rebuild
- `python3 -m venv` regenerates `activate`/`pyvenv.cfg` but **does not** rewrite `bin/pip`, `bin/capa`, etc. Those kept the dead box-#2 shebang.
- Symptom: `pip ...` → `cannot execute: required file not found`; `capa` invoked via subprocess → `FileNotFoundError` surfaced as `CapaNotFoundError` (the capa integration test failed this way even though the capa library imported fine).
- **The CLI vs library distinction matters:** `flare-capa` the *library* imported fine; the `capa` *console script* was broken. The migration doc only verified the library imported.
- **Fix:** prefer `python3 -m pip` (ignores the shebang); reinstalling through it regenerates the scripts. For `capa` specifically, `--force-reinstall --no-deps flare-capa` rewrote `bin/capa` without re-resolving deps.

### 2.3 Ownership: shared root-owned venv, but writable by the group
- `.venv` is `root:research` with setgid. As a `research` member, `kirito` **can** install into it (`pip install -e` succeeded). An earlier worry that root-ownership would block installs turned out unfounded (it only blocked overwriting specific root-owned files like `activate` during an in-place rebuild attempt).

### 2.4 FLOSS install downgraded networkx (shared-venv side effect)
- Installing flare-floss **downgraded networkx 3.6.1 → 3.1** to satisfy FLOSS's pin. networkx is shared with capa/vivisect, so this was a flagged risk.
- **Cleared:** full suite incl. the capa integration run (the real graph-analysis path) passed afterward — `16 passed` with the capa env vars set.

---

## 3. FLOSS API findings + design decisions

Discovered by inspecting the installed `flare-floss==3.1.1` directly (not the docs), via throwaway probe scripts and reading `main()`'s source. Recorded so the module's design choices are traceable — including the alternatives we weighed and rejected.

### 3.1 The Python API surface
- `floss.api` does **not** exist in 3.1.1. The real surface is `floss.main` (run + extractor functions) + `floss.results` (typed output dataclasses).
- `floss.results` exposes: `ResultDocument`, `Strings`, `StaticString`, `StackString`, `TightString`, `DecodedString`, `StringEncoding`, `AddressType`, plus `read` and `load`.

### 3.2 Design decision: invocation — Python API vs subprocess CLI

**Weighed:**
- *Subprocess CLI* (`floss -j` + parse JSON, like `capa.py`): the JSON output is a far more stable contract than FLOSS's internal functions; CLI contracts outlast library internals across versions. But — we'd just spent the session fighting dead console-script shebangs, so subprocess invocation carries that fragility. The pilot also actually went through JSON (`jq` on `floss -j` output), so this was the *validated* path.
- *Python API* (call extractor functions in-process): no subprocess, no shebang exposure, structured dataclasses back instead of JSON to parse, and richer per-string location data than the JSON exposes cleanly. Downside: FLOSS's Python API is **not a documented stable contract** — internal functions move between releases (e.g. `floss.api` existed in older versions, gone in 3.1.1).

**Chose:** Python API, **pinned exactly to 3.1.1** to neutralize the instability downside. The shebang pain was itself the argument against subprocess, and the in-process path gives Channel 2 the richer location fields it needs. Exact-pin (not `>=3.1,<4`) is the mitigation for the unstable-surface risk; on a shared thesis build, reproducibility beats picking up patch releases.

### 3.3 Design decision: location fields — preserve vs normalize

`ResultDocument.strings` (a `Strings`) holds six lists; we use four and drop two:

| FLOSS list | schema `string_source` | location fields |
|---|---|---|
| `static_strings` | `static` | `offset` (file offset), `encoding` |
| `stack_strings` | `stackstring` | `function`, `program_counter`, `frame_offset` (+more) |
| `tight_strings` | `tightstring` | same shape as stack |
| `decoded_strings` | `decoded` | `address`, `address_type` (STACK/GLOBAL/HEAP), `decoding_routine` |
| `language_strings` | — | dropped (v2 item #16) |
| `language_strings_missed` | — | dropped (v2 item #16) |

The four categories express *location* differently — static has a file `offset`, stack/tight have `function`+`program_counter`, decoded has a typed `address`+`address_type`. There is no single "address" field across them.

**Weighed:**
- *Normalize now* — collapse to one `(value, source, address)` shape with a single location field. Cleaner downstream interface. But Channel 2 (BN xref), which consumes these, **doesn't exist yet** to tell us what location shape it wants — so any normalization is a guess, and the address semantics differ too much across types to collapse safely (a decoded STACK address ≠ a static file offset).
- *Preserve faithfully* — `FlossString` keeps each category's native fields, normalizing nothing.

**Chose:** preserve. Premature normalization here discards data Channel 2 can't recover — the same trap as premature filtering (§3.4). The only thing Channel 1 standardizes is the *category label* (FLOSS's four lists → the `string_source` enum), which is genuinely Channel 1's call. `FlossString` carries the union of all location fields, with the inapplicable ones left `None`.

### 3.4 Design decision: filtering — extract everything vs filter

The README lists "raw output is noisy — needs regex filtering" as a FLOSS concern.

**Weighed:**
- *Filter in Channel 1* — drop junk/short strings, regex to likely-candidate values. Cleaner output. But the channel boundary (README) is: FLOSS extracts, **Channel 2 maps strings to call sites — that mapping IS the filter**. A string only matters if it traces to an API call site, and Channel 1 can't know which do. Filtering here risks discarding a string Channel 2 needed (e.g. a short DLL-fingerprint string).
- *Extract everything, tag, defer* — preserve all of FLOSS's output.

**Chose:** extract everything, no semantic filtering. The only length floor applied is FLOSS's own `MIN_STRING_LENGTH` (passed through as `min_length`), which is FLOSS's filter, not ours. Same information-preservation principle as §3.3.

### 3.5 The two `load`s — a naming trap
- `floss.results.read(path) -> ResultDocument` — **the JSON-file deserializer.** This is what `load_floss_results` uses.
- `floss.results.load(sample, analysis, functions, min_length)` AND `floss.main.load(...)` — both **assemble** a ResultDocument from a live vivisect workspace. NOT file readers.
- Initial code used `fr.load(path)` and failed with `missing 3 required positional arguments`. Fixed to `fr.read(path)`. The module comment warns about this explicitly so it isn't repeated.

### 3.6 `main()` has an interactive prompt that silently disables deobfuscation
- Reading `inspect.getsource(floss.main.main)` revealed: when no explicit `--only`/`--no` flags are given and a language is identified, `main()` calls `input("Do you want to enable string deobfuscation? [y/N]")`. In a **non-TTY** context it defaults to `"n"` and **disables** stack/tight/decoded extraction.
- **Consequence:** naively reusing `main()` in tests/automation would yield static-strings-only — a silent partial result, not an error. `run_floss()` avoids this entirely by constructing the `Analysis` object explicitly and calling the extractor functions directly — never touching the prompt. This is the single biggest reason the module drives the extractors itself rather than shelling out to (or calling) `main()`.

### 3.7 Extraction orchestration (mirrored from `main()`)
Order, fast→slow: static → (build workspace) → stack → tight → decoded.
- Static strings: `get_static_strings(sample, min_length)` — no workspace needed.
- Workspace: `load_vw(sample, fmt, sigpaths, save_workspace)`; sigs default to `get_default_root()/"sigs"` (FLOSS bundles its own sigs — **separate from capa's**; caller need not supply them).
- Functions: `select_functions(vw, None)` then `find_decoding_function_features(vw, funcs, ...)`.
- **Stack/tight coupling:** when tight is enabled, stack strings are extracted from `get_functions_without_tightloops(features)` (FP avoidance) and tight from `get_functions_with_tightloops(features)`.
- Decoded: top-20 by score (`get_top_functions(features, 20)`) + tight fvas, deduped via `append_unique`, then `decode_strings(vw, fvas, min_length)`.

### 3.8 Pin
- `flare-floss==3.1.1` (exact) — see the §3.2 rationale. FLOSS ships its own signatures inside the package, so there is no separate rules/sigs repo to pin (unlike capa's three-artifact pin).

---

## 4. Notes carried forward

- **`run_floss()`'s one fragile spot:** `select_functions(vw, None)` worked, but if a future FLOSS version errors on function selection, try `select_functions(vw, [])` (main() passes `args.functions`, an empty list).
- **Workspace caching:** `save_workspace=True` (or env `FLOSS_SAVE_WORKSPACE`) caches the vivisect workspace, which would cut the ~100s+ repeat-run cost. Not enabled by default.
- **Channel boundary → Channel 2:** FLOSS is a *value* channel — it produces strings + their locations. Mapping values to API call sites is **Channel 2 (Binary Ninja xref)**, which is next. The input contract for Channel 2 is `FlossResult`: static strings carry a file `offset`, decoded strings carry an `address`+`address_type` — those are the join keys BN works from.

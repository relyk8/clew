# Fixture Sources

Provenance log for everything in `tests/fixtures/`. Hand-built oracle records reference specific binaries by SHA-256; this file is the corresponding metadata so the binaries can be re-acquired or re-built later. **Binaries themselves are not committed** — `*.exe` and `*.bin` are gitignored. Only the records, this manifest, and supporting markdown live in the repo.

## Active fixtures

### `al-khaser_x86.exe`

- **SHA-256**: `1fe91674eb8daacd14ab42926a303fd16b6b21dfaed2c65b2862dcb41197d119`
- **Source**: github.com/LordNoteworthy/al-khaser
- **Build**: Visual Studio 2022, **Debug** configuration, x86 platform, default linker settings
- **Built on**: 2026-04-28, Windows 11 analysis VM
- **Local copy**: not committed; rebuild from source per `record_01_candidate.md` build instructions
- **Rationale for Debug over Release**: Debug guarantees per-function symbols are retained (no LTCG inlining). Channel 2 evaluation in week 5+ can additionally test against a Release build to exercise optimization-resilience.
- **Notes**: al-khaser is a public anti-evasion testing harness, not malware. The single binary is referenced by both `1fe91674eb8d_01.expected.json` (IsDebuggerPresentAPI) and `1fe91674eb8d_02.expected.json` (loaded_dlls 12-DLL loop). Each fixture is keyed off the same binary; the `_01`/`_02` suffix disambiguates which candidate within the binary the fixture targets.

## Rejected and deferred samples

Samples evaluated as candidates and not used. Logged here as audit trail and to avoid re-evaluating them later. See git log for the iteration history.

### `b6a3b9630a6ed8f626b7fdc083c73a03c57923c1055314bacaa49031c5fa6ae3`

- **Identity**: NSIS dropper, 2022 corpus, Pfuzzer "fully evasive" sample
- **Status**: rejected
- **Reason**: NSIS wrapper containing Salvity polymorphic file infector as inner payload. Inner PE has runtime-mutating code, so Pfuzzer's static offsets do not correspond to stable static-analysis addresses. Polymorphic file infectors are out of scope for v1 fixtures regardless of wrapper.
- **Source**: VX Underground (sample no longer browsable by SHA-256 lookup; was sourced via direct hash query before the site reorganization)

### `269aff53e58f71f5893d6d4bb552e57ab3f56d8b797259f8ed9a3ffc18a295b4`

- **Identity**: rebhip RAT (Trojan.Win32.Bublik.aeld variant), 2023 corpus
- **Status**: deferred — useful for Channel 2 wrapper-traversal testing in week 5+
- **Reason**: Delphi-compiled. API calls are wrapped in RTL helpers, so call sites and comparison sites are always in different functions. Two evaluated check sites (`GetUserNameA @ 70B2`, `RegQueryValueExA @ 68F4`) both turned out to be inside generic Delphi getter helpers, with the actual env-decision occurring in the caller — for one of them, the username feeds a mutex name, not a sandbox check. Hand-built ground truth not tractable.
- **Source**: VX Underground, downloadable by SHA-256 at time of evaluation

### `04aca5d7256cb3a1c1a9b92ac46ed0cf8a4f9c150ef23543d015fe6fe6eea94d`

- **Identity**: SINGLETON (no AV family attribution), 2018 corpus
- **Status**: rejected
- **Reason**: not freely downloadable. VirusTotal Academic feed required for access; institutional application not yet completed. Three free-tier sources (VX Underground search, MalwareBazaar, Hybrid Analysis) returned no hits.

### `68644caea1b3247e6f69d0210e9d59a911089808294f215c29cc2ed6e4c6afb7`

- **Identity**: Pony 2.x credential stealer, 2022 first-seen on MalwareBazaar
- **Status**: deferred — useful for Channel 2 helper-router-pattern testing in week 5+
- **Reason**: triages as legitimate Pony (correct imports: `wininet.dll`, `wsock32.dll`, `advapi32.dll`; Pony YARA family rules confirmed). However, the env checks are reached through a helper-router pattern: `_start` does a `GetTickCount` stalling check (timing-based, out of scope for v1 schema) then dispatches into `sub_410192`, which is itself a router into 5+ unnamed helpers. Locating the actual API call sites and their comparison sites would require multi-frame manual reverse engineering. Hand-built ground truth not tractable.
- **Source**: MalwareBazaar, downloadable by SHA-256 with free auth-key

## Methodology decisions reached during fixture work

These are documented here rather than in the schema or README because they're about how fixtures get sourced, not about Clew's design.

### v1 fixtures are al-khaser, not real malware

Originally planned for 3-5 Pfuzzer-corpus fixtures. Three real-malware sourcing attempts (above) revealed that hand-built ground-truth oracles are not tractable for samples with wrapper-router patterns (Delphi RTL, NSIS extraction, Pony dispatch). Real malware aggressively wraps API calls in helpers, so the call site and the comparison site are typically in different functions, requiring multi-frame manual RE per fixture.

The schema does not need real malware to be validated. al-khaser provides:
- Open-source ground truth (the C++ source code is the answer key)
- No corpus availability constraints
- Clean compilation with documented build steps
- Sufficient structural diversity to exercise the schema's distinct shapes

Real-malware evaluation moves to Channel 2 piloting (week 5+), where outputs are graded qualitatively against published reverse-engineering writeups rather than against hand-built `expected.json` oracles. The deferred samples above (`269aff53...`, `68644c...`) are the test set for that work.

### Sourcing triage order for any future external sample

If real-malware fixtures are added later, the triage order to avoid wasted effort is:

1. **Confirm availability** before evaluating analytical fit. Check MalwareBazaar (free auth-key) first, then Hybrid Analysis, then VirusTotal Academic if available. If the SHA-256 doesn't return a downloadable hit on any free or already-credentialed source, skip the sample.
2. **Reject family classes outright** without analysis: Salvity, Virut, Sality, Ramnit, Expiro, Polip, Neshta (polymorphic file infectors). Reject NSIS-wrapped samples unless the inner PE is what's being analyzed and its hash is recorded separately.
3. **In Binary Ninja, run the four-check triage** before any address work: section names (no `.ndata`/`UPX`/`.aspack`), import count (30+ across multiple DLLs), strings density (200+ readable), `_start` shape (MSVC C runtime, not Delphi RTL with `NtTib.ExceptionList` / `TObject`).
4. **For Pfuzzer-cited samples, verify offsets land in code, not data.** Pfuzzer's `@ XXXX` is a return-address relative to PE base. Adding the image base (typically `0x00400000`) and looking at the instruction one line above the result should reveal a recognizable IAT call to the named API. If it doesn't, either the sample is packed/wrapped (and Pfuzzer's offsets are from a runtime memory image that doesn't match the static binary) or BN didn't auto-disassemble the region.

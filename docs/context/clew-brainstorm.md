> Automated Candidate Extraction Pipeline
## What Clew Is
An automated candidate extraction pipeline for environment-sensitive malware analysis. Clew produces per-sample sets of fuzzing candidate API return values that downstream fuzzers (ariadneX) use as seed data for exploring hidden execution paths in malware binaries. It addresses a gap in current tools (like Pfuzzer, EuroS&P 2025) which rely on hand-coded retarget value lists.

Clew runs once per PE32 malware sample and extracts candidate API return values that AriadneX uses as seed data for environmental fuzzing. It solves Pfuzzer's key limitation: hand-coded, sample-agnostic retarget value lists. Clew makes those lists automated and per-sample.

Full candidate generation for Tier 1 (~60% of evasion techniques), partial for Tier 2 (~25%), triage-only for Tier 3-4. This still expands beyond Pfuzzer.

### The Problem in Plain English

Malware checks its environment before doing anything malicious. It calls Windows APIs like "what's my username?" or "is a debugger attached?" and if the answers suggest it's being analyzed, it hides its real behavior. Pfuzzer showed that if you intercept those API calls and feed back fake answers, you can trick malware into revealing hidden functionality — 42% of samples were hiding something.

But when Pfuzzer intercepts a call, it needs to know what fake values to try. A human manually wrote those lists — "for `GetUserName`, try these 10 usernames; for `GetModuleHandle`, try NULL." The same lists are used for every sample. If a sample checks for something not on the list, Pfuzzer can never find it.

Clew analyzes each binary *before* fuzzing and extracts the specific values *that particular sample* compares against. For example: if a sample calls `GetModuleHandle("SbieDll.dll")` to check for Sandboxie, Clew finds the string "SbieDll.dll" in the binary (FLOSS), traces it to the `GetModuleHandle` call site (Ghidra/BN), and outputs: "for `GetModuleHandle` at 0x401234, expect NULL (clean) or valid handle (sandbox detected)." AriadneX then knows exactly which API to hook and which values to try, instead of guessing from a generic list.

---
## Extraction Channels
### 1. FLOSS (Static String Extraction)
- Extracts plaintext and obfuscated strings (XOR, stackstrings, base64)
- Produces DLL names, registry paths, username blacklists, VM artifact strings
- **Concerns**: Produces nothing for hashed/encrypted comparison targets (FormBook-style). Raw output is noisy — needs regex filtering.
### 2. Ghidra/Binary Ninja Headless (Import Table + API Xref Analysis)
- Maps extracted strings to their specific API call sites — the glue that connects "what value" to "which API"
- **Concerns**: Hardest channel to automate. Argument recovery is fragile with compiler optimizations. Indirect/dynamic API resolution (API hashing) breaks import analysis and needs a hash brute-force preprocessing step.
- Binary Ninja has a cleaner scripting API but Ghidra is open-source. Either works.
- Consider using **capa** (Mandiant) as a fast first-pass filter to identify which evasion techniques are present before deep Ghidra analysis.
### 3. Binary Constants/Immediates Near Call Sites
- Extracts hardcoded integer thresholds (CPU count, RAM, LANGIDs, hash keys, protocol magic bytes)
- **Concerns**: Very noisy without filtering — loop counters, struct offsets, alignment padding all show up. Depends on channel 2 having already identified call sites. Needs channel 4 (dynamic) to validate which constants actually matter.
### 4. DynamoRIO Comparison Instruction Logging
- REDQUEEN-style: instruments `cmp`/`test` instructions after target API returns during a baseline run, captures both operands
- **The critical channel for Tier 2** — only way to get hashed/encrypted comparison targets
- **Concerns**: Requires running malware under DBI (DynamoRIO detectable by sophisticated samples — Pfuzzer found 19 such samples). Baseline run only exercises non-evasive paths, creating a chicken-and-egg problem. Adds ~10 min/sample.
- Internally consistent: if malware detects DBI in Clew, it detects it in AriadneX too — those samples are out of scope for both.
- **Open question**: Run inside CAPEv2 (shared infra with AriadneX) or standalone lightweight sandbox?
### 5. CAPE Config Extractors
- Runs known-family config extraction (~300 families supported)
- Produces C2 IPs, encryption keys, campaign IDs — high quality when it matches
- **Concerns**: Only works for known families. Config data (C2 IPs) is often not directly usable as API retarget values.
### 6. LLM-Based Candidate Enrichment 
- Variant expansion, "QEMU", etc.), semantic tagging, gap filling
- **Concerns**: Reproducibility — LLM outputs are non-deterministic. Most of what it does (VM vendor strings, sandbox DLL names, CIS LANGIDs) can be done with curated lookup tables deterministically and faster. Adds infrastructure complexity.
- **Recommendation**: Make this optional. Pipeline must work without it. Use dictionaries for variant expansion. Reserve LLM for genuinely ambiguous cases.

---
## Proposed Workload Split (by channel)
**Person A — Static Analysis Channels**:
- Channel 1 (FLOSS integration + filtering)
- Channel 2 (Ghidra/BN xref script — the big one)
- Channel 3 (binary constants, falls out of channel 2)
- Channel 5 (CAPE config integration)
**Person B — Dynamic Analysis + Integration**:
- Channel 4 (DynamoRIO comparison logging client)
- Channel 6 (LLM enrichment, if pursued)
- Output schema design (Clew → AriadneX interface)
- Pipeline orchestration (chaining all channels together)
Both workstreams are roughly equal. The interface contract between them is: "static channels produce candidate lists per API call site, dynamic channel validates/augments them, orchestrator merges into final output."

---
## Open Design Questions
1. **Output format**: What schema does Clew emit? Needs to encode: API name, candidate values, confidence source, coordination constraints (Tier 2 gate groups), and evasion tier classification.
2. **Standalone vs. CAPE-integrated**: Standalone CLI tool (portable, easier to demo) or CAPE processing module (tight integration)?
3. **Target API list**: Start with Pfuzzer's 68 interposition APIs, or build broader list from the 54-technique taxonomy?
4. **Chicken-and-egg for Tier 2**: Accept that baseline-only coverage misses evasive paths, or add iterative mode where Clew re-runs with partial candidates applied?

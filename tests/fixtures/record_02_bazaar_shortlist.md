# Record #2 — MalwareBazaar shortlist (Pony / Fareit pool)

## Search context

Bazaar query path: `query=get_siginfo&signature=Pony&limit=1000` → 853 rows (2020-03 → 2026-04). Pre-filter on `<500KB & file_type=exe & trid mentions Win32 MSVC (no UPX/Mew/VB6/Delphi/Win64)` → 66 candidates. Top 20 by size enriched via `get_info`. Applied seven hard requirements with the user-approved relaxation: **C3 replaced with "family is Pony/Fareit (documented evasion behavior in security literature) AND yara confirms unpacked Pony code is statically present"**. 15 strict survivors after rejection of UPX-yara-flagged samples and samples without Pony-family yara confirmation.

## Ranking criteria (in order)

1. Vintage diversity — picking from distinct compile clusters (MSVC 5.0 102KB cluster, MSVC 5.0 90-99KB cluster, MSVC 4.x 99-106KB cluster, MSVC-generic 44KB outlier).
2. Pony-family yara strength — count of `pony` / `Fareit` / `Windows_Trojan_Pony_d5516fe8` / `win_pony_auto` rule hits.
3. Static-target indicator yara — `INDICATOR_SUSPICIOUS_EXE_References_*` rules name the credential targets Pony scans for; presence implies richer `.rdata` string corpus for FLOSS.
4. Smaller file size — less BN navigation overhead.
5. Older `first_seen` — denser third-party analysis cross-reference.

## Documented Pony evasion behavior (relevant to record #2 differentiation)

From Palo Alto Unit 42 ("Pony 2.0", 2014), Proofpoint ("Decoding Pony", 2014), Malwarebytes ("Pony Stealer", 2016-2018), and the leaked Pony 2.x source code, Pony samples consistently exercise these env-sensitive checks as **statically-imported API calls** with **string fingerprints in `.rdata`**:

- **`GetModuleHandleA`** against `kernel32.dll` / `ntdll.dll` (resolution check, not env-sensitive on its own) and **`dbghelp.dll`** / **sandbox DLLs** (env-sensitive — maps to `represents: analysis_tool_detected`).
- **`RegOpenKeyExA` / `RegQueryValueExA`** on registry paths including `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName` (OS version) and, in some variants, VM-vendor keys under `HKLM\HARDWARE\DESCRIPTION\System` and `HKLM\Software\Oracle\VirtualBox` / `\Software\VMware`. The VM-key path is the primary candidate for record #2.
- **`CreateToolhelp32Snapshot` + `Process32FirstW` / `Process32NextW` loop** comparing against analysis-tool process names (`wireshark.exe`, `procmon.exe`, `ollydbg.exe`, `x64dbg.exe`, `idaq.exe`). String-array comparison pattern — fits record #2's "two simple env checks" shape if you split per-string.
- **`GetUserNameA` + `GetVolumeInformationA`** comparing username and volume serial against sandbox patterns (`Sandbox`, `Maltest`, `VMUser`, `CurrentUser` / known sandbox volume serials).
- **`IsDebuggerPresent`** — present in nearly all Pony samples but **duplicates record #1**, so prefer to extract one of the *non-debugger* checks above as the primary candidate for this record.

All five finalists below are from the same Pony codebase lineage and so will exhibit most or all of these checks. Sample-level evidence in bazaar yara is limited (bazaar does not run FLOSS or BN xref) — picking a strong candidate is therefore "this is representative of the Pony codebase" rather than "this specific sample is yara-confirmed to do X." BN inspection on download will confirm.

## Finalists

### #1 — `68644caea1b3247e6f69d0210e9d59a911089808294f215c29cc2ed6e4c6afb7`

- **Size**: 102400 bytes (100.0 KB)
- **Family / AV signature**: Pony (Fareit alias)
- **Tags**: ['exe', 'Pony']
- **First seen on bazaar**: 2022-11-22
- **Compile signature (trid top hit)**: 46.2% (.EXE) Win32 Executable MS Visual C++ 5.0 (60687/85)
- **Pony-family yara confirmations**: ['Fareit', 'pony', 'win_pony_auto']
- **Static-target indicator yara**: ['INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients']
- **All yara hits**: ['Fareit', 'INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients', 'Windows_Trojan_Pony_d5516fe8', 'pony', 'win_pony_auto']
- **Direct sample URL**: https://bazaar.abuse.ch/sample/68644caea1b3247e6f69d0210e9d59a911089808294f215c29cc2ed6e4c6afb7/

**Why it is a good candidate:** Oldest sample in the dominant 102KB MSVC-5.0 Pony 2.x cluster (6 functionally-similar samples). Maximum literature cross-reference for this exact compile vintage; 4 Pony-specific yara confirms.

**Concerns:** None — 102 KB is well within budget. Five other samples in this cluster (231fa5e4, 452cbd43, 112be48b, bc6f7039, a450ced6) are interchangeable backups if 68644cae fails to download.

### #2 — `09b457a2204c173c717617cc4dc3709c21e3f33e19f1e6b4b8bbbc1064491ad7`

- **Size**: 98304 bytes (96.0 KB)
- **Family / AV signature**: Pony (Fareit alias)
- **Tags**: ['exe', 'Pony']
- **First seen on bazaar**: 2023-02-08
- **Compile signature (trid top hit)**: 40.5% (.EXE) Microsoft Visual C++ compiled executable (generic) (16529/12/5)
- **Pony-family yara confirmations**: ['Fareit', 'pony', 'win_pony_auto']
- **Static-target indicator yara**: ['INDICATOR_SUSPICIOUS_EXE_References_Confidential_Data_Store', 'INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients']
- **All yara hits**: ['Fareit', 'INDICATOR_SUSPICIOUS_EXE_References_Confidential_Data_Store', 'INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients', 'Windows_Trojan_Pony_d5516fe8', 'pony', 'win_pony_auto']
- **Direct sample URL**: https://bazaar.abuse.ch/sample/09b457a2204c173c717617cc4dc3709c21e3f33e19f1e6b4b8bbbc1064491ad7/

**Why it is a good candidate:** Slightly smaller (98 KB) than the 102KB cluster, plus explicit yara hits for Pony's canonical credential-target strings (Confidential_Data_Store + File_Transfer_Clients). Implies a richer FLOSS-recoverable string corpus for record #2.

**Concerns:** Same MSVC-5.0 vintage as pick #1 — Channel 2 results may be near-duplicate. Useful to have both because the additional yara indicators may reflect a slightly different config payload.

### #3 — `2088c6ea8ac26f01d0fb39667f4772674eb8c6e627f5f61399b1e3d1f21d99ca`

- **Size**: 99328 bytes (97.0 KB)
- **Family / AV signature**: Pony (Fareit alias)
- **Tags**: ['exe', 'Pony']
- **First seen on bazaar**: 2023-03-04
- **Compile signature (trid top hit)**: 65.6% (.EXE) Win32 Executable MS Visual C++ 4.x (134693/65)
- **Pony-family yara confirmations**: ['pony', 'win_pony_auto']
- **Static-target indicator yara**: ['INDICATOR_SUSPICIOUS_EXE_References_Confidential_Data_Store', 'INDICATOR_SUSPICIOUS_EXE_References_CryptoWallets', 'INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients']
- **All yara hits**: ['INDICATOR_SUSPICIOUS_EXE_References_Confidential_Data_Store', 'INDICATOR_SUSPICIOUS_EXE_References_CryptoWallets', 'INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients', 'Windows_Trojan_Pony_d5516fe8', 'pony', 'win_pony_auto']
- **Direct sample URL**: https://bazaar.abuse.ch/sample/2088c6ea8ac26f01d0fb39667f4772674eb8c6e627f5f61399b1e3d1f21d99ca/

**Why it is a good candidate:** Richest static-target evidence: yara hits CryptoWallets + Confidential_Data_Store + File_Transfer_Clients on top of pony/Windows_Trojan_Pony. Compiled with MSVC 4.x (different vintage from picks #1 and #2). At 99 KB, comparable size budget.

**Concerns:** Lacks the explicit Fareit yara rule (only pony / Windows_Trojan_Pony / win_pony_auto). Family confidence remains high but slightly below the Fareit-flagged picks.

### #4 — `1b9e2afc2febeca968e097691ac3083accffcd997d124bcf552f79e358f938d6`

- **Size**: 44544 bytes (43.5 KB)
- **Family / AV signature**: Pony (Fareit alias)
- **Tags**: ['exe', 'Pony']
- **First seen on bazaar**: 2022-04-25
- **Compile signature (trid top hit)**: 42.7% (.EXE) Microsoft Visual C++ compiled executable (generic) (16529/12/5)
- **Pony-family yara confirmations**: ['pdb2', 'win_pony_auto']
- **Static-target indicator yara**: ['INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients']
- **All yara hits**: ['INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients', 'pdb2', 'win_pony_auto']
- **Direct sample URL**: https://bazaar.abuse.ch/sample/1b9e2afc2febeca968e097691ac3083accffcd997d124bcf552f79e358f938d6/

**Why it is a good candidate:** Smallest (44 KB) and oldest (2022-04-25) of the entire pool. Minimal BN navigation overhead, oldest = densest literature coverage. The `pdb2` yara indicates partial PDB information was retained, which often surfaces function-name strings in `.rdata`.

**Concerns:** Only one strong Pony yara confirmation (`win_pony_auto`) — lower confidence than picks #1-3. At 44 KB it may be a stripped-down Pony 1.9 build rather than full 2.x. High-risk / high-reward; recommend BN sanity-check before committing it as record #2.

### #5 — `6c84462a44a053f70fd3f68b58c87c53937ddd1e89693182fc4054dd42a18320`

- **Size**: 105984 bytes (103.5 KB)
- **Family / AV signature**: Pony (Fareit alias)
- **Tags**: ['exe', 'Pony']
- **First seen on bazaar**: 2024-07-29
- **Compile signature (trid top hit)**: 65.6% (.EXE) Win32 Executable MS Visual C++ 4.x (134693/65)
- **Pony-family yara confirmations**: ['Fareit', 'pony', 'win_pony_auto']
- **Static-target indicator yara**: ['INDICATOR_SUSPICIOUS_EXE_References_Confidential_Data_Store', 'INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients']
- **All yara hits**: ['Fareit', 'INDICATOR_SUSPICIOUS_EXE_References_Confidential_Data_Store', 'INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients', 'MD5_Constants', 'RIPEMD160_Constants', 'SHA1_Constants', 'Windows_Trojan_Pony_d5516fe8', 'maldoc_find_kernel32_base_method_1', 'pony', 'win_pony_auto']
- **Direct sample URL**: https://bazaar.abuse.ch/sample/6c84462a44a053f70fd3f68b58c87c53937ddd1e89693182fc4054dd42a18320/

**Why it is a good candidate:** Different compile vintage (MSVC 4.x) plus `maldoc_find_kernel32_base_method_1` yara, indicating PEB-walked kernel32 base resolution. That hint suggests the sample has manual-API-resolution code paths — likely a different evasion shape from picks #1-4 and worth including as a diversity hedge.

**Concerns:** 2024-07 first_seen (most recent of the picks). Pony has been functionally static since 2018, so the late date does not signal fresh active campaign — but cross-references to public reports may be sparser. The PEB-walking pattern, if present, may produce candidates with `api_resolution: getprocaddress` rather than `import` — that's schema-supported but a different shape from "two simple env checks via static imports" record #2 was written for.

## Bench (10 strict-survivor backups, not ranked)

Useful if any finalist fails to download or proves to be a stub. All passed the same 7-criterion filter.

| SHA-256 | Size (KB) | First seen | Pony-family yara | Notes |
|---|---|---|---|---|
| `60f0c2daba44c1f09f9677a15ba4031f2853e1d3a3b608721d25c261a2341472` | 88 | 2023-08-16 | pony, win_pony_auto | +kernel32 PEB-walk indicator |
| `ba4c0ef0209abd10274480fc3ae8cd4ba74287625c18e01e67dee204b4ca7eb0` | 90 | 2023-07-20 | Fareit, pony, win_pony_auto | Fareit-tagged |
| `a450ced61b33393fc3c651b33f5e50a8e5659a2dca76e06d7ba01d6a1e5e4631` | 100 | 2025-04-28 | Fareit, pony, win_pony_auto | — |
| `bc6f703904a7ab84b456e4d14cf60cbf44615c8b618db9a3fffa02d0467e0c0a` | 100 | 2023-03-11 | Fareit, pony, win_pony_auto | — |
| `112be48ba85ddaefc4aa6397e8a1728693c62231749dc3ce98af586283fc53e2` | 100 | 2023-01-01 | pony, win_pony_auto | — |
| `452cbd43da0897265fd82730973574f94dcc2be7cd8d8606fa992f609d9be39e` | 100 | 2022-12-04 | Fareit, pony, win_pony_auto | — |
| `231fa5e477b2133c25bc3d3eeb8928957f7de72d7b9a46f2b5845e449a39d1db` | 100 | 2022-12-03 | Fareit, pony, win_pony_auto | — |
| `3ab0c58f330345f3dae67a4f68a4b1b4e4b8ae975aa82d90f9b013200ed4f8b0` | 104 | 2025-11-23 | Fareit, pony, win_pony_auto | Fareit-tagged; +Confidential_Data_Store |
| `aaa583789b2a7d918ab2654f48b2f401588f43f8b835ea176ea4276c59bed4ee` | 104 | 2024-11-03 | Fareit, pony, win_pony_auto | +Confidential_Data_Store |
| `b08a4b2e818c2cea901bf41daa162722ded8a3136a38c207538ac913eb8767d7` | 104 | 2024-08-26 | Fareit, pony, win_pony_auto | +Confidential_Data_Store |

## #1 recommendation — start here

Download **`68644caea1b3247e6f69d0210e9d59a911089808294f215c29cc2ed6e4c6afb7`** (102 KB, 2022-11-22) first.

Reasoning: it is the oldest member of the largest single-vintage Pony 2.x cluster (6 functionally-similar 102KB MSVC-5.0 samples; the rest are listed as interchangeable backups). Choosing the oldest in this cluster maximises overlap with Palo Alto Unit 42, Proofpoint, and Malwarebytes' published Pony 2.x reverse-engineering — meaning every static check the binary makes has likely been documented multiple times, giving you cross-references to validate Clew's output against. Four Pony-specific yara hits (`Fareit`, `pony`, `Windows_Trojan_Pony_d5516fe8`, `win_pony_auto`) rule out mis-classification. 102 KB keeps BN navigation cheap. The static-targets indicator (`File_Transfer_Clients`) tells you the binary's `.rdata` carries the canonical Pony target strings, which is exactly what record #2 needs to extract two simple env checks.

Once you have the binary, the cleanest record-#2 differentiation from record #1 is to extract two of: (a) `GetModuleHandleA` against a sandbox DLL string in `.rdata`, (b) `RegOpenKeyExA` against a VM registry-key path string in `.rdata`, (c) `Process32NextW` plus the `wireshark.exe` / `procmon.exe` string array. Skip `IsDebuggerPresent` to keep records #1 and #2 distinct.

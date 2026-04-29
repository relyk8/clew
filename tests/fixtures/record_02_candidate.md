# Record #2 candidate — recommendation

## Pick: `loaded_dlls`

- **al-khaser path**: `al-khaser/AntiVM/Generic.cpp`
- **Function**: `loaded_dlls` (lines 8–44)
- **Evasion type**: heterogeneous — sandbox / VM / debugger / analysis-tool detection via blacklisted-DLL presence check (per-string mapping below)
- **Binary**: the same `tests/fixtures/al-khaser_x86.exe` used by record #1 (SHA-256 `1fe91674eb8daacd14ab42926a303fd16b6b21dfaed2c65b2862dcb41197d119`). No new build, no new download. Build instructions in `record_01_candidate.md` apply unchanged.

This function was on the spec'd line (around `Generic.cpp:38`) and matches all 6 criteria for the record-#2-shape candidate. It is the **only** loop-over-string-array + `GetModuleHandle` site in al-khaser's `AntiVM/`, `AntiAnalysis/`, and `AntiDebug/` directories — every other `GetModuleHandle` call in the codebase is either against a single hardcoded string (`Wine.cpp:14` chained with `GetProcAddress`, fails C2) or is `GetModuleHandleEx` against a code address (not a string fingerprint, fails C1).

## Source (verbatim)

`al-khaser/AntiVM/Generic.cpp`, lines 1–44:

```cpp
#include "pch.h"

#include "Generic.h"

/*
Check if the DLL is loaded in the context of the process
*/
VOID loaded_dlls()
{
	/* Some vars */
	HMODULE hDll;

	/* Array of strings of blacklisted dlls */
	CONST TCHAR *szDlls[] = {
		_T("avghookx.dll"),	 // AVG
		_T("avghooka.dll"),	 // AVG
		_T("snxhk.dll"),	 // Avast
		_T("sbiedll.dll"),	 // Sandboxie
		_T("dbghelp.dll"),	 // WindBG
		_T("api_log.dll"),	 // iDefense Lab
		_T("dir_watch.dll"), // iDefense Lab
		_T("pstorec.dll"),	 // SunBelt Sandbox
		_T("vmcheck.dll"),	 // Virtual PC
		_T("wpespy.dll"),	 // WPE Pro
		_T("cmdvrt64.dll"),	 // Comodo Container
		_T("cmdvrt32.dll"),	 // Comodo Container

	};

	WORD dwlength = sizeof(szDlls) / sizeof(szDlls[0]);
	for (int i = 0; i < dwlength; i++) {
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR),
					_T("Checking if process loaded modules contains: %s "),
					szDlls[i]);

		/* Check if process loaded modules contains the blacklisted dll */
		hDll = GetModuleHandle(szDlls[i]);
		if (hDll == NULL)
			print_results(FALSE, msg);
		else
			print_results(TRUE, msg);
	}
}
```

`loaded_dlls` is invoked directly at `al-khaser/Al-khaser.cpp:233` (`loaded_dlls();` inside the `ENABLE_GEN_SANDBOX_CHECKS` block). It is not gated through `exec_check`, but the direct call site still inhibits aggressive inlining of a 12-iteration loop, so the compiled binary will retain `loaded_dlls` as a real function. The TCHAR macro `GetModuleHandle` resolves to `GetModuleHandleW` because al-khaser builds with `_UNICODE` / `UNICODE` defined (default for the `v143` toolset on the project's platform settings), and `_T("avghookx.dll")` etc. become wide-char (UTF-16) literals in `.rdata`.

## Why it passes all 6 criteria

1. **Loop over a static string array.** Lines 14–28 declare `CONST TCHAR *szDlls[12]` with 12 wide-string literals. The array is local-scope but its elements are pointer literals to `.rdata`-resident UTF-16 strings, and the array of pointers itself ends up in `.rdata` as well (pointer-array initialisers in MSVC release builds with constant data go to `.rdata`, not stack-constructed). Loop runs `for (int i = 0; i < 12; i++)`.
2. **One Windows API call inside the loop.** Line 38: `hDll = GetModuleHandle(szDlls[i]);`. The other per-iteration calls are `_stprintf_s` (CRT, not Windows API) and `print_results` (al-khaser helper, called *after* the comparison — outside the env-check chain). The env-sensitive chain is exactly `GetModuleHandle(szDlls[i])` → `if (hDll == NULL)`.
3. **Statically-imported API.** `GetModuleHandleW` is a `kernel32.dll` import included via `pch.h` → `<windows.h>`. No `GetProcAddress`, no `LoadLibrary`, no `API::GetAPI`.
4. **Single comparison shape per iteration.** Line 39: `if (hDll == NULL)`. Detected branch (`print_results(TRUE)`) fires when `hDll != NULL`, i.e. the malware-equivalent test is `GetModuleHandle(...) != NULL` for every iteration. `comparison_operator: inequality`, identical for every value, matching schema Example 1's pattern exactly.
5. **Self-contained.** The function takes no args, has no #ifdef branching, makes no PEB reads, and depends on no al-khaser helper between the API call and the comparison. `_stprintf_s` runs *before* the API call (just formats the human-readable status) and `print_results` runs *after* the comparison (just prints). Removing those two non-env-check calls leaves a textbook `GetModuleHandle → if(NULL)` body.
6. **Maps to a recognizable evasion type.** The 12 strings cover three distinct semantic targets (`analysis_tool_detected`, `sandbox_detected`, `vm_detected`) — see the per-value `represents` mapping below. This actually exercises a schema feature record #1 didn't: heterogeneous `represents` values within one candidate's `candidate_values` array (the schema enum is per-value, not per-candidate).

## The 12 fingerprint strings

| Idx | Source line | String | Comment in source | `represents` |
|-----|-------------|--------|-------------------|--------------|
| 0 | `Generic.cpp:15` | `avghookx.dll` | AVG | `analysis_tool_detected` |
| 1 | `Generic.cpp:16` | `avghooka.dll` | AVG | `analysis_tool_detected` |
| 2 | `Generic.cpp:17` | `snxhk.dll` | Avast | `analysis_tool_detected` |
| 3 | `Generic.cpp:18` | `sbiedll.dll` | Sandboxie | `sandbox_detected` |
| 4 | `Generic.cpp:19` | `dbghelp.dll` | WindBG | `analysis_tool_detected` |
| 5 | `Generic.cpp:20` | `api_log.dll` | iDefense Lab | `analysis_tool_detected` |
| 6 | `Generic.cpp:21` | `dir_watch.dll` | iDefense Lab | `analysis_tool_detected` |
| 7 | `Generic.cpp:22` | `pstorec.dll` | SunBelt Sandbox | `sandbox_detected` |
| 8 | `Generic.cpp:23` | `vmcheck.dll` | Virtual PC | `vm_detected` |
| 9 | `Generic.cpp:24` | `wpespy.dll` | WPE Pro | `analysis_tool_detected` |
| 10 | `Generic.cpp:25` | `cmdvrt64.dll` | Comodo Container | `sandbox_detected` |
| 11 | `Generic.cpp:26` | `cmdvrt32.dll` | Comodo Container | `sandbox_detected` |

`represents` distribution: 7 × `analysis_tool_detected`, 4 × `sandbox_detected`, 1 × `vm_detected`. All 12 share `retarget_to: null` (the clean state for every entry is "module not loaded", which is `GetModuleHandleW`'s NULL return).

`dbghelp.dll` is annotated "WindBG" in the source, but it is the Microsoft Debug Helper Library and is loaded by many user-mode debuggers (WinDbg, x64dbg, IDA's debugger, etc.) plus a number of crash-reporting frameworks and legitimate analysis tooling. Treating its presence as `analysis_tool_detected` rather than the narrower `debugger_detected` keeps the mapping conservative — the malware can't actually distinguish "debugger attached" from "analyst's machine has dbghelp loaded for unrelated reasons" at this call site.

## Schema decision: one candidate with 12 values

Used the **one-candidate-twelve-values** framing per spec step 5. Justification:

- Physically there is exactly **one** `call ds:[__imp__GetModuleHandleW@4]` instruction in the compiled loop body. The same instruction executes 12 times, with `szDlls[i]` selecting the parameter. So `call_site_va` is one address, `function_va` is one address — fits one candidate cleanly.
- The values differ; the call site does not. That maps directly onto the schema's "one `call_site_va`, N `candidate_values`" structure.
- The alternative — 12 candidates AND-gated via `coordination_constraint.gate_group_id` — would have meant 12 records all sharing the same `call_site_va` and `function_va`, with `gate_group_id: "loaded_dlls_loop"` linking them. v1 of the schema documents `gate_group_id` as always `null`, so the AND-gate framing is reserved for v2 anyway.
- The semantic gate behaviour ("any one DLL present means detected" — i.e. these are OR-gated, not AND-gated) doesn't fit `gate_group_id` either — that field's documented meaning is "all candidates with the same id must be flipped together." The 12 DLL checks are independent; the loop fires `print_results(TRUE)` on the first match. So `gate_group_id` would actively misrepresent the coordination semantics if used.

The third-and-much-deeper-future framing — "v3 introduces an OR-gate field" — is irrelevant for v1; OR-gating across multiple values within a single candidate is exactly what `candidate_values` (an array) already expresses.

## Schema-field → source-line mapping

| Schema field | Value | Source for the value |
|---|---|---|
| `api_name` | `"GetModuleHandleW"` | `Generic.cpp:38` (`GetModuleHandle` macro → W variant under `_UNICODE` build) |
| `api_resolution` | `"import"` | `kernel32.dll` IAT via `pch.h` → `<windows.h>`; no dynamic resolution in the function |
| `parameter_index` | `0` | `lpModuleName` is parameter index 0 of `GetModuleHandleW(LPCWSTR lpModuleName)` |
| `comparison_operator` | `"inequality"` | `Generic.cpp:39` `if (hDll == NULL)` — the malware-equivalent semantic is "treat `result != NULL` as detected"; matches schema Example 1's pattern |
| `candidate_values[i].value` | the 12 strings above | Lines `Generic.cpp:15–26` |
| `candidate_values[i].represents` | per-value mapping table above | Same lines + the comment annotations identify each DLL's vendor/role |
| `candidate_values[i].retarget_to` | `null` | The clean-state return for `GetModuleHandleW` is NULL ("module not loaded") |
| `candidate_values[i].confidence` | `0.9` | Two-channel confirmation (capa + bn_xref), matching record #1's convention |
| `candidate_values[i].source_channels` | `["capa", "bn_xref"]` | Same as record #1 |
| `evidence.string_source` | `"static"` | The 12 wide-string literals live in `.rdata`; FLOSS recovers them as static strings |
| `evidence.string_va` | `null` | **See schema gap note below** — single field can't faithfully represent 12 different VAs; null in v1 |
| `evidence.string_function_va` | `null` | Not stackstrings — the strings are `.rdata`-resident, not stack-constructed |
| `evidence.dataflow_path` | TBD from BN, 2 entries | Function entry VA → loop-body call-site VA (the call instruction has a single address regardless of iteration) |
| `function_va` | TBD from BN | VA of `loaded_dlls` itself |
| `call_site_va` | TBD from BN | VA of the single `call ds:[__imp__GetModuleHandleW@4]` instruction in the loop body |
| `evidence.cmp_operand_a` / `cmp_operand_b` | `null` | Not observed dynamically (Channel 4 / DynamoRIO not in scope for record #2) |

## Schema gap flag — `evidence.string_va` is per-candidate, but per-value VAs differ

The current schema (`evidence.string_va: string | null`) has one `string_va` per candidate. For record #2's twelve `candidate_values`, each value's literal lives at a *different* `.rdata` VA:

```
.rdata:???????? unicode 0, "avghookx.dll", 0
.rdata:???????? unicode 0, "avghooka.dll", 0
.rdata:???????? unicode 0, "snxhk.dll",    0
... etc
```

A single `string_va` at the candidate level cannot point at all twelve. There are two reasonable fixes for v2:

1. **Move `string_va` (and `string_source`, `string_function_va`) into each `candidate_values` entry.** Each value carries its own provenance. This is conceptually cleanest — provenance is naturally per-value — and trivially handles the homogeneous case (record #1 just sets the per-value field on its single entry, indistinguishable from today). Drawback: every `candidate_values` entry duplicates `string_source` for the homogeneous case (12 × `"static"` for record #2).
2. **Add a parallel `evidence.value_string_vas: array<string|null>` of length matching `candidate_values`.** Keep `string_source` at the candidate level (homogeneous in practice anyway). Drawback: implicit positional binding between two arrays is fragile and easy to break with array reordering.

Recommendation: option 1. Provenance follows value, not call site, so the schema should encode it that way. The cost (one extra field per `candidate_values` entry) is fine — entries are small.

For v1, the `record_02.draft.expected.json` workaround is to set `evidence.string_va` to **`null`**. Picking any single VA — the first string, the array's base, the function's `.rdata` reference — would mislead a downstream consumer into thinking that VA was authoritative for all twelve values when it is not. `null` honestly signals "the schema cannot represent the per-value provenance for this candidate"; the per-value VAs still live in the binary and are recoverable by re-running BN against `function_va`, but the schema does not (in v1) carry them. The schema docs already permit `string_va: null` even when `string_source: "static"` (the field types are independently nullable), so this is schema-valid; it's a documented v1 expedient rather than a workaround that fakes a value. The v2 fix above is the right answer.

## Comparison-operator note — loop-exit semantics

The malware-equivalent test inside `loaded_dlls` is "any one DLL match means detected, but the loop continues to the end" (al-khaser keeps printing per-iteration to its log; a real malware variant would `break`/`return TRUE` on first match). Either way, the **per-iteration** comparison is unchanged: `GetModuleHandleW(szDlls[i]) != NULL`. So `comparison_operator: "inequality"` for every value is correct.

If a future extraction wanted to encode "first match wins" loop semantics — i.e. the binary's exit condition is OR over all 12 checks — that would belong in `coordination_constraint`, not `comparison_operator`. The schema docs note `coordination_constraint` is v1-null-only, so that nuance is not currently expressible. It's a v2 concern, not a record-#2 concern.

## Runner-up: `known_usernames`

`al-khaser/AntiVM/Generic.cpp`, function `known_usernames` (lines 122–177). Same multi-value array shape (16 sandbox-known usernames), but with two important deviations from `loaded_dlls`:

1. **API call is *outside* the loop.** `get_username()` (helper wrapping a single `GetUserNameW` call, lines 103–117) is called once, *before* the loop. The loop body contains only `_tcsicmp` (CRT, not a Windows API) comparing the cached username against each array element. So at the binary level there is **one** `call __imp__GetUserNameW` instruction reachable from `known_usernames`, but the per-array-element comparisons happen at 16 different call sites of `_tcsicmp` (or after MSVC inlines `_tcsicmp` into a series of cmp/jne instructions).
2. **`parameter_index` would be `-1`, not `0`.** The 16 username strings are compared against `GetUserName`'s *return* (well, its `lpBuffer` output parameter — but since `GetUserNameW(lpBuffer, &nSize)` writes into a caller-supplied buffer, the schema's `-1` is the right marker per `docs/schema.md`'s "the check is on the API's return value rather than an input" rule for parameterless-from-the-attacker's-perspective return-value-shaped checks).

Why use this as a runner-up and not as the primary:
- Different schema shape from what spec asked for (record #2 = parameter-fingerprint, not return-value-against-array).
- The "API call outside loop, comparison inside loop" structure means the call_site_va and the comparison sites are physically separated — Channel 2's xref pass would need to traverse one frame to associate the comparisons with the API call. That's still in-scope for Clew but is a strictly more demanding shape than `loaded_dlls`.
- BUT it tests N-value `candidate_values` just as well, with the bonus of matching record #1's `parameter_index: -1` shape — making it a useful regression check for the homogeneous-`parameter_index=-1` axis.

If BN reveals `loaded_dlls` has a complication — e.g. the 12-entry pointer-array got split across two compilation units, or MSVC rewrote the loop into unrolled cmp-chains losing the `szDlls[i]` indirection — fall back to `known_usernames` and document the substitution. The schema-decision discussion above carries over verbatim (one candidate, 16 values, OR-gated loop semantics, `gate_group_id: null`).

## Inventory note: how many candidates passed all six criteria?

**One.** `loaded_dlls` is the sole strict survivor in al-khaser for the record-#2 shape (parameter-fingerprint loop with statically-imported `GetModuleHandle`-family API).

The exhaustive search:

- **`AntiVM/Generic.cpp`** — 5 candidate functions (`loaded_dlls`, `known_file_names`, `known_usernames`, `known_hostnames`, `other_known_sandbox_environment_checks`). Only `loaded_dlls` uses `GetModuleHandle`. The others use `StrCmpIW` / `_tcsicmp` / `is_FileExists` against return values or PEB reads — all are different schema shapes (return-value-against-array, or compound conditions, or PEB walking which is excluded by record-#1's rule list).
- **`AntiVM/Wine.cpp`** — `kernel32_bcdry`-style: a single `GetModuleHandle(_T("kernel32.dll"))` followed by `GetProcAddress(hKernel32, "wine_get_unix_file_name")`. Single string, not an array → fails C1. Also a chain of two APIs → fails C2.
- **`AntiVM/{HyperV,KVM,Parallels,Qemu,VirtualBox,VirtualPC,VMWare,Xen}.cpp`** — these contain registry-key checks, MAC-address checks, CPUID checks, BIOS-string checks. Some have static-string arrays, but the per-iteration API is `RegOpenKeyEx` / `RegQueryValueEx` / `check_mac_addr` / inline assembly — not `GetModuleHandle`. They satisfy criteria 1, 3, 4, 5 but fail C2 (different API class).
- **`AntiVM/Services.cpp`** — service-name array, but the API per iteration is `OpenService` (advapi32), not `GetModuleHandle`. Fails C2 if interpreting C2 strictly as the three named APIs.
- **`AntiAnalysis/process.cpp`** — process-name array compared against `Process32Next` results. Fails C2 (the env-check API is `Process32Next`/`CreateToolhelp32Snapshot`, not `GetModuleHandle`).
- **`AntiDebug/`** — every `GetModuleHandle*` use is `GetModuleHandleEx` against a code address (used to determine which module a return-address belongs to). Fails C1 (no string fingerprint).

So the inventory matches record #1's experience: al-khaser is sparse for the strict record-#2 shape, with `loaded_dlls` the lone strict fit. If a future record #3 wants to test a different multi-value shape (e.g. a `RegOpenKeyEx`-loop), `AntiVM/VirtualBox.cpp` or `AntiVM/VMWare.cpp` is where to look.

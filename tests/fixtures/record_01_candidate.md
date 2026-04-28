# Record #1 candidate — recommendation

## Pick: `IsDebuggerPresentAPI`

- **al-khaser path**: `al-khaser/AntiDebug/IsDebuggerPresent.cpp`
- **Function**: `IsDebuggerPresentAPI`
- **Evasion type**: debugger detection (`represents: debugger_detected`)

This is the only function in al-khaser that strictly satisfies all seven hard
criteria. Every other plausible candidate fails at least one — see the inventory
notes at the bottom of this file for why.

## Source (verbatim)

`al-khaser/AntiDebug/IsDebuggerPresent.cpp`, lines 1–28:

```cpp
#include "pch.h"
#include "IsDebuggerPresent.h"

BOOL
IsDebuggerPresentAPI (
	VOID
	)
/*++

Routine Description:

	Calls the IsDebuggerPresent() API. This function is part of the
	Win32 Debugging API and it returns TRUE if a user mode debugger
	is present. Internally, it simply returns the value of the
	PEB->BeingDebugged flag.

Arguments:

	None

Return Value:

	TRUE - if debugger was detected
	FALSE - otherwise
--*/
{
	return IsDebuggerPresent();
}
```

The function pointer is taken at `al-khaser/Al-khaser.cpp:176`
(`exec_check(&IsDebuggerPresentAPI, …)`), so the compiler cannot inline
`IsDebuggerPresentAPI` away. In a 32-bit Release build it will exist as a real
function whose body is essentially `call ds:[__imp__IsDebuggerPresent@0]; ret`.
The "is detected?" comparison physically lives in `exec_check`
(`Shared/Common.cpp:84`) where the returned `int` is treated as a boolean —
semantically equivalent to `if (IsDebuggerPresent() != 0)`.

## Why it passes all seven criteria

1. **Single API call** — exactly one statement: `return IsDebuggerPresent();`.
   No loop, no conjunction, no helper that hides additional API calls.
2. **Statically-imported API** — `IsDebuggerPresent` is a `kernel32.dll` IAT
   import included via `pch.h` → `<windows.h>`. No `GetProcAddress`, no
   `LoadLibrary`, no `API::GetAPI` indirection.
3. **Single string or numeric comparison** — the call has no parameters; the
   single check is on the return value. Exactly one comparison total.
4. **String stored statically** — N/A, vacuously satisfied. The API takes no
   arguments, so there is no string to recover. `evidence.string_source` is
   `null` (the schema permits this; see Example 2 in `docs/schema.md` for the
   no-string field combination).
5. **Return-value or simple-equality check** — return value treated as a
   boolean (`TRUE` ⇒ detected). Mirrors Example 2 of the schema docs exactly,
   which uses `comparison_operator: equality` with `value: true`.
6. **Self-contained** — function is one line. No al-khaser helpers, no globals,
   no preprocessor branching, no platform-specific assembly.
7. **Recognizable evasion type** — debugger detection, mapping cleanly to
   `represents: debugger_detected` and `tier_classification: tier_1`
   (`IsDebuggerPresent` is one of Pfuzzer's 68 covered APIs).

## Schema-field → source-line mapping

| Schema field | Value | Source for the value |
|---|---|---|
| `api_name` | `"IsDebuggerPresent"` | The identifier on line 27: `return IsDebuggerPresent();` |
| `api_resolution` | `"import"` | No `GetProcAddress` / `LoadLibrary` / `API::GetAPI` in this translation unit; `IsDebuggerPresent` is a `kernel32.dll` IAT import via `pch.h` → `<windows.h>` |
| `parameter_index` | `-1` | `IsDebuggerPresent()` takes no parameters; the check is on the return value |
| `comparison_operator` | `"equality"` | Caller (`exec_check`) treats the return as boolean — semantically `IsDebuggerPresent() == TRUE` ⇒ detected (matches Example 2 in `docs/schema.md`) |
| `candidate_values[0].value` | `true` | The "dirty-state" return: `TRUE` from line 27 means a debugger was detected |
| `candidate_values[0].represents` | `"debugger_detected"` | Routine Description comment, lines 11–15: "returns TRUE if a user mode debugger is present" |
| `candidate_values[0].retarget_to` | `false` | The "clean-state" return: `FALSE` from line 27 means no debugger present |
| `evidence.string_source` | `null` | API takes no string parameter — no string exists to classify |
| `evidence.string_va` | `null` | Same reason — no string |
| `evidence.string_function_va` | `null` | Same reason — no string |
| `function_va` | TBD from BN | VA of `IsDebuggerPresentAPI` itself in the built binary |
| `call_site_va` | TBD from BN | VA of the `call ds:[__imp__IsDebuggerPresent]` instruction inside `IsDebuggerPresentAPI` |
| `evidence.dataflow_path` | TBD from BN | VAs traced from function entry to the call site (likely 1–2 entries given the body is a single statement) |

## Build instructions (32-bit Release, on the Windows VM)

al-khaser does **not** support per-check builds. The whole project compiles to
one `al-khaser.exe`; checks are gated at runtime by `--check` flags parsed in
`Al-khaser.cpp`. For Clew's purposes that's fine — Binary Ninja will see every
check function compiled in, and we point it at `IsDebuggerPresentAPI`
specifically. (If you want a smaller, less noisy binary, you can run with
`--check DEBUG --sleep 0`, but the binary itself is the same regardless.)

### Prerequisites
- Visual Studio 2022 with the "Desktop development with C++" workload
  (platform toolset `v143`, per `al-khaser.vcxproj`).
- The Windows 10/11 SDK (any recent version VS 2022 ships with works).
- NuGet on PATH (only needed if VS doesn't auto-restore packages on first
  build — al-khaser uses `packages.config`).

### Steps
1. Clone or copy the al-khaser tree onto the VM at e.g. `C:\al-khaser\`.
2. Open `C:\al-khaser\al-khaser.sln` in Visual Studio 2022.
3. In the configuration dropdowns at the top of the IDE, select:
   - **Configuration**: `Release`
   - **Solution Platform**: `x86` (the solution's `x86` maps internally to the
     vcxproj's `Win32` configuration — this is the correct 32-bit pick).
4. Right-click the `al-khaser` project → **Build** (or `Ctrl+Shift+B` for
   Build Solution; the `Tools/ATAIdentifyDump` sub-project also builds but is
   irrelevant to us).
5. Output binary lands at:
   - `C:\al-khaser\al-khaser\Release\al-khaser.exe` (the primary build output)
   - `C:\al-khaser\al-khaser_x86.exe` (the post-build copy, per the `<Command>`
     in `al-khaser.vcxproj` that runs `copy $(OutDir)$(AssemblyName).exe
     $(SolutionDir)$(AssemblyName)_$(PlatformTarget).exe`)
   - Either copy works as the Clew sample. The `_x86.exe` one at the solution
     root is the easier of the two to grab.

### Equivalent CLI build (matches what CI does)
```
msbuild /m /p:Platform=x86 /p:Configuration=Release al-khaser.sln
```
This is exactly what `.github/workflows/release.yml` runs.

### Defines
None required. No `#ifdef` guards toggle `IsDebuggerPresentAPI` on/off — it is
always compiled. The `ENV32BIT` / `ENV64BIT` macros (set automatically by the
toolchain) gate other checks but not this one.

### Filling the four TBDs after the build
Once `al-khaser_x86.exe` exists:
1. `sample_sha256`: `Get-FileHash -Algorithm SHA256 al-khaser_x86.exe`
   (PowerShell), or `sha256sum` on the analyst host.
2. `sample_path`: relative path under `tests/fixtures/` after copying the
   binary in (e.g. `tests/fixtures/al-khaser_x86.exe`).
3. Open in Binary Ninja, locate `IsDebuggerPresentAPI` (it should retain its
   symbol since al-khaser builds with default linker settings; if symbols are
   stripped, it's the small function whose only call is to
   `__imp__IsDebuggerPresent@0`).
4. Read off `function_va`, `call_site_va`, and the `dataflow_path` VAs.

## Runner-up: `CheckRemoteDebuggerPresentAPI`

`al-khaser/AntiDebug/CheckRemoteDebuggerPresent.cpp`, function
`CheckRemoteDebuggerPresentAPI`. Source body:

```cpp
BOOL bIsDbgPresent = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &bIsDbgPresent);
return bIsDbgPresent;
```

This is the next-cleanest fallback. It nominally fails criterion 1 because two
API names appear in the source (`GetCurrentProcess` and
`CheckRemoteDebuggerPresent`), but in practice `GetCurrentProcess` is defined
in `<processthreadsapi.h>` as essentially `(HANDLE)-1` — MSVC inlines it to a
constant `mov`/`push` and emits **no** import call for it. At the binary level,
the function body contains exactly one IAT call (to
`__imp__CheckRemoteDebuggerPresent@8`) and writes its result into a stack
boolean that's then returned. So if Binary Ninja shows something unexpected for
`IsDebuggerPresentAPI` (e.g., the compiler did something surprising under
LTCG, or the `__imp__` symbol is renamed in a way that confuses Channel 2),
falling back to `CheckRemoteDebuggerPresentAPI` costs us only the source-level
strictness of criterion 1; everything else (single-import, return-value check,
self-contained, debugger_detected) carries over identically. Set
`api_name: "CheckRemoteDebuggerPresent"`, `parameter_index: 1`
(the `lpDebuggerPresent` out-param), and keep the rest of the candidate
identical.

## Inventory note: how many candidates passed all seven criteria?

**One.** `IsDebuggerPresentAPI` is the sole strict survivor.

Common failure modes in al-khaser (so you know what's being filtered out):

- **Loops over arrays of strings** (`loaded_dlls` in `AntiVM/Generic.cpp`,
  every `*_processes` / `*_reg_keys` / `*_files` in `AntiVM/`,
  `analysis_tools_process` in `AntiAnalysis/`) — fail criterion 1 ("not a
  loop") and criterion 5 ("one parameter compared against one value"). This
  is what kills the canonical `GetModuleHandleW(L"sbiedll.dll")` Sandboxie
  pattern: in al-khaser it lives at `Generic.cpp:38` inside a `for` loop over
  12 DLL names, not as a standalone call site.
- **Dynamic API resolution** — every `Nt*` check, every `WUDF_*` check, and
  several others go through `API::GetAPI(API_IDENTIFIER::API_*)`, which is
  al-khaser's `GetProcAddress` wrapper. Fails criterion 2.
- **Chained / compound checks** — `wine_exports` does
  `GetModuleHandle` then `GetProcAddress` (chain, fails 1);
  `OutputDebugStringAPI` does `SetLastError` then `OutputDebugString` then
  `GetLastError` (chain); `ProcessJob` does `QueryInformationJobObject` then
  loops with `OpenProcess` + `GetProcessImageFileName` per process; etc.
- **PEB / KUSER_SHARED_DATA reads** (`BeingDebugged`, `NtGlobalFlag`,
  `HeapFlags`, `HeapForceFlags`, `SharedUserData_KernelDebugger`) — no
  Windows API call at all, just direct memory reads. Fails 1, and explicitly
  excluded by the task's "Don't pick PEB walking" rule.
- **Helper-wrapped one-liners** (`vmware_adapter_name`,
  `parallels_check_mac`, `xen_check_mac`) — single static string, but the
  helper (`check_adapter_name`, `check_mac_addr`) iterates adapters and is
  not itself a Windows API. Fails criterion 1 (the API is hidden inside the
  helper) and criterion 6 (depends on al-khaser helper).

So al-khaser is **sparse, not rich**, for record-#1-shaped checks: the
project is dominated by multi-string / multi-API patterns because it's built
to be a comprehensive PoC of every known evasion, not a corpus of minimal
reference checks.

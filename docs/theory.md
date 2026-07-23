# Clew

## Theory

Environment-sensitive malware gates its behavior behind checks against the
execution environment. Before it runs its real payload, a sample asks where it
is. It queries whether a debugger is attached, whether it sits inside a virtual
machine or a sandbox, and whether a particular file, registry key, mutex,
username, or hostname exists, and it takes the harmless path whenever the answer
looks like an analyst's machine. The tactic is widespread, and one survey of over
180,000 samples found that 68% of malware families contain at least one evasive
sample. The checks run through a small, recognizable set of Windows API calls,
among them `IsDebuggerPresent` and `NtQueryInformationProcess` for debuggers,
`GetModuleHandleW` for sandbox DLLs, `GetUserNameA` and `GetComputerName` to
fingerprint the host, and `RegQueryValueEx` to probe the registry.

Under ordinary analysis these samples look inert. Static analysis is limited by
packing and obfuscation, which hide the control flow before it can be read. A
sandbox runs the binary but observes only the path it chooses to take, which for
an evasive sample is the cover path. Symbolic and concolic execution can in
principle reach every path, but they face state explosion as the branching grows.
Environmental fuzzing is the current answer, and it intercepts the API calls a
sample uses to inspect its environment, feeds back a crafted response, and forces
the sample down the path it was hiding.

The open question is where the crafted responses come from. Current environmental
fuzzers seed them from a list of values chosen by hand and shared across every
sample, and whether that suffices depends on the kind of check. Sandbox, virtual
machine, and debugger detection are hide-on-match checks, where the malware hides
once it finds the fingerprint. A uniform default that never matches, such as a
null handle for `GetModuleHandleW` or zero for `IsDebuggerPresent`, defeats the
check without knowing the specific value it looked for, and a generic hand-coded
list already handles it. Target identification and per-campaign markers invert
that logic. They are run-on-match checks, where the malware proceeds only when a
specific value matches, so a sample that reads a username with `GetUserNameA` and
compares the result against `"JohnDoe"` exits on every other name. No generic
default can satisfy it, and the only way to unlock the path is to supply the
exact value the sample expects, which lives in the binary itself.

Clew exists for the run-on-match case. It reads a single sample and derives,
statically, the concrete values its environment checks are keyed on, among them
DLL and device names, registry paths, mutexes, usernames, and the constants those
checks compare against. It emits them as a structured, schema-validated seed
corpus, with every candidate tied to the API call site that consumes it. Rather
than seeding a fuzzer from a generic list, Clew seeds it from the sample.

## Approach

Clew preprocesses each PE32 binary once and produces a seed corpus keyed to call
sites that any environmental fuzzer can consume. The work is split across four
numbered channels, each contributing one kind of evidence, and a consolidation
step joins them into the final record.

| Channel | Contribution |
|---|---|
| 0. Technique detection | Identify which evasion techniques the sample exhibits, so the pipeline knows where to look. |
| 1. String recovery | Recover candidate string values, including obfuscated ones that appear only after the sample decodes them at runtime. |
| 2. Call sites and dataflow | Enumerate every targeted Windows-API call site and trace, backward through the binary's dataflow, which values flow into each one. |
| 3. Dynamic operands | Where static analysis cannot resolve a value, detonate the sample and capture the operands it compares against as it runs. |

Each candidate carries its provenance and a confidence score, so the downstream
fuzzer can decide what to try first. Clew does not defeat evasion on its own. It
produces the per-sample seed data that lets a fuzzer do so efficiently.

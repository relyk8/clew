# Clew Record Schema

## Purpose

A Clew record is the structured output of running Clew against a single PE32 sample. It enumerates the environment-sensitive API call sites Clew identified in the binary, and for each call site, the candidate values a downstream fuzzer can use to bypass the check. The record is consumed by Pfuzzer-style retargeting fuzzers as input — replacing their hand-coded retarget value lists with per-sample candidates derived from the binary itself.

The schema is deliberately narrow. It does not describe the full behavior of the binary, only the retargeting candidates. Behavioral signatures, family attribution, and execution traces belong in separate artifacts.

## Versioning

The schema version lives in two places. The `$id` URL of the JSON Schema is the canonical version of the schema itself. Each record carries `clew_version` — the version of the Clew tool that produced it. A consumer that supports `clew_version >= X` can rely on the fields documented for that version being present and behaving as specified.

v1 of the schema is single-shot: every record carries `total_iterations: 1` and every candidate carries `iteration_number: 0`. v2 will support iterative refinement. The fields exist in v1 specifically so that v2 consumers do not break on v1 records, and v1 producers do not break on v2 schemas.

Breaking changes (removed fields, narrowed types, new required fields) bump the major version. Additive changes (new optional fields, new enum values where consumers are expected to handle unknowns) bump the minor version.

## Top-level fields

Every Clew record is a JSON object with exactly the following top-level keys. `additionalProperties: false` is set; unknown fields are an error.

### `sample_sha256` (required, string)

The SHA-256 hash of the analyzed binary as 64 lowercase hex characters with no `0x` prefix and no separators. This is the primary key of the record. Two records produced from the same binary by the same Clew version should be byte-identical except for ordering of array elements.

### `sample_path` (required, string or null)

The path to the binary on the analyst's machine at the time of analysis. Nullable because corpora often redact paths. When present, it is informational only — the schema does not constrain its format.

### `clew_version` (required, string)

Semantic version of the Clew tool that produced this record. Format: `MAJOR.MINOR.PATCH`. v1 records report `0.x.y` until Clew hits a stable 1.0 release.

### `capa_techniques` (required, array of strings)

The list of capa rule matches relevant to evasion that fired on this sample, as produced by Channel 0. Each entry is a capa rule name, e.g. `"check for sandbox files via API"`. An empty array means capa was run and matched no evasion rules. Use an empty array (not null) if capa was not run; absence of capa results is operationally equivalent to "no rules matched."

This field exists primarily to support tier classification and to give analysts a quick at-a-glance summary of what kind of evasion the sample uses.

### `tier_classification` (required, string enum or null)

Clew's tier classification for the sample, derived from `capa_techniques` and other heuristics. One of:

- `tier_1` — full-coverage scope; Pfuzzer's 68 APIs cover the sample's checks
- `tier_2` — partial coverage; some checks fall outside the API list
- `tier_3` — triage-only; sample uses techniques Clew can identify but not extract candidates for
- `tier_4` — triage-only; sample uses techniques Clew cannot identify

Null if classification was skipped (e.g. capa was disabled).

### `total_iterations` (required, integer)

Always `1` in v1. v2 will set this to the total number of iterations the Clew run executed.

### `candidates` (required, array)

The list of candidate records, each describing one API call site and its associated candidate values. An empty array is valid: it means Clew ran successfully but found no extractable environment checks. The fuzzer should treat an empty `candidates` array as "fall back to Pfuzzer's default value lists for this sample."

## Candidate fields

Each entry in `candidates` is an object with exactly the following keys.

### `call_site_va` (required, string)

The virtual address of the API call instruction as a hex string with `0x` prefix. Lowercase by convention; the schema accepts mixed case for tooling tolerance. Example: `"0x00401234"`. This is the canonical identifier for the candidate within a sample.

### `function_va` (required, string)

The virtual address of the function containing the call site. Useful for grouping candidates by function and for cross-referencing back to Binary Ninja sessions.

### `api_name` (required, string, non-empty)

The name of the Windows API being called. For statically-imported APIs, this is the symbol name (e.g. `"GetModuleHandleW"`). For dynamically-resolved APIs, this is the name being resolved (recovered from the `GetProcAddress` argument or equivalent), not the resolver's name.

### `api_resolution` (required, string enum)

How the API was resolved at the call site. One of:

- `import` — statically imported via the IAT
- `getprocaddress` — resolved at runtime via `GetProcAddress` or equivalent
- `ordinal` — resolved by ordinal rather than name
- `hashed` — resolved via API name hashing (FormBook, Carbanak style). **v1 reserves this enum value but produces no records with it.** Channel 2 in v1 does not detect hash-based resolution; v2 will.

### `parameter_index` (required, integer, ≥ -1)

The zero-indexed parameter of the API whose value is the fingerprint of the environment check, or `-1` to indicate the check is on the API's return value rather than an input.

For `GetModuleHandleW(L"SbieDll.dll")`, the parameter at index 0 (`lpModuleName`) carries the fingerprint string, so `parameter_index = 0`. For `IsDebuggerPresent()`, which has no parameters and is checked solely by its return, `parameter_index = -1`.

For APIs that write to output parameters (`GetSystemInfo` writing into a `SYSTEM_INFO` struct), `parameter_index` is the index of that output parameter. Sub-field selection within compound structs is handled by `clew/api_knowledge/` in the producer, not by the schema; this is a documented v1 limitation.

### `comparison_operator` (required, string enum)

The semantic operator of the environment check — how the API's effective output (return, output parameter, or relevant subfield) is compared against detection criteria. One of:

- `equality` — `==` or string equality
- `inequality` — `!=`
- `greater_than`, `less_than`, `greater_equal`, `less_equal` — numeric comparisons
- `bitwise_and`, `bitwise_or` — flag tests
- `contains` — substring or pattern containment (e.g. a registry value contains "VirtualBox")
- `unknown` — Clew identified the call but could not classify the operator

A single call site that performs multiple comparisons of the same parameter should be split into multiple candidate records, one per operator.

When the API has no parameters and the check is on the return value (parameter_index == -1), the comparison_operator describes how a consumer should interpret the return: equality means "consider the check fired when the return matches value." The physical test/cmp/jz instruction implementing this comparison may live in the caller of the API-wrapping function rather than at call_site_va itself.

### `evasion_tier` (required, string enum)

The tier classification for this specific candidate. Same enumeration as `tier_classification`. The sample-level `tier_classification` is the worst tier among its candidates.

### `iteration_number` (required, integer, ≥ 0)

Always `0` in v1. v2 will set this to the iteration in which the candidate was emitted.

### `candidate_values` (required, array, min length 1)

The candidate values for this call site. See [`candidate_values` entry](#candidate_values-entry) below. Must be non-empty: a candidate record with no values is a structural error. If no values can be derived, emit nothing rather than an empty list.

### `coordination_constraint` (required, object)

How this candidate is gated together with others. See [`coordination_constraint`](#coordination_constraint).

### `evidence` (required, object)

The provenance and supporting evidence for the candidate. See [`evidence`](#evidence).

## `candidate_values` entry

Each entry describes one specific value the fuzzer should consider feeding back.

### `value` (required, string | number | boolean | null)

The value at the location indicated by `parameter_index`. Type matches the parameter's natural type: a string for path or module name comparisons, a number for thresholds, a boolean for flag checks. `null` is permitted for cases where the check is "value is null/zero" without a meaningful constant.

When `parameter_index >= 0`, this is the input value passed to the API at that parameter. When `parameter_index == -1`, this is the return value the API would produce in the *detected* state — the value the malware compares against and acts on.

### `represents` (required, string enum)

What the value semantically represents. One of:

- `sandbox_detected` — value indicates the sample is in a sandbox
- `vm_detected` — value indicates virtualization
- `debugger_detected` — value indicates a debugger is attached
- `analysis_tool_detected` — value indicates analyst tooling (Wireshark, Procmon)
- `clean_environment` — value matching what the sample expects in a non-analysis environment
- `threshold_value` — numeric threshold (CPU count, RAM size, screen resolution)
- `unknown` — Clew could not classify

### `retarget_to` (required, string | number | boolean | null)

The value the fuzzer should retarget the API's effective output to in order to make the malware perceive a clean environment. For `GetModuleHandleW(L"SbieDll.dll")`, `retarget_to` is `null` (return NULL means "module not loaded"). For `IsDebuggerPresent`, `retarget_to` is `false`. For a CPU count check `>= 2`, `retarget_to` might be `4`.

### `confidence` (required, number, 0.0 to 1.0)

Clew's confidence that this candidate is real and correctly characterized. The number is a heuristic score, not a calibrated probability. It is comparable across candidates within a single Clew run but is not calibrated against any external dataset. Values near 1.0 indicate near-certainty (e.g. a string-comparison check confirmed by both FLOSS and Binary Ninja dataflow). Values below 0.5 should be treated as speculative.

### `source_channels` (required, array, min length 1)

Which channels contributed to this specific value. Each entry is one of: `capa`, `floss`, `bn_xref`, `drio`, `cape_config`. Multiple channels for the same value increase confidence.

## `coordination_constraint`

### `gate_group_id` (required, string or null)

A string identifier shared by candidates AND-gated together in the binary. The fuzzer interprets this as: "all candidates with the same `gate_group_id` must be flipped together; flipping one without the others does not bypass the check."

In v1 this field is always `null`. v1 does not detect gate groups statically. v2 will populate them.

### `description` (required, string or null)

A human-readable description of the gate, for analyst review. Always `null` in v1.

## `evidence`

### `channels` (required, array, min length 1)

Which channels contributed to identifying the *call site* (as opposed to which channels recovered specific values). Same enumeration as `source_channels`. The distinction matters: Binary Ninja may identify a call site to `GetModuleHandleW` taking some string, while FLOSS recovers what that string actually is — the call site's `channels` is `["bn_xref"]` while a candidate value's `source_channels` is `["floss"]`.

### `string_source` (required, string enum or null)

If the comparison value is a string, where the string was recovered. One of:

- `static` — string in `.rdata` or another static section, with a stable VA
- `stackstring` — constructed on the stack at runtime, no global VA
- `tightstring` — FLOSS-specific category for densely-packed obfuscated strings
- `decoded` — recovered via FLOSS's emulator from a decoder routine

`null` if the comparison value is not a string.

### `string_va` (required, string or null)

The VA where the string lives. Populated when `string_source == "static"`. `null` for stackstrings, tightstrings, decoded strings, or non-string values.

### `string_function_va` (required, string or null)

The VA of the function whose stack frame constructs the string. Populated when `string_source` is `stackstring` or `tightstring`. `null` otherwise. This field exists because stackstrings have no global VA but are anchored to a specific function context — `string_va` alone cannot distinguish "no string" from "string with no global address."

### `dataflow_path` (required, array of strings)

The sequence of instruction VAs Clew traced from the value's source (string reference, API return, or constant load) to the comparison site. Each entry is a VA string. May be empty for candidates derived from FLOSS-only evidence where no dataflow analysis was performed. The path is informational; the fuzzer does not act on it directly, but it is invaluable for analyst debugging when a candidate looks wrong.

### `cmp_operand_a`, `cmp_operand_b` (required, string or null)

Populated by Channel 4. When DynamoRIO observes a `cmp` or `test` instruction following an API return at the call site, both operand values at the time of comparison are logged here as hex strings. `null` for candidates not observed dynamically.

When both are populated, the relation `cmp_operand_a <comparison_operator> cmp_operand_b` should hold true at runtime.

## Enumerations summary

For quick reference:

| Field | Values |
|---|---|
| `tier_classification`, `evasion_tier` | `tier_1`, `tier_2`, `tier_3`, `tier_4` |
| `api_resolution` | `import`, `getprocaddress`, `ordinal`, `hashed` (reserved) |
| `comparison_operator` | `equality`, `inequality`, `greater_than`, `less_than`, `greater_equal`, `less_equal`, `bitwise_and`, `bitwise_or`, `contains`, `unknown` |
| `represents` | `sandbox_detected`, `vm_detected`, `debugger_detected`, `analysis_tool_detected`, `clean_environment`, `threshold_value`, `unknown` |
| `source_channels`, `evidence.channels` | `capa`, `floss`, `bn_xref`, `drio`, `cape_config` |
| `string_source` | `static`, `stackstring`, `tightstring`, `decoded` |

## Examples

These examples are normative. Any change to the schema that breaks them is a breaking change and requires bumping the major version.

### Example 1 — `GetModuleHandleW("SbieDll.dll")` Sandboxie check

A standard Sandboxie detection: the sample calls `GetModuleHandleW` with `"SbieDll.dll"` and treats a non-NULL return as "I'm in Sandboxie." The string is in `.rdata`, found by both FLOSS and Binary Ninja's xref analysis.

```json
{
  "sample_sha256": "a3f4b8c2e9d147a5b6c8d9e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
  "sample_path": "tests/fixtures/sandboxie_check.exe",
  "clew_version": "0.1.0",
  "capa_techniques": ["check for sandbox files via API", "reference sandbox artifacts"],
  "tier_classification": "tier_1",
  "total_iterations": 1,
  "candidates": [
    {
      "call_site_va": "0x00401234",
      "function_va": "0x00401200",
      "api_name": "GetModuleHandleW",
      "api_resolution": "import",
      "parameter_index": 0,
      "comparison_operator": "inequality",
      "evasion_tier": "tier_1",
      "iteration_number": 0,
      "candidate_values": [
        {
          "value": "SbieDll.dll",
          "represents": "sandbox_detected",
          "retarget_to": null,
          "confidence": 0.95,
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
        "string_va": "0x00404020",
        "string_function_va": null,
        "dataflow_path": ["0x00401220", "0x00401228", "0x00401234"],
        "cmp_operand_a": null,
        "cmp_operand_b": null
      }
    }
  ]
}
```

`comparison_operator: inequality` because the malware tests `GetModuleHandleW(...) != NULL`. `retarget_to: null` because returning NULL makes the malware believe Sandboxie is not loaded. `parameter_index: 0` because parameter 0 (`lpModuleName`) carries the fingerprint string `"SbieDll.dll"`.

### Example 2 — `GetProcAddress`-resolved `IsDebuggerPresent` via stackstring

A more sophisticated sample resolves `IsDebuggerPresent` at runtime by passing a stack-constructed string to `GetProcAddress`. The string `"IsDebuggerPresent"` is built byte-by-byte on the stack rather than living in `.rdata`. FLOSS's stackstring recovery finds it; static xref analysis alone would have missed it.

```json
{
  "sample_sha256": "b4e5c9d3f0e258b6c7d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
  "sample_path": "tests/fixtures/dynamic_isdebugger.exe",
  "clew_version": "0.1.0",
  "capa_techniques": ["resolve API by name", "check for debugger via API"],
  "tier_classification": "tier_1",
  "total_iterations": 1,
  "candidates": [
    {
      "call_site_va": "0x004018a0",
      "function_va": "0x00401850",
      "api_name": "IsDebuggerPresent",
      "api_resolution": "getprocaddress",
      "parameter_index": -1,
      "comparison_operator": "equality",
      "evasion_tier": "tier_1",
      "iteration_number": 0,
      "candidate_values": [
        {
          "value": true,
          "represents": "debugger_detected",
          "retarget_to": false,
          "confidence": 0.85,
          "source_channels": ["floss", "bn_xref"]
        }
      ],
      "coordination_constraint": {
        "gate_group_id": null,
        "description": null
      },
      "evidence": {
        "channels": ["floss", "bn_xref"],
        "string_source": "stackstring",
        "string_va": null,
        "string_function_va": "0x00401850",
        "dataflow_path": ["0x00401860", "0x00401872", "0x00401888", "0x004018a0"],
        "cmp_operand_a": null,
        "cmp_operand_b": null
      }
    }
  ]
}
```

`parameter_index: -1` because `IsDebuggerPresent` takes no parameters; the check is on the return value. `value: true` is the dirty-state return (debugger detected). `retarget_to: false` is the clean-state return. `string_source: stackstring`, `string_va: null`, `string_function_va: "0x00401850"` because the string `"IsDebuggerPresent"` is constructed on the stack of the function at `0x00401850` and has no global VA.

## Validation

Use the `jsonschema` Python library:

```python
import json
import jsonschema

schema = json.load(open("schema/clew_record.schema.json"))
record = json.load(open("path/to/record.json"))

jsonschema.validate(record, schema)  # raises on failure
print("OK")
```

Both example records above must validate against the schema. They function as the schema's regression test.

## Open questions deferred to v2

- **Hashed API resolution.** The `hashed` enum value is reserved but unused.
- **Static gate group detection.** `coordination_constraint` fields are always null in v1.
- **Iterative refinement.** `iteration_number` and `total_iterations` are scaffolding-only.
- **Compound output parameters.** Sub-field selection within structs (e.g. `SYSTEM_INFO.dwNumberOfProcessors`) is handled in `clew/api_knowledge/` rather than the schema. v2 may introduce a `parameter_path` field.
- **Multi-comparison call sites.** v1 splits these into multiple candidate records; v2 may introduce a more compact representation.
- **Confidence calibration.** v1's `confidence` is heuristic and uncalibrated.
- **Per-value provenance fields.** v1 places string_source, string_va, and string_function_va in the per-candidate evidence block, which cannot represent multi-value candidates where each value's literal lives at a different address. Record #2 (al-khaser loaded_dlls) surfaces this: 12 wide-string values, 12 distinct .rdata addresses, one schema field. v2 should move these three fields into each candidate_values entry. The homogeneous case (record #1, where there's no string at all) still works — each entry just sets the field to null or "static" as appropriate.

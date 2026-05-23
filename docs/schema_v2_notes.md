# Schema v2 notes

Findings collected while implementing Channel 0 (capa) that the current
schema cannot cleanly express. None of these are bugs in v1 — they are
constraints we accepted to ship a working pilot. Each section is a
candidate for the v2 schema revision.

## 1. Channel 0 boundary: sample-level, not call-site-level

capa is a static-analysis pattern matcher. For some techniques it
identifies a code-level pattern that lines up with a specific call site
(e.g. `check for debugger via API` fires inside the function that calls
`IsDebuggerPresent`, so the rule's match address and our candidate's
function VA agree). For other techniques capa only sees string features
in the binary's data section, with no rule firing at any call site
(e.g. al-khaser's `GetModuleHandleW` DLL fingerprint loop has no rule
matching at the call site; capa's `reference anti-VM strings` rules only
match the literal DLL names sitting in `.rdata`).

Both are legitimate Channel 0 contributions and v1 records both as
`source_channels: ["capa", "bn_xref"]`. But the per-candidate evidence
model can't distinguish "capa fired at the call site" from "capa
matched one of the candidate values as a string." That distinction
matters when downstream consumers want to score capa's confidence in a
specific candidate — a call-site match is direct corroboration that the
function does what the rule says it does, while a value-feature match
only says "this value appears somewhere relevant in the binary" and is
much weaker as per-candidate evidence.

v2 should add a `capa_match_kind` field per candidate-value or per
evidence record, with values `call_site`, `value_feature`, or `both`.

## 2. Coverage gap example: 8 of 12

al-khaser's `loaded_dlls` candidate (record #2 in the fixture set) has
12 fingerprint values. capa's `reference anti-VM strings` rule matches
8 of them:

- `avghookx.dll`, `avghooka.dll`, `snxhk.dll`, `pstorec.dll`,
  `vmcheck.dll`, `wpespy.dll`, `cmdvrt64.dll`, `cmdvrt32.dll`

It misses 4:

- `dbghelp.dll`, `sbiedll.dll`, `api_log.dll`, `dir_watch.dll`

That gap is the concrete justification for Channels 1 (FLOSS) and 2
(BN xref): even when capa fires the right anti-VM rule on the right
function, complete value enumeration requires non-capa channels.
Anyone reviewing the schema and asking "why bother with the other
channels if capa already detects this?" should be pointed at this 8/12
ratio.

## 3. `derivation_status` and per-candidate `evasion_tier` are different concepts

The schema separates two distinct ideas that had collided in earlier
drafts under the single name "tier":

- Sample-level `derivation_status` (`fully_derivable` /
  `partially_derivable` / `not_derivable` / `no_capa_signal`) is a
  rollup of per-rule actionability. A rule is actionable iff it's in
  `CAPA_RULE_TO_APIS` AND all its implied APIs are in
  `PFUZZER_68_APIS`. Sample-level: all actionable → fully_derivable;
  mix → partially_derivable; none → not_derivable; no rules at all →
  no_capa_signal.
- Per-candidate `evasion_tier` (`tier_1`..`tier_4`) is the
  *defeatability tier* of the evasion technique the candidate
  addresses, drawn from the taxonomy in
  `docs/context/evasion-taxonomy.md`.

`no_capa_signal` is also assigned to samples where capa didn't
successfully complete (timeouts, capa errors). Operationally same as
"capa returned no anti-analysis rules": no usable signal from capa.
Run health (timeout rate, error rate) is tracked in the `status` field
alongside the categorical.

Schema v0.3.0 dropped `not_capa_detectable` (never populated, no real
operational path) and renamed `unmapped_only` → `not_derivable` (the
broader category covers both unmapped rules and mapped-but-outside-
target rules).

Open v2 question: when a check is identifiable from capa but
unreachable by the candidate-extraction layer, should `candidates[]`
contain a placeholder record? The current v1 rule is: no — only
extractable checks become candidate records, and `derivation_status`
captures the sample-level "how much of this can we currently do"
question independent of how many candidates landed. v2 may revisit
this if downstream consumers want a per-technique audit trail
regardless of extractability.

`partially_derivable` and `not_derivable` are both reachable in
principle. Under the current `CAPA_RULE_TO_APIS`, every entry produces
APIs that are all inside `PFUZZER_68_APIS`, so non-actionable rules in
practice all come from the "unmapped" failure mode rather than the
"outside-target" failure mode. The categories cover both failure
modes; the data is currently all-one-flavor.

## 4. capa attribution rule for `source_channels`

A candidate value gets `"capa"` in its `source_channels` when at least
one of the following holds:

- **Call-site match.** capa fired a rule whose match address falls
  inside the candidate's function VA range (or, more strictly, equals
  the function VA). Indicates capa identified the same code pattern
  the candidate-extractor identified.
- **Value match.** capa's rule output contains a string-feature regex
  (or literal string match) matching the candidate's value. Indicates
  capa saw the literal value as a string feature in the binary, even
  if no rule fired at the candidate's call site.

Both fixtures' `["capa", "bn_xref"]` attribution is justified under
this rule:

- Record #1 (`IsDebuggerPresent` -> bool comparison): call-site match,
  via `check for debugger via API` firing at the candidate's function.
- Record #2 (`GetModuleHandleW` -> DLL name): value match, via the
  `reference anti-VM strings*` rules matching 8 of 12 DLL fingerprint
  literals.

The schema records the union (`["capa", "bn_xref"]`) but not which
attribution rule each channel was credited under. See finding #1 for
the v2 fix.

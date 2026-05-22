# Clew — DEFCON 34 Demo Lab Slide Outline

## Context
30-minute presentation + 15 min Q&A. Two presenters (Kyler + Anita). Narrative stays capability-level — technical depth lives in the live demo. No academic citations, no tool name-dropping in narrative slides.

---

## Act 1: The Problem (5-7 min)

### Slide 1 — Title
- "Clew: Per-Sample Seed Corpora for Environmental Malware Fuzzing"
- Kyler McElroy & Anita Ding, AFIT
- DEFCON 34 Demo Lab

### Slide 2 — About Us

**Kyler McElroy**
- Born in RAF Lakenheath, England
- Lived in Fordham, England (8 yrs) → Tokyo, Japan (10 yrs) → Columbus, Ohio (4 yrs)
- MS in Computer Science, AI focus at AFIT
- Interested in all things Cyber and AI
- Soccer, snowboarding, reading, some video games, and rearranging my desk for no reason

**Anita Ding**
- TBD — get Anita's info

### Slide 3 — Malware hides its real behavior
- Malware queries the environment before doing anything interesting
- "Am I in a sandbox?" "Is a debugger attached?" "What's the username?"
- If the answer smells like analysis → hide, exit, or lie
- Stat to anchor it: 68% of malware families contain at least one evasive sample (Maffia et al., 180K+ samples analyzed)

### Slide 4 — Environmental fuzzing: the idea
- If malware gates on API return values, we can control those return values
- Hook the API, feed back crafted responses, force the sample down hidden paths
- Visual: simple diagram of API call → hook → fake response → new code path

### Slide 5 — The gap: where do the fake values come from?
- Current approach: a human writes a generic list of values to try ("for GetUserName, try these 10 names")
- Same list for every sample — if a sample checks for something specific, you'll never find it
- Concrete example: sample checks `GetUserNameA` against a hardcoded string "JohnDoe" — a generic list won't have it

### Slide 6 — Scale of the problem
- 54 documented evasion techniques across 9 categories
- ~60% single-call defeatable, ~25% multi-call, ~15% infeasible
- The defeatable ones are where Clew operates — and that's a LOT of techniques with sample-specific values

---

## Act 2: Clew's Approach (3-5 min)

### Slide 7 — What Clew does (one sentence)
- Analyzes each binary *before* fuzzing and extracts the specific values *that sample* compares against
- Output: a per-sample seed corpus keyed to call sites
- Visual: binary → Clew → structured candidate set → fuzzer

### Slide 8 — The GetUserName example, end-to-end
- Sample calls `GetUserNameA`, compares result against hardcoded "JohnDoe"
- Clew identifies the `GetUserNameA` call site, traces the data flow to find what the result is compared against, and extracts "JohnDoe" as a candidate
- Fuzzer now tries "JohnDoe" first instead of random mutations
- Keep this concrete and visual — one walkthrough people can anchor to

### Slide 9 — Static + Dynamic, briefly
- Static: recovers strings, constants, and maps them to their API call sites
- Dynamic: captures comparison values at runtime for cases static misses (hashing, encryption)
- **Don't go deeper than this on slides** — the demo shows the real thing

---

## Act 3: Live Demo (~15 min)

### Slide 10 — Demo intro / what to watch for
- Brief setup slide: "We're going to run Clew against [sample] and show you the output"
- Tell the audience what they're about to see before you show it

### Slides 11-13 — Demo placeholders
- These are just "DEMO" title cards or minimal context slides
- The actual content is the live terminal / tool running
- See demo brainstorm below

### Slide 14 — Demo recap
- Summarize what just happened in case people got lost
- Show the before/after: generic list vs. Clew's per-sample output

---

## Act 4: Impact & What's Next (3-5 min)

### Slide 15 — What this enables
- Any downstream environmental fuzzer benefits — Clew is tool-agnostic
- Automates what was previously manual analyst work
- Lowers the barrier to multi-path malware analysis

### Slide 16 — Availability / closing
- Open source (per submission)
- Repo link, contact info
- End on the capability, not limitations

---

## Demo Brainstorm (TBD)

The demo is ~15 min and is the centerpiece. Options to consider:

### Option A: Single sample, full pipeline
- Pick one PE32 with a known evasion (e.g., GetUserName check or VM artifact query)
- Run Clew end-to-end, show the structured output
- Then show a fuzzer using that output to unlock the hidden path
- **Pro:** Complete story. **Con:** Depends on having a working fuzzer to show the payoff.

### Option B: Clew-only, multiple samples
- Run Clew against 2-3 samples with different evasion types (string check, registry check, module check)
- Show how the output differs per sample (the whole point of per-sample extraction)
- Compare against what a generic list would have given
- **Pro:** Shows breadth, doesn't depend on AriadneX being ready. **Con:** No "and then the malware reveals its payload" moment.

### Option C: Hybrid
- Run Clew on one sample live → show output
- Then show a pre-recorded or scripted demo of that output being fed to a fuzzer and unlocking a hidden path
- **Pro:** Best of both worlds. **Con:** Pre-recorded portion may feel less authentic.

### Demo sample selection criteria
- Must have a clear, audience-understandable evasion (string comparison > hash comparison for demo purposes)
- Ideally something where the hidden behavior is visibly different (drops a file, opens a connection, shows a message)
- Consider using a custom-built sample for reliability — real malware may be flaky in a live setting

---

## Presenter Split (suggestion)

- **Kyler:** Acts 1-2 (problem + approach) — sets up the "why"
- **Anita:** Act 3 (demo) — drives the live portion
- **Both:** Act 4 wrap-up, Q&A
- Adjust based on who's more comfortable with what

---

## Key Constraints
- Don't name academic tools — say "current approaches" or "existing tools"
- Stay capability-level, not implementation-level (no specific tool names on narrative slides)
- Empire and Moriarty Demo Labs are the structural/tone templates
- Leave room to expand slides as Clew develops — this outline is intentionally sparse on "how"

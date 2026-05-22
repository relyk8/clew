# Context for collaborators (and AI sessions)

This file is the durable "who I am and what I'm working on" briefing for anyone — human or AI — picking up Clew with no prior context. It is **not** a project plan or design doc; for those, see [`README.md`](../../README.md) (pilot plan, locked decisions, 12-week schedule) and [`schema.md`](../schema.md) (output contract). This file fills in everything that exists in the author's head but not in the repo: the people, the thesis arc, the class-project history, the venue constraints, and the deadlines currently in play.

Read this first, then the README, then anything else you need from this folder.

---

## The author

**Kyler McElroy.** Second lieutenant and developmental engineer in the United States Air Force. Graduate student at the Air Force Institute of Technology (AFIT) pursuing an MS in Computer Science with an AI focus. Background: ACE Cybersecurity Internship Program alumnus; authored S.A.N.D. (Synthetic Adversarial and Natural Data Generation) under AFRL at Rome, NY; commissioned from Ohio State.

## The collaborator

**Anita Ding.** Second lieutenant and cyber operations officer, USAF. AFIT MS in cyber operations with an AI focus. Her own research is LLM-orchestrated red-team automation and GNNs for AD attack-path scoring — separate from Clew. On Clew she's a co-author and Demo Lab co-presenter. Work is split by channel: she owns the DynamoRIO side (Channel 4) and the dynamic-analysis infrastructure threads; Kyler drives Channel 0 + Channel 2 and the static-analysis side. There is a second Channel 0 effort on Anita's work laptop that's currently disorganized — periodic audit + reconciliation against the clean version in this repo is the workflow there.

---

## The thesis arc — Clew is one of two tools

The full picture, in order of dependency:

1. **Clew** (this repo). Engineering effort. A standalone preprocessing pipeline that runs once per PE32 sample and emits a per-sample seed corpus of candidate values. Production-style: schema-first, tested, CLI. Novelty is that nobody has wired the channels together this way — the individual techniques are known.

2. **AriadneX** (separate repo, parked). Research effort. RL-guided environmental fuzzer built on CAPEv2 + DynamoRIO + Gymnasium + Stable Baselines3. Consumes Clew's output as seeds. Open questions in fuzzer design live here; this is where the RL learning loop sits.

3. **RL contribution** (thesis). The intellectual contribution of the master's thesis is the RL layer of AriadneX — how an agent learns which crafted values to try, in what order, with what reward shaping. Clew is the seed-data dependency that makes that learning tractable.

Implications for any session working in this repo:
- Don't conflate Clew's per-sample extraction contribution with AriadneX's mutation/RL contribution. They are separate claims.
- Don't surface AriadneX in any public-facing Clew material (DEFCON, the open-source repo). AriadneX is unpublished and the strategy is to release Clew first as a standalone tool.
- When AriadneX code shows up in this repo (it does — see `clew/cape_client.py` and `clew/novelty.py`), it's been pulled in because Clew can reuse it. That's documented in the README under "Reusable from AriadneX repo."

---

## Class projects — what they were and what was learned

Three graduate courses are in flight around Clew. Each contributed a lesson that shaped how Clew is being built.

### CSCE 623 — Machine Learning

Original framing: train a model on Pfuzzer's per-iteration features (api_count, baseline_evasive, post_evasive, family, mut_type) to predict per-iteration outcomes (did this iteration produce novel coverage). The original Notebook A built this; results looked fine but the model was learning tautologies, not mechanism.

**Why it failed:** Pfuzzer's outcome depends on the binary's *internal decision structure* — which conditional branches read which API return values, how data flows from a hook to a comparison. None of that is in Pfuzzer's outputs. The features are downstream *summaries of execution* (counts, evasive flags, family metadata), not representations of *cause* (control-flow graph, data-flow, branch predicates). You cannot learn cause→outcome from outcome→outcome data. Best you get is "samples with higher api_count have more chances to succeed" — a near-truism, not a mechanism.

**The pivot:** EMBER 2018 family classification. EMBER's 2,381 LIEF features describe *causes* (PE header structure, byte histograms, import tables, section entropy), and the target (family) is a stable property of the binary itself. The information needed to compute the target actually lives in the features. The model could learn.

**Lesson, generalized:** Before treating a feature-set as predictive, ask "does the information needed to compute the target actually live in these features, or am I asking the features to recover information that exists only inside the binary's runtime?" If the latter, the model will fit but won't be learning. Real ML-for-malware (graph NNs on CFGs, byte-level CNNs, behavioral-embedding models) works precisely because it represents the binary's structure as features.

### CSCE 686 — Reinforcement Learning / Search

Final project explores RL surrogate models in a fuzzing context. **The 623 lesson applies directly:** any surrogate model that tries to extrapolate coverage value for unseen (API, mut_type) pairs or unseen samples needs binary-structure features (import-table embeddings, CFG features), not Pfuzzer-trace summaries. The trap does *not* apply if the evaluation function stays as a direct lookup into Pfuzzer's ground truth — only when you start training a learned predictor.

### CSCE 725 — Reverse Engineering (current)

Clew is being double-dipped as the 725 final project. Topic approved 2026-04-10, abstract submitted 2026-04-24. **Progress report due 2026-05-22 (today)**, final writeup due 2026-06-10. The 725 deliverable can be more exploratory and academically framed than the DEFCON one — academic framing (Pfuzzer citations, EuroS&P 2025 references, the 5.75% unreachable-sample stat) belongs here, not in the DEFCON material.

### General lesson that runs through all three

**Verify mechanism, not correlation.** Distrust results that look right when the features can't possibly carry the information needed. This applies to: ML model design, agent reward shaping, "AI-generated code that looks plausible," and reading other people's tests for tautologies. Pattern-matching is cheap; mechanism is hard.

---

## Venues and framing constraints

Two parallel public stories.

### DEFCON 34 Demo Lab — submitted

Submission is finalized; advisor revised the detailed outline before submission. See [`defcon-submission.txt`](defcon-submission.txt) for the canonical "what Clew is, in public-facing prose." Slide outline at [`defcon-slide-outline.md`](defcon-slide-outline.md) — Acts 1–4 roughed, three-node environmental-fuzzing diagram, GetUserNameA hardcoded-string as the go-to example, deliberate failure case in the demo plan.

**Framing rules for any DEFCON-facing copy:**
- No Pfuzzer name. Describe "current environmental fuzzing approaches" or "existing tools" generically. Demo Labs are showcases, not academic papers — naming a predecessor frames Clew as derivative. Empire and Moriarty don't reference competitors in their Demo Lab abstracts either.
- No AriadneX name. The downstream-fuzzer story is generic ("any API-hooking fuzzer").
- "Per-sample" is the differentiator that anchors every framing.
- The 68% evasion-prevalence stat (Maffia et al. arXiv, 180K samples) replaces less-defensible numbers — the original LLM-generated taxonomy stats are unverifiable and got cut.

### CSCE 725 writeup and thesis — academic framing

Pfuzzer citations, EuroS&P 2025 reference, the 5.75% unreachable-sample stat — all welcome here. This is where the academic-positioning work lives.

### PA approval

Public-affairs approval is a military requirement that gated the DEFCON submission. Done. Future Clew material aimed at public audiences needs to assume PA review is in the loop.

---

## Terminology — use these exact words

Settled with Anita; these aren't preferences, they're decisions:

- **"crafted value"** — not "return value." Many APIs (e.g. `GetUserNameA`) write to out-parameters, not returns. `GetUserNameA` returns `BOOL`; the username lands in `lpBuffer`. "Crafted value" covers both return values and out-parameter cases.
- **"control what the malware sees"** — not "control return values."
- **"per-sample candidates"** — not "return values" in Clew descriptions.
- **"the values the sample compares against"** — these are what Clew extracts, which may be input parameters (e.g. `GetModuleHandle("SbieDll.dll")`) or downstream comparison targets, not just API return values.

---

## Current state and what's live right now

As of 2026-05-22 (the day this file was written):

- This repo has Channel 0 working through commit `c3db90c` — capa wrapper, tier classifier, two al-khaser fixtures reconciled. FLOSS and DynamoRIO pilots complete (`6892dcf`). AriadneX reuse files migrated in (`a7cfc7e`).
- Anita's parallel Channel 0 work lives on her work laptop in a disorganized, AI-gen-heavy state. Audit and salvage is ongoing.
- **Today (Friday 2026-05-22):** CSCE 725 progress report due.
- **Tuesday 2026-05-26:** Clew status presentation. Open question: lift Anita's salvageable work in before then, or present what's in the clean repo as-is.
- **2026-06-10:** CSCE 725 final writeup due.
- **August 2026:** DEFCON 34 Demo Lab presentation.

---

## Where to read next

Order matters:

1. [`README.md`](../../README.md) — pilot study plan, locked decisions, the five channels, 12-week schedule, repo structure. This is the operating doc.
2. [`schema.md`](../schema.md) — output contract.
3. [`schema_v2_notes.md`](../schema_v2_notes.md) — known limits of the v1 schema discovered while implementing Channel 0. Read before proposing schema changes.
4. [`week_01_retrospective.md`](../week_01_retrospective.md), [`week_02_retrospective.md`](../week_02_retrospective.md), [`pilot_results.md`](../pilot_results.md) — what's been done, what was deferred and why.
5. [`clew-brainstorm.md`](clew-brainstorm.md) — original brainstorm with per-channel concerns. Older than the README; treat it as historical context, not current scope.
6. [`defcon-submission.txt`](defcon-submission.txt) — public-facing Clew description.
7. [`defcon-slide-outline.md`](defcon-slide-outline.md) — how Clew is currently being framed publicly.
8. [`evasion-taxonomy.md`](evasion-taxonomy.md) — the 54-technique, 4-tier evasion-defeatability taxonomy. Useful when reasoning about scope (Tier 1 full, Tier 2 partial, Tier 3–4 triage-only).

"""Grade bridge output against a hand-built oracle (`*.expected.json`).

An oracle is a *full* clew schema record. The bridge (`to_partial_candidates`)
produces only the *intermediate*, bridge-owned fields; the rest are filled by
the derivation stage and Channel 4. So grading compares only the bridge-owned
fields and treats derivation-owned fields as report-only context -- never as
failures. This keeps the grade honest: the bridge is not marked wrong for
leaving `represents`/`evasion_tier`/comparison operands unset, because that is
by design.

Bridge-owned (graded):
    call_site_va, function_va, api_name, api_resolution, parameter_index,
    the set of candidate_values[].value,
    evidence.string_source, evidence.dataflow_path

Derivation / Channel-4 (report-only, never a failure):
    comparison_operator, cmp_operand_a/_b, evasion_tier, iteration_number,
    coordination_constraint, candidate_values[].{represents,retarget_to,confidence}

Return-value checks (`parameter_index == -1`, e.g. IsDebuggerPresent): the
"value" is the API's return in the detected state, which is dynamic (Channel 4)
and semantic (derivation), NOT static argument dataflow. For these the bridge
can only be expected to *locate* the call, so only structural identification is
graded; the value and its semantics are report-only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# --- field categories --------------------------------------------------------

# Graded exactly (bridge-owned scalars).
STRUCTURAL_FIELDS = ("call_site_va", "function_va", "api_name", "api_resolution")

# Reported but never failed (owned by derivation / Channel 4).
DERIVATION_FIELDS = ("comparison_operator", "evasion_tier", "coordination_constraint")


@dataclass
class FieldVerdict:
    field: str
    ok: Optional[bool]        # True=match, False=mismatch, None=report-only
    expected: object
    actual: object
    note: str = ""

    def marker(self) -> str:
        return {True: "PASS", False: "FAIL", None: "info"}[self.ok]


@dataclass
class CandidateGrade:
    call_site_va: object
    matched: bool             # did the bridge produce a candidate at this call site?
    is_return_value: bool
    api_name: str = ""
    fields: list = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.matched and not any(f.ok is False for f in self.fields)


# --- helpers -----------------------------------------------------------------

def _va_int(s):
    if isinstance(s, int):
        return s
    try:
        return int(s, 16)
    except (ValueError, TypeError):
        return None


def _val_key(v):
    return v.lower() if isinstance(v, str) else v


def _nonnull_values(cand: dict) -> set:
    return {
        _val_key(cv.get("value"))
        for cv in cand.get("candidate_values", [])
        if cv.get("value") is not None
    }


# --- grading -----------------------------------------------------------------

def grade_candidate(expected: dict, actual: Optional[dict]) -> CandidateGrade:
    csva = expected.get("call_site_va")
    is_rv = expected.get("parameter_index") == -1
    api = expected.get("api_name", "")

    if actual is None:
        return CandidateGrade(csva, matched=False, is_return_value=is_rv, api_name=api,
                              fields=[FieldVerdict("(located)", False, csva,
                                                   None, "bridge produced no candidate here")])

    fields: list[FieldVerdict] = []

    # structural (exact, bridge-owned)
    for f in STRUCTURAL_FIELDS:
        e, a = expected.get(f), actual.get(f)
        if f in ("call_site_va", "function_va"):
            ok = _va_int(e) == _va_int(a)
        else:
            ok = e == a
        fields.append(FieldVerdict(f, ok, e, a))

    # parameter_index (bridge-owned)
    fields.append(FieldVerdict("parameter_index",
                               expected.get("parameter_index") == actual.get("parameter_index"),
                               expected.get("parameter_index"), actual.get("parameter_index")))

    # candidate values
    exp_vals = _nonnull_values(expected)
    act_vals = _nonnull_values(actual)
    if is_rv:
        fields.append(FieldVerdict(
            "candidate_values.value", None,
            sorted(map(str, exp_vals)), sorted(map(str, act_vals)),
            "return-value check -> value is Channel 4 / derivation, not static arg dataflow"))
    else:
        missing = exp_vals - act_vals
        extra = act_vals - exp_vals
        note = ""
        if missing:
            note += f"MISSING from bridge: {sorted(map(str, missing))} "
        if extra:
            note += f"(extra found by bridge: {sorted(map(str, extra))})"
        fields.append(FieldVerdict("candidate_values.value(set)", len(missing) == 0,
                                   sorted(map(str, exp_vals)), sorted(map(str, act_vals)),
                                   note.strip()))

    # evidence: string_source (bridge-owned unless return-value), dataflow_path
    ev_e = expected.get("evidence", {}) or {}
    ev_a = actual.get("evidence", {}) or {}
    if is_rv:
        fields.append(FieldVerdict("evidence.string_source", None,
                                   ev_e.get("string_source"), ev_a.get("string_source"),
                                   "return-value"))
        fields.append(FieldVerdict("evidence.dataflow_path", None,
                                   ev_e.get("dataflow_path"), ev_a.get("dataflow_path"),
                                   "return-value"))
    else:
        fields.append(FieldVerdict("evidence.string_source",
                                   ev_e.get("string_source") == ev_a.get("string_source"),
                                   ev_e.get("string_source"), ev_a.get("string_source")))
        dfa = ev_a.get("dataflow_path") or []
        csi = _va_int(csva)
        includes = csi is not None and any(_va_int(x) == csi for x in dfa)
        df_ok = len(dfa) > 0 and includes
        fields.append(FieldVerdict("evidence.dataflow_path", df_ok,
                                   ev_e.get("dataflow_path"), dfa,
                                   "" if df_ok else "expected a non-empty path reaching the call site"))

    # derivation-owned (report-only)
    for f in DERIVATION_FIELDS:
        fields.append(FieldVerdict(f, None, expected.get(f), actual.get(f), "derivation stage"))
    exp_sem = [(cv.get("value"), cv.get("represents"), cv.get("retarget_to"))
               for cv in expected.get("candidate_values", [])]
    fields.append(FieldVerdict("candidate_values.represents/retarget_to", None, exp_sem,
                               "[unknown / null]", "derivation stage"))

    return CandidateGrade(csva, matched=True, is_return_value=is_rv, api_name=api, fields=fields)


def grade_record(expected_record: dict, bridge_candidates: list) -> list:
    """Grade every candidate in an oracle record against the bridge's candidates,
    matched by call_site_va (and parameter_index when several share a site)."""
    by_va: dict = {}
    for c in bridge_candidates:
        by_va.setdefault(_va_int(c.get("call_site_va")), []).append(c)

    grades = []
    for exp in expected_record.get("candidates", []):
        cands = by_va.get(_va_int(exp.get("call_site_va")), [])
        actual = None
        if cands:
            pi = exp.get("parameter_index")
            actual = next((c for c in cands if c.get("parameter_index") == pi), cands[0])
        grades.append(grade_candidate(exp, actual))
    return grades


# --- reporting ---------------------------------------------------------------

def format_report(grades: list, title: str = "") -> str:
    lines = []
    if title:
        lines.append(f"=== oracle grade: {title} ===")
    for g in grades:
        verdict = "PASS" if g.passed else ("NO-MATCH" if not g.matched else "REVIEW")
        rv = " [return-value]" if g.is_return_value else ""
        csva = g.call_site_va
        lines.append(f"\ncandidate {csva} {g.api_name}{rv}: {verdict}")
        for f in g.fields:
            m = f.marker()
            base = f"  [{m}] {f.field}"
            if f.ok is None:
                lines.append(f"{base}: oracle={f.expected!r} bridge={f.actual!r}"
                             + (f"  ({f.note})" if f.note else ""))
            elif f.ok:
                lines.append(f"{base}")
            else:
                lines.append(f"{base}: oracle={f.expected!r} bridge={f.actual!r}"
                             + (f"  {f.note}" if f.note else ""))
    npass = sum(1 for g in grades if g.passed)
    lines.append(f"\n{npass}/{len(grades)} candidates pass bridge-owned grading.")
    return "\n".join(lines)


def all_passed(grades: list) -> bool:
    return bool(grades) and all(g.passed for g in grades)

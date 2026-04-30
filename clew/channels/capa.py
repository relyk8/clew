"""Channel 0: capa preprocessing.

Wraps the capa CLI (flare-capa) and parses its JSON output. capa is a
sample-level / feature-level signal, not a per-call-site signal. See
docs/schema_v2_notes.md for the full architectural note.

Version pinning: this module assumes a coordinated set of (flare-capa,
capa-rules tag, capa sigs commit). Mismatches will silently change which
rules fire. Pin all three together when integrating.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class CapaError(Exception):
    """Base error for Channel 0."""


class CapaNotFoundError(CapaError):
    """capa binary not on PATH or not executable."""


class CapaRunError(CapaError):
    """capa ran but returned a nonzero exit code."""


class CapaParseError(CapaError):
    """capa returned output that wasn't parseable JSON."""


@dataclass(frozen=True)
class CapaResult:
    rule_names: frozenset[str]
    rule_matches: dict[str, list[int]]  # rule_name -> [function_VAs]
    raw: dict


EVASION_NAME_OVERRIDES: frozenset[str] = frozenset({
    "find graphical window",
    "check process job object",
    "check for unmoving mouse cursor",
    "check for time delay via GetTickCount",
    "acquire debug privileges",
    "execute anti-debugging instructions",
})


def run_capa(
    sample_path: Path,
    *,
    rules_path: Path,
    sigs_path: Path,
    capa_bin: str = "capa",
    timeout: int = 300,
) -> CapaResult:
    """Run capa against a PE; return parsed result."""
    cmd = [
        capa_bin,
        "-r", str(rules_path),
        "-s", str(sigs_path),
        "-j",
        str(sample_path),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as e:
        raise CapaNotFoundError(f"capa binary not found: {capa_bin}") from e

    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace")
        raise CapaRunError(
            f"capa exited with code {proc.returncode}: {stderr}"
        )

    stdout = proc.stdout.decode("utf-8", errors="replace")
    return _parse_capa_json(stdout)


def _parse_capa_json(data: dict | str) -> CapaResult:
    """Parse capa JSON output into a CapaResult.

    Address objects in capa output have shape {"type": "absolute", "value": int}.
    Each rule's `matches` is a list of [address_obj, result_node] pairs.
    Extract the function VA from match[0]["value"] for each match.

    If `data` is a string, json.loads it. If parsing fails, raise CapaParseError.
    Handles capa's banner/log lines that may precede the JSON by finding the
    first '{' if needed.
    """
    if isinstance(data, str):
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            brace = data.find("{")
            if brace == -1:
                raise CapaParseError("no JSON object found in capa output")
            try:
                parsed = json.loads(data[brace:])
            except json.JSONDecodeError as e:
                raise CapaParseError(f"could not parse capa JSON: {e}") from e
    elif isinstance(data, dict):
        parsed = data
    else:
        raise CapaParseError(f"unexpected data type for capa output: {type(data)}")

    rules = parsed.get("rules")
    if not isinstance(rules, dict):
        raise CapaParseError("capa output missing 'rules' object")

    rule_names = frozenset(rules.keys())
    rule_matches: dict[str, list[int]] = {}
    for name, rule in rules.items():
        matches = rule.get("matches") or []
        vas: set[int] = set()
        for match in matches:
            if not isinstance(match, list) or len(match) < 1:
                continue
            addr = match[0]
            if not isinstance(addr, dict):
                continue
            if addr.get("type") != "absolute":
                continue
            value = addr.get("value")
            if isinstance(value, int):
                vas.add(value)
        rule_matches[name] = sorted(vas)

    return CapaResult(rule_names=rule_names, rule_matches=rule_matches, raw=parsed)


def filter_evasion_techniques(
    rule_names: Iterable[str],
    rules_meta: dict,
) -> list[str]:
    """Filter rule_names to evasion-relevant rules. Returns sorted list.

    A rule is evasion-relevant if its meta.namespace starts with 'anti-analysis/'
    OR its name is in EVASION_NAME_OVERRIDES.
    """
    out: set[str] = set()
    for name in rule_names:
        if name in EVASION_NAME_OVERRIDES:
            out.add(name)
            continue
        rule = rules_meta.get(name)
        if not isinstance(rule, dict):
            continue
        ns = rule.get("meta", {}).get("namespace") or ""
        if ns == "anti-analysis" or ns.startswith("anti-analysis/"):
            out.add(name)
    return sorted(out)

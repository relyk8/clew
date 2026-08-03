"""Pure parser for the DynamoRIO `drtrace` client's logs.

Channel 3's client (see `cape_packages/drtrace/drtrace.c` and its README for the
frozen v1 format) emits four record types into per-thread text logs: module
loads, API calls, API returns, and comparisons. This module does only the parse,
stdlib only, so its test runs offline with no network and no monkeypatch.

The comparison record is identical to `cmplog`'s, so it is parsed by
`cmplog_parse.parse_comparison_line` rather than reimplemented here.

Two properties of the format shape this parser:

- **Strings arrive hex-encoded** (`A:` ascii, `W:` utf-16le). The client encodes
  them because the bytes come from memory the sample controls; decoding is
  therefore the one place where attacker-chosen content enters the host, and it
  is bounded and error-tolerant here rather than trusted.
- **Every record carries a global `seq`**, so call, return and comparison records
  can be ordered against each other across threads. That ordering is what lets
  the correlator bind a comparison to the API return that produced its operand.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .cmplog_parse import (
    MAX_LINE_LEN,
    MAX_RECORDS,
    CmpRecord,
    _bounded_lines,
    parse_comparison_line,
)

logger = logging.getLogger(__name__)

# Caps. Same reasoning as cmplog_parse: the logs are attacker-influenced, so
# bound what a hostile sample can make the host allocate.
MAX_HEX_CHARS = 4096

_M_RE = re.compile(
    r"^M\s+seq=(\d+)\s+base=(0x[0-9a-fA-F]+)\s+end=(0x[0-9a-fA-F]+)\s+name=([0-9a-fA-F]*)\s*$"
)
_C_RE = re.compile(r"^C\s+seq=(\d+)\s+T(\d+)\s+api=(\w{1,64})\s+site=(0x[0-9a-fA-F]+)(.*)$")
_R_RE = re.compile(
    r"^R\s+seq=(\d+)\s+T(\d+)\s+api=(\w{1,64})\s+site=(0x[0-9a-fA-F]+)"
    r"\s+rv=(0x[0-9a-fA-F]+)(.*)$"
)
_CAPPED_RE = re.compile(r"^#\s*capped\s+api=(\w{1,64})\s+site=(0x[0-9a-fA-F]+)\s+after\s+(\d+)")

# a<i>=0x<hex>  -- one raw argument slot.
_ARG_RE = re.compile(r"\ba(\d+)=(0x[0-9a-fA-F]+)")
# s<i>=A:<hex> (argument at call time) / o<i>=A:<hex> (re-read after return).
_STR_RE = re.compile(r"\b([so])(\d+)=([AW]):([0-9a-fA-F]*)")


def decode_hex_string(kind: str, hexdigits: str) -> str | None:
    """Decode one hex-encoded logged string. None if it is unusable.

    Decoding is deliberately lossy-tolerant (`errors="replace"`): these bytes
    came from the sample's memory via a heuristic that only claimed they *look*
    like text, so a partial or mis-classified read should degrade to a visibly
    odd string rather than raise.
    """
    if not hexdigits or len(hexdigits) > MAX_HEX_CHARS or len(hexdigits) % 2:
        return None
    try:
        raw = bytes.fromhex(hexdigits)
    except ValueError:
        return None
    text = raw.decode("utf-16-le" if kind == "W" else "ascii", errors="replace")
    # The client logs up to the terminator but a truncated read can leave one.
    return text.rstrip("\x00") or None


@dataclass(frozen=True)
class ModuleRecord:
    """One module load, with the runtime extent used to rebase PCs."""

    seq: int
    base: int
    end: int
    name: str | None

    def contains(self, pc: int) -> bool:
        return self.base <= pc < self.end


@dataclass(frozen=True)
class ApiCall:
    """One observed API call, pairing its `C` record with its matching `R`.

    `args` holds the raw argument values; `arg_strings` and `out_strings` hold
    the dereferenced text keyed by argument index, from call time and after the
    return respectively. `out_strings` is where out-parameters land -- values the
    environment supplied that exist nowhere in the binary.

    `site` is the return address in the caller, so it joins directly against a
    static candidate's `call_site_va`.
    """

    seq: int
    tid: int
    api: str
    site: int
    args: dict[int, int] = field(default_factory=dict)
    arg_strings: dict[int, str] = field(default_factory=dict)
    return_seq: int | None = None
    retval: int | None = None
    out_strings: dict[int, str] = field(default_factory=dict)

    @property
    def returned(self) -> bool:
        """Whether a matching return was seen. A call without one was still in
        flight when the process died -- common under CAPE's timeout-kill."""
        return self.return_seq is not None


@dataclass(frozen=True)
class CappedNotice:
    """A (API, call site) pair that hit the client's per-site logging cap.

    Surfaced rather than swallowed: a capped pair means the trace under-counts
    that site, and a consumer that silently treated the count as complete would
    be wrong."""

    api: str
    site: int
    after: int


@dataclass
class Trace:
    """Everything one drtrace run produced."""

    modules: list[ModuleRecord] = field(default_factory=list)
    calls: list[ApiCall] = field(default_factory=list)
    comparisons: list[CmpRecord] = field(default_factory=list)
    capped: list[CappedNotice] = field(default_factory=list)

    def main_module(self, sample_name: str | None = None) -> ModuleRecord | None:
        """The sample's own module, whose base is what PCs rebase against.

        Prefers an exact name match on the submitted sample, then the sole `.exe`
        module, then the first module logged (DR reports the main executable
        first). Returns None when no modules were logged at all, which is what a
        legacy cmplog log looks like.
        """
        if not self.modules:
            return None
        if sample_name:
            wanted = sample_name.lower()
            for m in self.modules:
                if m.name and m.name.lower() == wanted:
                    return m
        exes = [m for m in self.modules if m.name and m.name.lower().endswith(".exe")]
        if len(exes) == 1:
            return exes[0]
        return exes[0] if exes else self.modules[0]


def _parse_strings(tail: str) -> tuple[dict[int, str], dict[int, str]]:
    """Split the `s<i>=` / `o<i>=` tokens in a record tail into (call, return)."""
    at_call: dict[int, str] = {}
    at_return: dict[int, str] = {}
    for tag, idx, kind, hexdigits in _STR_RE.findall(tail):
        text = decode_hex_string(kind, hexdigits)
        if text is None:
            continue
        (at_call if tag == "s" else at_return)[int(idx)] = text
    return at_call, at_return


def parse_drtrace_lines(lines: Iterable[str], max_records: int | None = None) -> Trace:
    """Parse drtrace log lines into a `Trace`.

    Calls and returns are paired per thread with a stack, so a wrapped API that
    re-enters (or one wrapped API calling another) pairs correctly rather than by
    nearest-match. A call left unpaired keeps `returned == False`.
    """
    cap = MAX_RECORDS if max_records is None else max_records
    unlimited = cap == 0
    trace = Trace()
    # Per-thread stack of in-flight calls, so nesting pairs correctly.
    pending: dict[int, list[dict]] = {}
    total = 0

    for line in lines:
        if len(line) > MAX_LINE_LEN:
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if not unlimited and total >= cap:
            logger.warning("drtrace record cap (%d) reached; truncating", cap)
            break

        if stripped.startswith("#"):
            m = _CAPPED_RE.match(stripped)
            if m:
                trace.capped.append(
                    CappedNotice(api=m.group(1), site=int(m.group(2), 16), after=int(m.group(3)))
                )
            continue

        head = stripped[0]
        if head == "M":
            m = _M_RE.match(stripped)
            if m:
                trace.modules.append(
                    ModuleRecord(
                        seq=int(m.group(1)),
                        base=int(m.group(2), 16),
                        end=int(m.group(3), 16),
                        name=decode_hex_string("A", m.group(4)),
                    )
                )
                total += 1
            continue

        if head == "C":
            m = _C_RE.match(stripped)
            if m:
                tail = m.group(5)
                at_call, _ = _parse_strings(tail)
                entry = {
                    "seq": int(m.group(1)),
                    "tid": int(m.group(2)),
                    "api": m.group(3),
                    "site": int(m.group(4), 16),
                    "args": {int(i): int(v, 16) for i, v in _ARG_RE.findall(tail)},
                    "arg_strings": at_call,
                }
                pending.setdefault(entry["tid"], []).append(entry)
                total += 1
            continue

        if head == "R":
            m = _R_RE.match(stripped)
            if m:
                tid, api, site = int(m.group(2)), m.group(3), int(m.group(4), 16)
                _, at_return = _parse_strings(m.group(6))
                stack = pending.get(tid, [])
                entry = None
                # Match the innermost in-flight call for this (api, site).
                for i in range(len(stack) - 1, -1, -1):
                    if stack[i]["api"] == api and stack[i]["site"] == site:
                        entry = stack.pop(i)
                        break
                if entry is not None:
                    trace.calls.append(
                        ApiCall(
                            seq=entry["seq"],
                            tid=entry["tid"],
                            api=entry["api"],
                            site=entry["site"],
                            args=entry["args"],
                            arg_strings=entry["arg_strings"],
                            return_seq=int(m.group(1)),
                            retval=int(m.group(5), 16),
                            out_strings=at_return,
                        )
                    )
                total += 1
            continue

        record = parse_comparison_line(stripped)
        if record is not None:
            trace.comparisons.append(record)
            total += 1

    # Calls still in flight at the end of the log: the process died before they
    # returned, which CAPE's timeout-kill makes routine. Keep them -- the
    # arguments were still observed, only the return value is missing.
    for stack in pending.values():
        for entry in stack:
            trace.calls.append(
                ApiCall(
                    seq=entry["seq"],
                    tid=entry["tid"],
                    api=entry["api"],
                    site=entry["site"],
                    args=entry["args"],
                    arg_strings=entry["arg_strings"],
                )
            )
    trace.calls.sort(key=lambda c: c.seq)
    return trace


def parse_drtrace_files(paths: Iterable[Path], max_records: int | None = None) -> Trace:
    """Read and merge drtrace logs. One unreadable file is skipped.

    Merging across files is correct because `seq` is global to the process, not
    per-thread: the module table lives in its own file and the per-thread traces
    interleave into one consistent ordering.
    """
    cap = MAX_RECORDS if max_records is None else max_records
    unlimited = cap == 0
    merged = Trace()
    for path in paths:
        # The cap is a budget across all files, not per file: a hostile sample
        # can choose how many threads it spawns, and therefore how many logs
        # there are to read.
        used = len(merged.comparisons) + len(merged.calls) + len(merged.modules)
        if not unlimited and used >= cap:
            logger.warning("drtrace record cap (%d) reached; skipping remaining files", cap)
            break
        try:
            with Path(path).open(encoding="utf-8", errors="replace") as fh:
                part = parse_drtrace_lines(
                    _bounded_lines(fh), max_records=0 if unlimited else cap - used
                )
        except OSError as exc:
            logger.warning("skipping unreadable drtrace file %s (%s)", path, exc)
            continue
        merged.modules.extend(part.modules)
        merged.calls.extend(part.calls)
        merged.comparisons.extend(part.comparisons)
        merged.capped.extend(part.capped)

    merged.modules.sort(key=lambda m: m.seq)
    merged.calls.sort(key=lambda c: c.seq)
    return merged

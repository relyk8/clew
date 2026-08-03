"""Pure parser for the DynamoRIO `cmplog` client's per-thread logs.

Channel 3 correlation joins runtime comparison operands (captured by the
`cmplog` DR client, see `cape_packages/cmplog/cmplog.c`) against static call
sites. That join needs the raw logs as typed records. This module does only the
parse (log lines to `CmpRecord` list), stdlib only, so its test runs offline
with no network and no monkeypatch.

Log format (one body line per captured `OP_cmp`/`OP_test`):

    T<tid> pc=0x<hex> <opcode> src0=<kind> src1=<kind> ...

`#` header/comment lines and blank lines are skipped. There can be more than two
`src` operands. Operand kinds are `reg:NAME=0x<hex>`, `imm=0x<hex>`,
`mem[0x<addr>]=0x<hex>` (or `mem[0x<addr>]=<unreadable>`), and bare `other`.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)

# Keep opcodes the correlator understands. Defensive against a future client
# that logs more (jcc, sub, ...).
_KEPT_OPCODES = frozenset({"cmp", "test"})

# Caps: the logs are attacker-influenced (a sample controls how many comparisons
# it executes, and can write into the shared guest filesystem), so bound both the
# total records accumulated and any single line's length to keep the host parser
# from exhausting memory. A real run is tens of thousands of short lines; these
# ceilings sit far above that.
MAX_RECORDS = 5_000_000
MAX_LINE_LEN = 8192

# T<tid> pc=0x<hex> <opcode> <rest-of-operands>
_LINE_RE = re.compile(r"^T(\d+)\s+pc=(0x[0-9a-fA-F]+)\s+(\S+)(.*)$")

# One operand token: src<i>=<value>, value has no spaces.
_SRC_RE = re.compile(r"src\d+=(\S+)")

# drtrace v1 additions, absent from cmplog logs. They sit in the same tail this
# parser already scans for operands, so a drtrace log parses either way.
_SEQ_RE = re.compile(r"\bseq=(\d+)\b")
_JCC_RE = re.compile(r"\bjcc=(\w{1,16})\b")

_REG_RE = re.compile(r"^reg:(\w+)=(0x[0-9a-fA-F]+)$")
_IMM_RE = re.compile(r"^imm=(0x[0-9a-fA-F]+)$")
_MEM_RE = re.compile(r"^mem\[(0x[0-9a-fA-F]+)\]=(0x[0-9a-fA-F]+|<unreadable>)$")


@dataclass(frozen=True)
class Operand:
    """One source operand of a logged comparison.

    `kind` is "reg", "imm", "mem", or "other". `value` is the concrete hex value
    (None for an unreadable mem read or an "other" operand). `reg` holds the
    register name for reg kind, `addr` the computed address for mem kind.
    """

    kind: str
    value: int | None = None
    reg: str | None = None
    addr: int | None = None


@dataclass(frozen=True)
class CmpRecord:
    """One captured comparison instruction with its live source operands.

    `seq` and `jcc` are only present in `drtrace` v1 logs and stay None for
    `cmplog` logs. `seq` is the client's global record counter, which orders this
    comparison against the API returns in the same trace. `jcc` is the mnemonic
    of the conditional branch that consumed the comparison's flags, which is what
    resolves a bare `cmp` to a concrete operator.
    """

    tid: int
    pc: int
    opcode: str
    operands: list[Operand]
    seq: int | None = None
    jcc: str | None = None


def _parse_operand(token: str) -> Operand | None:
    """Classify one `src<i>=` value token. None if it matches no known kind."""
    m = _REG_RE.match(token)
    if m:
        return Operand(kind="reg", value=int(m.group(2), 16), reg=m.group(1))
    m = _IMM_RE.match(token)
    if m:
        return Operand(kind="imm", value=int(m.group(1), 16))
    m = _MEM_RE.match(token)
    if m:
        addr = int(m.group(1), 16)
        raw = m.group(2)
        value = None if raw == "<unreadable>" else int(raw, 16)
        return Operand(kind="mem", value=value, addr=addr)
    if token == "other":
        return Operand(kind="other")
    return None


def parse_comparison_line(line: str) -> CmpRecord | None:
    """Parse one comparison line to a `CmpRecord`. None if it is not one.

    Public because `drtrace_parse` reuses it: the comparison record is identical
    in both log formats apart from the optional `seq=` / `jcc=` tokens, so there
    is one implementation rather than two that can drift.
    """
    m = _LINE_RE.match(line)
    if not m:
        return None
    opcode = m.group(3).lower()
    if opcode not in _KEPT_OPCODES:
        return None
    tail = m.group(4)
    operands = [op for tok in _SRC_RE.findall(tail) if (op := _parse_operand(tok))]
    seq_match = _SEQ_RE.search(tail)
    jcc_match = _JCC_RE.search(tail)
    return CmpRecord(
        tid=int(m.group(1)),
        pc=int(m.group(2), 16),
        opcode=opcode,
        operands=operands,
        seq=int(seq_match.group(1)) if seq_match else None,
        jcc=jcc_match.group(1).lower() if jcc_match else None,
    )


# Retained for the module's own internal use and existing callers.
_parse_line = parse_comparison_line


def parse_cmplog_lines(lines: Iterable[str], max_records: int | None = None) -> list[CmpRecord]:
    """Parse cmplog log lines to `CmpRecord`s. Malformed and pathologically long
    lines are skipped; accumulation stops at `max_records` (default MAX_RECORDS,
    `0` = unlimited)."""
    cap = MAX_RECORDS if max_records is None else max_records
    unlimited = cap == 0
    records: list[CmpRecord] = []
    for line in lines:
        if len(line) > MAX_LINE_LEN:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        record = _parse_line(stripped)
        if record is not None:
            records.append(record)
            if not unlimited and len(records) >= cap:
                logger.warning("cmplog record cap (%d) reached; truncating", cap)
                break
    return records


def _bounded_lines(fh, max_line_len: int = MAX_LINE_LEN, chunk_size: int = 65536):
    """Yield newline-delimited lines from `fh` without buffering an unbounded
    single line. A stretch longer than `max_line_len` with no newline (a
    malformed or hostile log) is dropped and parsing resyncs at the next
    newline, so one giant line can't exhaust host memory."""
    buf = ""
    for chunk in iter(lambda: fh.read(chunk_size), ""):
        buf += chunk
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            yield line
        if len(buf) > max_line_len:
            buf = ""  # drop the oversized partial line; resync at next newline
    if buf:
        yield buf


def parse_cmplog_files(paths: Iterable[Path], max_records: int | None = None) -> list[CmpRecord]:
    """Read and concatenate cmplog logs. One unreadable/bad file is skipped;
    total records are capped at `max_records` (default MAX_RECORDS, `0` =
    unlimited) across all files."""
    cap = MAX_RECORDS if max_records is None else max_records
    unlimited = cap == 0
    records: list[CmpRecord] = []
    for path in paths:
        if not unlimited and len(records) >= cap:
            break
        try:
            remaining = 0 if unlimited else cap - len(records)
            with Path(path).open(encoding="utf-8", errors="replace") as fh:
                records.extend(parse_cmplog_lines(_bounded_lines(fh), max_records=remaining))
        except OSError as exc:
            logger.warning("skipping unreadable cmplog file %s (%s)", path, exc)
    return records

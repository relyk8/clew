"""Offline tests for the pure cmplog log parser.

Inline string fixtures only, no external files, no network, no monkeypatch.
"""

from __future__ import annotations

from clew.channels.cape.cmplog_parse import (
    CmpRecord,
    Operand,
    parse_cmplog_files,
    parse_cmplog_lines,
)

# Header/comment + blank lines mixed with body lines, plus every operand kind,
# an nsrcs>2 line, a malformed line, and a non-kept opcode.
SAMPLE = """\
# clew cmplog thread=2996 pid=8672
# fields: T<tid> pc=<app_pc> <opcode> src[i]=<kind>:<hexval>...

T2996 pc=0x77c35c1d test src0=reg:eax=0x102 src1=reg:eax=0x102
T2996 pc=0x77c35c25 test src0=mem[0x0084fe24]=0x0 src1=imm=0x1
T2996 pc=0x77c67e50 cmp src0=mem[0x77d25da8]=<unreadable> src1=imm=0x0
T2996 pc=0x77c42435 cmp src0=reg:ecx=0x1 src1=imm=0x2 src2=other
T2996 pc=0xdeadbeef sub src0=reg:eax=0x1 src1=reg:ebx=0x2
this is not a cmplog line at all
"""


def test_comments_and_blanks_skipped_and_body_parsed():
    records = parse_cmplog_lines(SAMPLE.splitlines())
    # Six non-comment/non-blank lines, but the `sub` opcode and the garbage line
    # drop out, leaving four kept records.
    assert len(records) == 4
    assert all(isinstance(r, CmpRecord) for r in records)


def test_register_and_immediate_operands():
    (rec,) = parse_cmplog_lines(
        ["T2996 pc=0x77c35c1d test src0=reg:eax=0x102 src1=imm=0x1"]
    )
    assert rec == CmpRecord(
        tid=2996,
        pc=0x77C35C1D,
        opcode="test",
        operands=[
            Operand(kind="reg", value=0x102, reg="eax"),
            Operand(kind="imm", value=0x1),
        ],
    )


def test_memory_operand_readable_and_unreadable():
    readable, unreadable = parse_cmplog_lines(
        [
            "T1 pc=0x1000 cmp src0=mem[0x0084fe24]=0x2a src1=imm=0x0",
            "T1 pc=0x1004 cmp src0=mem[0x77d25da8]=<unreadable> src1=imm=0x0",
        ]
    )
    assert readable.operands[0] == Operand(kind="mem", value=0x2A, addr=0x0084FE24)
    # Unreadable mem read carries the address but a None value.
    assert unreadable.operands[0] == Operand(kind="mem", value=None, addr=0x77D25DA8)


def test_other_operand_and_nsrcs_over_two():
    (rec,) = parse_cmplog_lines(
        ["T7 pc=0x2000 cmp src0=reg:ecx=0x1 src1=imm=0x2 src2=other"]
    )
    assert len(rec.operands) == 3
    assert rec.operands[2] == Operand(kind="other", value=None, reg=None, addr=None)


def test_opcode_filter_keeps_only_cmp_and_test():
    records = parse_cmplog_lines(
        [
            "T1 pc=0x1 cmp src0=imm=0x1 src1=imm=0x1",
            "T1 pc=0x2 test src0=imm=0x1 src1=imm=0x1",
            "T1 pc=0x3 sub src0=imm=0x1 src1=imm=0x1",
            "T1 pc=0x4 jz src0=imm=0x1",
        ]
    )
    assert [r.opcode for r in records] == ["cmp", "test"]


def test_hex_fields_are_parsed_as_ints():
    (rec,) = parse_cmplog_lines(["T2996 pc=0x77c35c1d cmp src0=reg:eax=0xdeadbeef src1=imm=0x0"])
    assert rec.tid == 2996
    assert rec.pc == 0x77C35C1D
    assert rec.operands[0].value == 0xDEADBEEF


def test_malformed_lines_tolerated():
    records = parse_cmplog_lines(
        [
            "garbage",
            "T not-a-number pc=0x1 cmp",
            "Tabc pc=0x1 cmp src0=imm=0x1",
            "T1 pc=0x1 cmp src0=imm=0x1 src1=imm=0x2",
        ]
    )
    # Only the last well-formed line survives.
    assert len(records) == 1
    assert records[0].pc == 0x1


def test_parse_files_reads_and_concatenates(tmp_path):
    a = tmp_path / "cmplog.1.log"
    b = tmp_path / "cmplog.2.log"
    a.write_text("# hdr\nT1 pc=0x1 cmp src0=imm=0x1 src1=imm=0x2\n")
    b.write_text("T2 pc=0x2 test src0=reg:al=0x0 src1=reg:al=0x0\n")
    records = parse_cmplog_files([a, b])
    assert [r.tid for r in records] == [1, 2]


def test_parse_files_skips_one_bad_file(tmp_path):
    good = tmp_path / "cmplog.good.log"
    good.write_text("T1 pc=0x1 cmp src0=imm=0x1 src1=imm=0x2\n")
    missing = tmp_path / "does-not-exist.log"
    # A missing/unreadable file is skipped, the good one still parses.
    records = parse_cmplog_files([missing, good])
    assert len(records) == 1
    assert records[0].tid == 1

"""Offline tests for the drtrace log parser.

Fixtures are written inline rather than shipped as files: the format is frozen in
`cape_packages/drtrace/README.md`, and a test that spells out the exact bytes it
expects is the clearer regression guard against drifting from it.
"""

from __future__ import annotations

from clew.channels.cape.drtrace_parse import (
    decode_hex_string,
    parse_drtrace_files,
    parse_drtrace_lines,
)


def _hex(text: str, wide: bool = False) -> str:
    return text.encode("utf-16-le" if wide else "ascii").hex()


_CALL_LINE = (
    "C seq=10 T2224 api=GetModuleHandleW site=0x0041a2f0 "
    f'a0=0x0019fb14 s0=W:{_hex("SbieDll.dll", True)} a1=0x0'
)

# A short but complete trace: two modules, a wrapped call with a wide-string
# argument that returns NULL, an out-parameter call, a comparison carrying its
# jcc, and a capped notice.
SAMPLE_LOG = f"""\
# drtrace v1 pid=5148 tid=2224
M seq=1 base=0x00400000 end=0x0049a000 name={_hex("autoit3.exe")}
M seq=2 base=0x77c10000 end=0x77d50000 name={_hex("kernel32.dll")}
{_CALL_LINE}
R seq=11 T2224 api=GetModuleHandleW site=0x0041a2f0 rv=0x00000000
T2224 pc=0x0041a2f5 cmp seq=12 jcc=jz src0=reg:eax=0x0 src1=imm=0x0
C seq=20 T2224 api=GetComputerNameA site=0x00421b80 a0=0x0019fc00 a1=0x0019fc90
R seq=21 T2224 api=GetComputerNameA site=0x00421b80 rv=0x00000001 o0=A:{_hex("DESKTOP-7F2K9")}
# capped api=GetTickCount site=0x00412345 after 64 calls
"""


def _parse(text: str):
    return parse_drtrace_lines(text.splitlines())


def test_modules_parse_with_decoded_names():
    trace = _parse(SAMPLE_LOG)
    assert [(m.base, m.end, m.name) for m in trace.modules] == [
        (0x00400000, 0x0049A000, "autoit3.exe"),
        (0x77C10000, 0x77D50000, "kernel32.dll"),
    ]


def test_module_contains_bounds_are_half_open():
    trace = _parse(SAMPLE_LOG)
    exe = trace.modules[0]
    assert exe.contains(0x00400000)
    assert exe.contains(0x00499FFF)
    assert not exe.contains(0x0049A000)


def test_call_pairs_with_its_return_and_decodes_a_wide_argument():
    trace = _parse(SAMPLE_LOG)
    call = next(c for c in trace.calls if c.api == "GetModuleHandleW")
    assert call.site == 0x0041A2F0
    assert call.seq == 10 and call.return_seq == 11
    assert call.returned
    assert call.args == {0: 0x0019FB14, 1: 0x0}
    # The value an evasion check is looking for, bound to the site that used it.
    assert call.arg_strings == {0: "SbieDll.dll"}
    assert call.retval == 0


def test_out_parameter_is_captured_only_after_the_return():
    """The whole point of re-reading arguments in the post-callback: before the
    call the buffer holds nothing, so this value exists only at return."""
    trace = _parse(SAMPLE_LOG)
    call = next(c for c in trace.calls if c.api == "GetComputerNameA")
    assert call.arg_strings == {}
    assert call.out_strings == {0: "DESKTOP-7F2K9"}
    assert call.retval == 1


def test_comparison_carries_seq_and_jcc():
    trace = _parse(SAMPLE_LOG)
    (cmp_record,) = trace.comparisons
    assert cmp_record.pc == 0x0041A2F5
    assert cmp_record.opcode == "cmp"
    assert cmp_record.seq == 12
    assert cmp_record.jcc == "jz"
    assert [op.value for op in cmp_record.operands] == [0x0, 0x0]


def test_capped_notice_is_surfaced_not_swallowed():
    trace = _parse(SAMPLE_LOG)
    (notice,) = trace.capped
    assert (notice.api, notice.site, notice.after) == ("GetTickCount", 0x00412345, 64)


def test_nested_calls_pair_innermost_first():
    """One wrapped API calling another must pair by nesting, not nearest match.

    Nesting is keyed on (api, site), so this is the real case: a *different*
    wrapped API entered before the outer one returns. The same (api, site)
    re-entering is treated as a forwarder hop instead -- see
    test_forwarder_hop_collapses_to_one_call. A Windows API cannot recurse
    through the same application call site, so nothing genuine is lost.
    """
    log = """\
C seq=1 T1 api=CreateFileW site=0x00401000 a0=0x0
C seq=2 T1 api=NtCreateFile site=0x75a01000 a0=0x1
R seq=3 T1 api=NtCreateFile site=0x75a01000 rv=0x10
R seq=4 T1 api=CreateFileW site=0x00401000 rv=0x20
"""
    calls = sorted(_parse(log).calls, key=lambda c: c.seq)
    assert [(c.seq, c.return_seq, c.retval) for c in calls] == [(1, 4, 0x20), (2, 3, 0x10)]


def test_threads_do_not_pair_across_each_other():
    log = """\
C seq=1 T1 api=Sleep site=0x00401000 a0=0x64
C seq=2 T2 api=Sleep site=0x00401000 a0=0xc8
R seq=3 T2 api=Sleep site=0x00401000 rv=0x0
"""
    calls = {c.tid: c for c in _parse(log).calls}
    assert calls[2].returned
    assert not calls[1].returned


def test_unreturned_call_is_kept_with_its_arguments():
    """CAPE kills the target at the analysis timeout, so calls in flight at the
    end of the log are routine. The arguments were still observed."""
    log = f'C seq=1 T1 api=GetModuleHandleW site=0x00401000 a0=0x2 s0=A:{_hex("vmware")}\n'
    (call,) = _parse(log).calls
    assert not call.returned
    assert call.retval is None
    assert call.arg_strings == {0: "vmware"}


def test_malformed_and_unknown_lines_are_skipped():
    log = """\
M seq=notanumber base=0x1 end=0x2 name=00
C seq=1 T1 api=X site=notahex
R seq=2 T1 api=X site=0x1 rv=zzz
Q seq=3 something entirely else
"""
    trace = _parse(log)
    assert (trace.modules, trace.calls, trace.comparisons) == ([], [], [])


def test_a_string_containing_a_forged_record_cannot_inject_one():
    """Why the format hex-encodes strings. The sample controls these bytes; as
    literal text this payload would parse as an extra comparison record."""
    forged = "\nT9 pc=0xdeadbeef cmp src0=imm=0x1 src1=imm=0x1\n"
    log = f"C seq=1 T1 api=CreateFileA site=0x00401000 a0=0x2 s0=A:{_hex(forged)}\n"
    trace = _parse(log)
    assert trace.comparisons == []
    (call,) = trace.calls
    assert call.arg_strings[0].strip() == "T9 pc=0xdeadbeef cmp src0=imm=0x1 src1=imm=0x1"


def test_main_module_prefers_the_named_sample_then_the_exe():
    trace = _parse(SAMPLE_LOG)
    assert trace.main_module("autoit3.exe").base == 0x00400000
    # No name given: the sole .exe wins over the first-logged module.
    assert trace.main_module().name == "autoit3.exe"
    assert trace.main_module("nosuch.exe").name == "autoit3.exe"


def test_main_module_is_none_for_a_legacy_log_with_no_module_records():
    log = "T1 pc=0x401000 cmp src0=imm=0x1 src1=imm=0x2\n"
    trace = _parse(log)
    assert trace.main_module() is None
    assert len(trace.comparisons) == 1


def test_record_cap_truncates():
    log = "".join(f"T1 pc=0x40{i:04x} cmp src0=imm=0x1 src1=imm=0x2\n" for i in range(50))
    assert len(parse_drtrace_lines(log.splitlines(), max_records=10).comparisons) == 10
    assert len(parse_drtrace_lines(log.splitlines(), max_records=0).comparisons) == 50


def test_overlong_lines_are_dropped():
    log = "T1 pc=0x401000 cmp src0=imm=0x1 " + "x" * 9000 + "\nT1 pc=0x401004 test src0=imm=0x3\n"
    trace = _parse(log)
    assert [c.pc for c in trace.comparisons] == [0x401004]


def test_decode_hex_string_rejects_unusable_input():
    assert decode_hex_string("A", "") is None
    assert decode_hex_string("A", "abc") is None  # odd length
    assert decode_hex_string("A", "zz") is None  # not hex
    assert decode_hex_string("A", "00") is None  # decodes to nothing but NULs
    assert decode_hex_string("W", _hex("ok", True)) == "ok"


def test_files_merge_and_sort_by_global_seq(tmp_path):
    """seq is global to the process, so per-thread files and the module table
    merge into one consistent ordering."""
    (tmp_path / "drtrace.1.modules.log").write_text(
        f"M seq=1 base=0x400000 end=0x410000 name={_hex('s.exe')}\n"
    )
    (tmp_path / "drtrace.1.100.log").write_text(
        "C seq=30 T100 api=Sleep site=0x401000 a0=0x1\n"
        "R seq=31 T100 api=Sleep site=0x401000 rv=0x0\n"
    )
    (tmp_path / "drtrace.1.200.log").write_text(
        "C seq=10 T200 api=GetTickCount site=0x402000\n"
        "R seq=11 T200 api=GetTickCount site=0x402000 rv=0x1234\n"
    )
    trace = parse_drtrace_files(sorted(tmp_path.glob("drtrace.*.log")))
    assert [c.seq for c in trace.calls] == [10, 30]
    assert trace.main_module().name == "s.exe"


def test_record_cap_is_a_budget_across_files_not_per_file(tmp_path):
    """A sample chooses how many threads it spawns, and so how many logs there
    are to read; a per-file cap would not bound the total."""
    for n in range(4):
        (tmp_path / f"drtrace.1.{n}.log").write_text(
            "".join(f"T{n} pc=0x40{i:04x} cmp src0=imm=0x1 src1=imm=0x2\n" for i in range(10))
        )
    trace = parse_drtrace_files(sorted(tmp_path.glob("drtrace.*.log")), max_records=15)
    assert len(trace.comparisons) == 15


def test_unreadable_file_is_skipped(tmp_path):
    good = tmp_path / "drtrace.1.1.log"
    good.write_text("T1 pc=0x401000 cmp seq=5 src0=imm=0x1 src1=imm=0x2\n")
    trace = parse_drtrace_files([tmp_path / "missing.log", good])
    assert len(trace.comparisons) == 1


def test_forwarder_hop_collapses_to_one_call():
    """kernel32!X tail-jumps into kernelbase!X and the client wraps both, so one
    application call fires two pre-callbacks reporting the same site. The second
    arrives while the first is still in flight, which two real calls cannot do."""
    log = """\
C seq=10 T1 api=GetNativeSystemInfo site=0x00401005 a0=0x19fb14
C seq=11 T1 api=GetNativeSystemInfo site=0x00401005 a0=0x19fb14
R seq=12 T1 api=GetNativeSystemInfo site=0x00401005 rv=0x0
R seq=13 T1 api=GetNativeSystemInfo site=0x00401005 rv=0x0
"""
    (call,) = _parse(log).calls
    assert call.seq == 10 and call.returned


def test_two_real_calls_to_the_same_site_are_both_kept():
    """The counterpart: sequential calls do not overlap, so a return separates
    them and both must survive."""
    log = """\
C seq=10 T1 api=GetTickCount site=0x00401005
R seq=11 T1 api=GetTickCount site=0x00401005 rv=0x1
C seq=12 T1 api=GetTickCount site=0x00401005
R seq=13 T1 api=GetTickCount site=0x00401005 rv=0x2
"""
    calls = sorted(_parse(log).calls, key=lambda c: c.seq)
    assert [(c.seq, c.retval) for c in calls] == [(10, 0x1), (12, 0x2)]


def test_forwarder_collapse_is_per_site_not_per_api():
    """The same API reached through two different call sites is two real calls."""
    log = """\
C seq=10 T1 api=GetTickCount site=0x00401005
C seq=11 T1 api=GetTickCount site=0x00402005
R seq=12 T1 api=GetTickCount site=0x00402005 rv=0x2
R seq=13 T1 api=GetTickCount site=0x00401005 rv=0x1
"""
    calls = sorted(_parse(log).calls, key=lambda c: c.seq)
    assert [(c.site, c.retval) for c in calls] == [(0x401005, 0x1), (0x402005, 0x2)]

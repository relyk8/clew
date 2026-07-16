"""Offline tests for Channel 2 / Unit 4 (bn_dataflow).

No Binary Ninja, no license: everything here exercises the serialization
round-trips, the FLOSS adapter, the pure decision helpers, and the
stub-enrichment path. The BN-driven walk (_resolve / _find_ssa_call) is
covered by the manual fixture run in docs/binary_ninja_headless_setup.md,
since it needs a live view; the logic it *feeds* is unit-tested here.
"""

from __future__ import annotations

import json

import pytest

import clew.analysis.dataflow as bd
from clew.analysis.dataflow import (
    CHANNEL_BN,
    CHANNEL_FLOSS,
    CONF_STATIC_BN_ONLY,
    CONF_STATIC_CORROBORATED,
    SOURCE_DECODED,
    SOURCE_STACKSTRING,
    SOURCE_STATIC,
    SOURCE_TIGHTSTRING,
    BNDataflow,
    BridgedCallSite,
    FlossIndex,
)
from clew.channels.bn_callsites import BNCallSites, CallSite

# --- fixtures ----------------------------------------------------------------


def _resolved(**kw) -> BridgedCallSite:
    base = dict(
        api_name="GetModuleHandleW",
        call_site_va=0x401234,
        function_va=0x401200,
        api_resolution="import",
        parameter_index=0,
        value="SbieDll.dll",
        string_source=SOURCE_STATIC,
        string_va=0x404020,
        string_function_va=None,
        dataflow_path=(0x401220, 0x401228, 0x401234),
        source_channels=(CHANNEL_BN, CHANNEL_FLOSS),
        confidence=CONF_STATIC_CORROBORATED,
        resolved=True,
    )
    base.update(kw)
    return BridgedCallSite(**base)


def _unresolved(**kw) -> BridgedCallSite:
    base = dict(
        api_name="Sleep",
        call_site_va=0x401300,
        function_va=0x401200,
        api_resolution="import",
        parameter_index=-1,
        value=None,
        string_source=None,
        string_va=None,
        string_function_va=None,
        dataflow_path=(0x401300,),
        source_channels=(CHANNEL_BN,),
        confidence=0.0,
        resolved=False,
    )
    base.update(kw)
    return BridgedCallSite(**base)


# --- BridgedCallSite serialization -------------------------------------------


def test_bridged_roundtrip_resolved():
    b = _resolved()
    d = b.to_dict()
    assert d["call_site_va"] == "0x00401234"
    assert d["string_va"] == "0x00404020"
    assert d["dataflow_path"] == ["0x00401220", "0x00401228", "0x00401234"]
    assert BridgedCallSite.from_dict(d) == b


def test_bridged_roundtrip_unresolved_nulls():
    b = _unresolved()
    d = b.to_dict()
    assert d["value"] is None
    assert d["string_va"] is None
    assert d["string_function_va"] is None
    assert BridgedCallSite.from_dict(d) == b


def test_bridged_stackstring_function_va_hex():
    b = _resolved(string_source=SOURCE_STACKSTRING, string_va=None, string_function_va=0x401200)
    d = b.to_dict()
    assert d["string_va"] is None
    assert d["string_function_va"] == "0x00401200"
    assert BridgedCallSite.from_dict(d).string_function_va == 0x401200


# --- BNDataflow container ----------------------------------------------------


def test_bndataflow_roundtrip_and_accessors():
    df = BNDataflow(
        sample_path="/x/sample.exe",
        sample_sha256="a" * 64,
        bn_core_version="4.2.6455",
        bridged=[_resolved(), _unresolved()],
    )
    assert len(df.resolved()) == 1
    assert len(df.unresolved()) == 1
    assert df.for_api("GetModuleHandleW")[0].value == "SbieDll.dll"
    assert df.for_call_site(0x401234)[0].parameter_index == 0

    d = df.to_dict()
    restored = bd.load_dataflow_results  # sanity: symbol exists
    assert restored is not None
    # write/read round-trip
    text = json.dumps(d)
    reparsed = json.loads(text)
    assert reparsed["bridged"][0]["api_name"] == "GetModuleHandleW"


def test_load_dataflow_results(tmp_path):
    df = BNDataflow("/x/s.exe", "b" * 64, "4.2.6455", [_resolved()])
    p = tmp_path / "df.json"
    df.write_json(p)
    loaded = bd.load_dataflow_results(p)
    assert loaded.sample_sha256 == "b" * 64
    assert loaded.bridged[0] == _resolved()


# --- FlossIndex --------------------------------------------------------------


def test_flossindex_primitives():
    fi = FlossIndex(
        static_values={"SbieDll.dll", "VBoxService.exe"},
        obfuscated_by_function={0x401200: [("wine_get_unix_file_name", SOURCE_STACKSTRING)]},
    )
    assert fi.has_static("SbieDll.dll")
    assert not fi.has_static("nope")
    assert fi.obfuscated_for_function(0x401200)[0][1] == SOURCE_STACKSTRING
    assert fi.obfuscated_for_function(0xDEAD) == []


def test_flossindex_dict_roundtrip():
    fi = FlossIndex(
        static_values={"a", "b"},
        obfuscated_by_function={0x1000: [("x", SOURCE_DECODED)]},
    )
    fi2 = FlossIndex.from_dict(fi.to_dict())
    assert fi2.static_values == {"a", "b"}
    assert fi2.obfuscated_by_function == {0x1000: [("x", SOURCE_DECODED)]}


class _FakeFlossString:
    """Mirrors clew's FlossString: value, source, and category-specific loci
    (function for stack/tight, decoding_routine for decoded)."""

    def __init__(self, value, source, function=None, decoding_routine=None):
        self.value = value
        self.source = source
        self.function = function
        self.decoding_routine = decoding_routine


class _FakeFlossResult:
    def __init__(self, strings):
        self._strings = strings

    def all_strings(self):
        return list(self._strings)


def test_flossindex_from_floss_result_categorizes():
    fr = _FakeFlossResult(
        [
            _FakeFlossString("SbieDll.dll", "static"),
            _FakeFlossString("cmd.exe", "stackstring", function=0x401200),
            _FakeFlossString("evil", "tightstring", function=0x401500),
            _FakeFlossString("payload", "decoded", decoding_routine=0x401700),
        ]
    )
    fi = FlossIndex.from_floss_result(fr)
    assert fi.has_static("SbieDll.dll")
    assert fi.obfuscated_for_function(0x401200) == [("cmd.exe", SOURCE_STACKSTRING)]
    assert fi.obfuscated_for_function(0x401500) == [("evil", SOURCE_TIGHTSTRING)]
    # decoded string keyed off decoding_routine (it has no `function`)
    assert fi.obfuscated_for_function(0x401700) == [("payload", SOURCE_DECODED)]


def test_flossindex_from_floss_result_hex_function_va():
    fr = _FakeFlossResult([_FakeFlossString("s", "stackstring", function="0x401200")])
    fi = FlossIndex.from_floss_result(fr)
    assert fi.obfuscated_for_function(0x401200)[0][0] == "s"


def test_flossindex_from_floss_json_real_shapes():
    # Mirrors FLOSS 3.x --json: static has {string}; stack/tight have
    # {string, function:int}; decoded has {string, decoding_routine:int}
    # (no `function`). VAs are integers.
    data = {
        "strings": {
            "static_strings": [
                {"string": "sbiedll.dll", "offset": 77, "encoding": "ASCII"},
                {"string": "kernel32.dll", "offset": 90, "encoding": "ASCII"},
            ],
            "stack_strings": [
                {"string": "BMSR", "function": 4363335, "encoding": "ASCII"},  # 0x429447
            ],
            "tight_strings": [],
            "decoded_strings": [
                {"string": "S0VAl", "decoding_routine": 4367250, "address": 3216243468},
            ],
        }
    }
    fi = FlossIndex.from_floss_json(data)
    assert fi.has_static("sbiedll.dll")
    assert fi.has_static("kernel32.dll")
    assert fi.obfuscated_for_function(4363335) == [("BMSR", SOURCE_STACKSTRING)]
    # decoded string keyed off its decoding routine, tagged 'decoded'
    assert fi.obfuscated_for_function(4367250) == [("S0VAl", SOURCE_DECODED)]


def test_flossindex_from_floss_json_no_locus_falls_back_to_static():
    data = {"strings": {"stack_strings": [{"string": "orphan"}]}}  # no function VA
    fi = FlossIndex.from_floss_json(data)
    assert fi.has_static("orphan")  # corroborates by value
    assert fi.obfuscated_by_function == {}


def test_flossindex_from_floss_json_corroborates_static_score():
    # The point of loading FLOSS: a BN-read static string that FLOSS also saw
    # scores 0.9/[bn_xref,floss] instead of 0.7/[bn_xref].
    fi = FlossIndex.from_floss_json({"strings": {"static_strings": [{"string": "sbiedll.dll"}]}})
    ch, conf = bd._score_static("sbiedll.dll", fi)
    assert ch == (CHANNEL_BN, CHANNEL_FLOSS) and conf == CONF_STATIC_CORROBORATED


def test_normalise_floss_source():
    assert bd._normalise_floss_source("static string") == SOURCE_STATIC
    assert bd._normalise_floss_source("stackstring") == SOURCE_STACKSTRING
    assert bd._normalise_floss_source("tight string") == SOURCE_TIGHTSTRING
    assert bd._normalise_floss_source("decoded") == SOURCE_DECODED
    assert bd._normalise_floss_source(None) == SOURCE_STATIC


# --- pure decision helpers ---------------------------------------------------


def test_channels_union_always_has_bn_first():
    assert bd._channels_union(("floss",)) == (CHANNEL_BN, CHANNEL_FLOSS)
    assert bd._channels_union(()) == (CHANNEL_BN,)
    assert bd._channels_union((CHANNEL_BN,)) == (CHANNEL_BN,)


def test_score_static_corroboration():
    fi = FlossIndex(static_values={"SbieDll.dll"})
    ch, conf = bd._score_static("SbieDll.dll", fi)
    assert ch == (CHANNEL_BN, CHANNEL_FLOSS) and conf == CONF_STATIC_CORROBORATED
    ch2, conf2 = bd._score_static("OnlyBNSawThis.dll", fi)
    assert ch2 == (CHANNEL_BN,) and conf2 == CONF_STATIC_BN_ONLY


def test_match_obfuscated_single_zero_ambiguous():
    fi = FlossIndex(
        obfuscated_by_function={
            0x1000: [("only", SOURCE_STACKSTRING)],
            0x2000: [("a", SOURCE_STACKSTRING), ("b", SOURCE_DECODED)],
        }
    )
    assert bd._match_obfuscated(0x1000, fi) == ("only", SOURCE_STACKSTRING)
    assert bd._match_obfuscated(0x3000, fi) is None  # none
    assert bd._match_obfuscated(0x2000, fi) is None  # ambiguous -> not guessed


# --- candidate emission (the hand-off to derivation) -------------------------


def test_to_partial_candidates_resolved_only_by_default():
    df = BNDataflow("/x/s.exe", "c" * 64, "4.2.6455", [_resolved(), _unresolved()])
    cands = df.to_partial_candidates()
    assert len(cands) == 1
    assert cands[0]["api_name"] == "GetModuleHandleW"


def test_to_partial_candidates_include_unresolved():
    df = BNDataflow("/x/s.exe", "c" * 64, "4.2.6455", [_resolved(), _unresolved()])
    cands = df.to_partial_candidates(include_unresolved=True)
    assert len(cands) == 2


def test_to_partial_candidate_shape_and_boundaries():
    df = BNDataflow("/x/s.exe", "c" * 64, "4.2.6455", [_resolved()])
    c = df.to_partial_candidates()[0]

    # filled by the bridge
    assert c["parameter_index"] == 0
    assert c["candidate_values"][0]["value"] == "SbieDll.dll"
    assert c["candidate_values"][0]["confidence"] == CONF_STATIC_CORROBORATED
    assert c["candidate_values"][0]["source_channels"] == [CHANNEL_BN, CHANNEL_FLOSS]
    assert c["evidence"]["channels"] == [CHANNEL_BN, CHANNEL_FLOSS]
    assert c["evidence"]["string_source"] == SOURCE_STATIC
    assert c["evidence"]["string_va"] == "0x00404020"
    assert c["evidence"]["dataflow_path"] == ["0x00401220", "0x00401228", "0x00401234"]

    # deliberately NOT owned by the bridge
    assert c["comparison_operator"] == "unknown"  # Channel 4
    assert c["evidence"]["cmp_operand_a"] is None  # Channel 4
    assert c["evidence"]["cmp_operand_b"] is None  # Channel 4
    assert c["candidate_values"][0]["represents"] == "unknown"  # derivation
    assert c["candidate_values"][0]["retarget_to"] is None  # derivation
    assert "evasion_tier" not in c  # derivation
    assert "coordination_constraint" not in c  # derivation


def test_partial_candidate_va_pattern_matches_schema():
    import re

    va = re.compile(r"^0x[0-9a-fA-F]+$")
    df = BNDataflow("/x/s.exe", "c" * 64, "4.2.6455", [_resolved()])
    c = df.to_partial_candidates()[0]
    assert va.match(c["call_site_va"])
    assert va.match(c["function_va"])
    assert va.match(c["evidence"]["string_va"])
    for v in c["evidence"]["dataflow_path"]:
        assert va.match(v)


def test_unit3_stub_and_bridge_agree_on_keys():
    """The bridge's enriched candidate must be a superset-compatible shape of
    Unit 3's stub for the fields they share, so the orchestrator can merge."""
    cs = BNCallSites(
        sample_path="/x/s.exe",
        sample_sha256="d" * 64,
        bn_core_version="4.2.6455",
        call_sites=[CallSite("GetModuleHandleW", 0x401234, 0x401200, "import", "cdecl")],
    )
    stub = cs.to_partial_candidates()[0]
    bridged = BNDataflow("/x/s.exe", "d" * 64, "4.2.6455", [_resolved()]).to_partial_candidates()[0]
    shared = {"call_site_va", "function_va", "api_name", "api_resolution"}
    for k in shared:
        assert stub[k] == bridged[k]
    # both carry an evidence block with the same channel-array key
    assert "channels" in stub["evidence"] and "channels" in bridged["evidence"]


# --- indicator-array grouping (GetModuleHandleW(names[i]) in a loop) ---------


def _array_record(value, string_va, **kw) -> BridgedCallSite:
    """One element of an indicator array: same call site + param 0, own value."""
    return _resolved(
        api_name="GetModuleHandleW",
        call_site_va=0x4595FC,
        function_va=0x459500,
        parameter_index=0,
        value=value,
        string_va=string_va,
        string_source=SOURCE_STATIC,
        source_channels=(CHANNEL_BN,),
        confidence=0.7,
        dataflow_path=(0x459532, 0x4595FC),
        **kw,
    )


def test_array_collapses_to_one_candidate_with_many_values():
    names = [("avghookx.dll", 0x48A2E4), ("sbiedll.dll", 0x48A33C), ("cmdvrt32.dll", 0x48A428)]
    df = BNDataflow("/x/al.exe", "e" * 64, "4.2.6455", [_array_record(v, a) for v, a in names])
    cands = df.to_partial_candidates()
    assert len(cands) == 1  # one call site, one candidate
    c = cands[0]
    vals = [cv["value"] for cv in c["candidate_values"]]
    assert vals == ["avghookx.dll", "sbiedll.dll", "cmdvrt32.dll"]
    assert c["parameter_index"] == 0
    # multi-value: no single string_va, but the loop-load path is preserved
    assert c["evidence"]["string_va"] is None
    assert c["evidence"]["string_source"] == SOURCE_STATIC
    assert c["evidence"]["dataflow_path"] == ["0x00459532", "0x004595fc"]


def test_array_dedups_repeated_values():
    df = BNDataflow(
        "/x/al.exe",
        "e" * 64,
        "4.2.6455",
        [
            _array_record("sbiedll.dll", 0x48A33C),
            _array_record("sbiedll.dll", 0x48A33C),  # duplicate
            _array_record("dbghelp.dll", 0x48A358),
        ],
    )
    c = df.to_partial_candidates()[0]
    assert [cv["value"] for cv in c["candidate_values"]] == ["sbiedll.dll", "dbghelp.dll"]


def test_single_value_still_reports_string_va():
    """Regression: a lone resolved record (group of one) keeps its string_va,
    exactly as before grouping was introduced."""
    c = BNDataflow("/x/s.exe", "f" * 64, "4.2.6455", [_resolved()]).to_partial_candidates()[0]
    assert len(c["candidate_values"]) == 1
    assert c["evidence"]["string_va"] == "0x00404020"


def test_distinct_call_sites_stay_separate():
    df = BNDataflow(
        "/x/s.exe",
        "f" * 64,
        "4.2.6455",
        [
            _array_record("sbiedll.dll", 0x48A33C),  # call 0x4595fc
            _resolved(
                call_site_va=0x463407,
                function_va=0x463400,  # different call
                value="kernel32.dll",
                string_va=0x4877A4,
            ),
        ],
    )
    cands = df.to_partial_candidates()
    assert len(cands) == 2


# --- _is_stack_var: the bug that broke array resolution on real BN ----------


class _FakeSrcType:
    """Mimics BN's VariableSourceType: str() lacks 'Stack', .name has it."""

    def __init__(self, name):
        self._name = name

    @property
    def name(self):
        return self._name

    def __str__(self):
        return "0"  # BN renders the enum as an int-ish value, not the name


class _FakeVar:
    def __init__(self, storage, srcname="StackVariableSourceType"):
        self.storage = storage
        self.source_type = _FakeSrcType(srcname) if srcname else None


class _FakeSSAVar:
    def __init__(self, var):
        self.var = var


def test_is_stack_var_uses_enum_name_not_str():
    # This is exactly the al-khaser case: str(source_type)=='0', name has 'Stack'.
    assert bd._is_stack_var(_FakeSSAVar(_FakeVar(-60))) is True
    assert bd._is_stack_var(_FakeSSAVar(_FakeVar(0, "RegisterVariableSourceType"))) is False


def test_is_stack_var_negative_storage_fallback():
    # source_type unavailable -> fall back to the negative-storage signature.
    assert bd._is_stack_var(_FakeVar(-16, srcname=None)) is True
    assert bd._is_stack_var(_FakeVar(8, srcname=None)) is False
    assert bd._is_stack_var(None) is False


# --- end-to-end array walk with fakes mirroring al-khaser sub_459500 --------


class _FOp:
    def __init__(self, name):
        self.name = name


class _FExpr:
    def __init__(self, op, **kw):
        self.operation = _FOp(op)
        self.address = kw.pop("address", 0x0)
        self.value = kw.pop("value", None)  # BN dataflow value; None == undetermined
        for k, v in kw.items():
            setattr(self, k, v)


class _FStr:
    def __init__(self, value):
        self.value = value


class _FArch:
    address_size = 4


class _FBV:
    def __init__(self, strings):
        self._s = strings
        self.arch = _FArch()

    def get_string_at(self, addr):
        return _FStr(self._s[addr]) if addr in self._s else None

    def get_ascii_string_at(self, addr, min_length=1):
        return _FStr(self._s[addr]) if addr in self._s else None

    def read(self, addr, n):
        return b""


class _FSSA:
    def __init__(self, insns):
        self._insns = insns

    def __iter__(self):
        return iter([self._insns])  # a single basic block


def test_resolve_array_load_enumerates_stack_pointer_array():
    # 12 module-name pointers in a contiguous stack run (var_48..var_1c),
    # exactly as diagnosed: storages -72..-28 step 4. Plus a stray format
    # string far away (-1024) that must NOT be pulled into the array.
    names = [
        (-72, 0x48A2E4, "avghookx.dll"),
        (-68, 0x48A304, "avghooka.dll"),
        (-64, 0x48A324, "snxhk.dll"),
        (-60, 0x48A33C, "sbiedll.dll"),
        (-56, 0x48A358, "dbghelp.dll"),
        (-52, 0x48A374, "api_log.dll"),
        (-48, 0x48A390, "dir_watch.dll"),
        (-44, 0x48A3B4, "pstorec.dll"),
        (-40, 0x48A3D0, "vmcheck.dll"),
        (-36, 0x48A3EC, "wpespy.dll"),
        (-32, 0x48A408, "cmdvrt64.dll"),
        (-28, 0x48A428, "cmdvrt32.dll"),
    ]
    stray = (-1024, 0x48A500, "Checking if process loaded modules contains: %s ")

    strings = {addr: name for _s, addr, name in names}
    strings[stray[1]] = stray[2]

    insns = []
    for storage, addr, _name in names + [stray]:
        insns.append(
            _FExpr(
                "MLIL_SET_VAR_SSA",
                address=0x459532,
                dest=_FakeSSAVar(_FakeVar(storage)),
                src=_FExpr("MLIL_CONST_PTR", constant=addr),
            )
        )
    ssa = _FSSA(insns)
    bv = _FBV(strings)

    # load of [&var_48 + (index << 2)] with a *variable* index (undetermined)
    base_var = _FakeVar(-72)
    load = _FExpr(
        "MLIL_LOAD_SSA",
        src=_FExpr(
            "MLIL_ADD",
            left=_FExpr("MLIL_ADDRESS_OF", src=base_var),
            right=_FExpr("MLIL_LSL", value=None),
        ),
    )

    findings = bd._resolve_array_load(bv, ssa, load, FlossIndex.empty(), 0x459500)
    values = [f.value for f in findings]

    assert "sbiedll.dll" in values
    assert values == [n for _s, _a, n in names]  # all 12, in slot order
    assert stray[2] not in values  # format string excluded
    assert all(f.string_source == SOURCE_STATIC for f in findings)
    # no FLOSS index -> each element scores as a BN-only static string
    assert all(f.confidence == bd.CONF_STATIC_BN_ONLY for f in findings)
    assert all(f.channels == (CHANNEL_BN,) for f in findings)


def test_resolve_array_load_corroborated_elements_reach_0_9():
    """With FLOSS corroboration, array elements score exactly like any static
    string (0.9 / [bn_xref, floss]) -- no array-specific confidence cap."""
    names = [(-72, 0x48A2E4, "avghookx.dll"), (-68, 0x48A33C, "sbiedll.dll")]
    strings = {addr: name for _s, addr, name in names}
    insns = [
        _FExpr(
            "MLIL_SET_VAR_SSA",
            address=0x459532,
            dest=_FakeSSAVar(_FakeVar(storage)),
            src=_FExpr("MLIL_CONST_PTR", constant=addr),
        )
        for storage, addr, _name in names
    ]
    ssa, bv = _FSSA(insns), _FBV(strings)
    load = _FExpr(
        "MLIL_LOAD_SSA",
        src=_FExpr(
            "MLIL_ADD",
            left=_FExpr("MLIL_ADDRESS_OF", src=_FakeVar(-72)),
            right=_FExpr("MLIL_LSL", value=None),
        ),
    )
    # FLOSS recovered both names as static strings -> both corroborate
    floss = FlossIndex(static_values={"avghookx.dll", "sbiedll.dll"})

    findings = bd._resolve_array_load(bv, ssa, load, floss, 0x459500)
    assert all(f.confidence == bd.CONF_STATIC_CORROBORATED for f in findings)
    assert all(f.channels == (CHANNEL_BN, CHANNEL_FLOSS) for f in findings)


class _FSSAWithDefs(_FSSA):
    def __init__(self, insns, defs):
        super().__init__(insns)
        self._defs = defs

    def get_ssa_var_definition(self, var):
        return self._defs.get(id(var))


def test_resolve_follows_stack_var_to_const_string():
    """Regression: a bare MLIL_VAR_SSA of a *stack* variable must be followed
    to its definition, NOT intercepted as an obfuscated-string buffer. This is
    the case that collapsed 254 resolved -> 11 when _is_stack_ref shadowed it."""
    v = _FakeSSAVar(_FakeVar(-16))  # a STACK variable
    const = _FExpr("MLIL_CONST_PTR", constant=0x4877A4)
    setdef = _FExpr("MLIL_SET_VAR_SSA", address=0x1000, dest=v, src=const)
    ssa = _FSSAWithDefs([setdef], {id(v): setdef})
    bv = _FBV({0x4877A4: "kernel32.dll"})
    arg = _FExpr("MLIL_VAR_SSA", src=v)

    findings = bd._resolve(bv, ssa, arg, FlossIndex.empty(), 0x1000, None, 0, [], set())
    assert [f.value for f in findings] == ["kernel32.dll"]


def test_resolve_addressof_stack_buffer_uses_floss_obfuscated():
    """A literal &buffer argument is the obfuscated-string case: associate with
    FLOSS's decoded/stack/tight output for the function."""
    arg = _FExpr("MLIL_ADDRESS_OF", src=_FakeVar(-32))
    fi = FlossIndex(obfuscated_by_function={0x1000: [("decoded_secret", SOURCE_DECODED)]})
    findings = bd._resolve(_FBV({}), _FSSA([]), arg, fi, 0x1000, None, 0, [], set())
    assert [f.value for f in findings] == ["decoded_secret"]
    assert findings[0].string_source == SOURCE_DECODED


def test_resolve_stack_var_without_def_is_unresolved_absent_floss():
    """A stack VAR with no definition and no FLOSS match stays unresolved
    (empty) rather than being guessed."""
    v = _FakeSSAVar(_FakeVar(-16))
    ssa = _FSSAWithDefs([], {})  # no definition for v
    arg = _FExpr("MLIL_VAR_SSA", src=v)
    findings = bd._resolve(_FBV({}), ssa, arg, FlossIndex.empty(), 0x1000, None, 0, [], set())
    assert findings == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

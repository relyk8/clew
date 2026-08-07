"""Offline tests for the Ghidra backend.

None of these boot a JVM or need Ghidra installed: they cover the pure decision
logic (name classification, backend resolution, preflight failures) that decides
what the backend does before it ever touches the Java API. The Ghidra-driven
half is exercised against a real sample in the integration path, not here --
the same split the Binary Ninja backend's tests use.
"""

from __future__ import annotations

import pytest

from clew.channels import BackendUnavailable
from clew.channels.binaryninja.callsites import (
    RESOLUTION_IMPORT,
    RESOLUTION_ORDINAL,
)
from clew.channels.ghidra import _api, callsites
from clew.pipeline import (
    BACKEND_BINARYNINJA,
    BACKEND_GHIDRA,
    UnknownBackendError,
    resolve_backend,
)

# --- backend selection -------------------------------------------------------


def test_backend_defaults_to_ghidra(monkeypatch):
    monkeypatch.delenv("CLEW_STATIC_BACKEND", raising=False)
    assert resolve_backend() == BACKEND_GHIDRA


def test_explicit_backend_beats_the_environment(monkeypatch):
    monkeypatch.setenv("CLEW_STATIC_BACKEND", "ghidra")
    assert resolve_backend(BACKEND_BINARYNINJA) == BACKEND_BINARYNINJA


def test_environment_beats_the_default(monkeypatch):
    monkeypatch.setenv("CLEW_STATIC_BACKEND", "binaryninja")
    assert resolve_backend() == BACKEND_BINARYNINJA


@pytest.mark.parametrize("spelling", ["bn", "binary-ninja", "binary_ninja", "BinaryNinja"])
def test_binary_ninja_spellings_are_accepted(monkeypatch, spelling):
    monkeypatch.delenv("CLEW_STATIC_BACKEND", raising=False)
    assert resolve_backend(spelling) == BACKEND_BINARYNINJA


def test_unknown_backend_names_the_valid_choices(monkeypatch):
    monkeypatch.delenv("CLEW_STATIC_BACKEND", raising=False)
    with pytest.raises(UnknownBackendError) as excinfo:
        resolve_backend("ida")
    message = str(excinfo.value)
    assert "ida" in message
    assert "ghidra" in message and "binaryninja" in message


# --- preflight ---------------------------------------------------------------


def test_preflight_reports_a_missing_install_dir(monkeypatch):
    pytest.importorskip("pyghidra")
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    with pytest.raises(BackendUnavailable) as excinfo:
        _api.preflight()
    assert "GHIDRA_INSTALL_DIR" in str(excinfo.value)


def test_preflight_rejects_a_directory_that_is_not_ghidra(monkeypatch, tmp_path):
    pytest.importorskip("pyghidra")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
    with pytest.raises(BackendUnavailable) as excinfo:
        _api.preflight()
    assert "analyzeHeadless" in str(excinfo.value)


def test_preflight_accepts_a_ghidra_shaped_directory(monkeypatch, tmp_path):
    pytest.importorskip("pyghidra")
    (tmp_path / "support").mkdir()
    (tmp_path / "support" / "analyzeHeadless").write_text("#!/bin/sh\n")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
    _api.preflight()  # must not raise


def test_startup_errors_are_backend_unavailable():
    # The CLI catches BackendUnavailable to print a fix instead of a traceback;
    # if this inheritance breaks, that turns back into a stack trace.
    assert issubclass(_api.GhidraStartupError, BackendUnavailable)


# --- import-name classification ---------------------------------------------


def test_named_import_classifies_as_import():
    name, resolution, ordinal = callsites._classify("CreateFileW")
    assert (name, resolution, ordinal) == ("CreateFileW", RESOLUTION_IMPORT, None)


def test_ordinal_import_keeps_the_ordinal_number():
    # Ghidra labels a name-less import Ordinal_<n>. That maps onto the schema's
    # `ordinal` resolution; the number is what a later name table would need.
    name, resolution, ordinal = callsites._classify("Ordinal_115")
    assert resolution == RESOLUTION_ORDINAL
    assert ordinal == 115
    assert name == "Ordinal_115"


def test_library_qualified_names_are_stripped():
    name, resolution, _ = callsites._classify("KERNEL32.DLL::CreateFileW")
    assert name == "CreateFileW"
    assert resolution == RESOLUTION_IMPORT


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("thunk_LoadLibraryW", "LoadLibraryW"),
        ("__imp_GetProcAddress", "GetProcAddress"),
        ("_imp_RegOpenKeyExW", "RegOpenKeyExW"),
        ("  CreateMutexW  ", "CreateMutexW"),
    ],
)
def test_decorations_are_stripped(raw, expected):
    assert callsites._clean_name(raw) == expected


def test_empty_names_are_dropped():
    assert callsites._classify("")[0] is None
    assert callsites._classify(None)[0] is None


def test_switch_table_labels_are_dropped():
    # Ghidra bookkeeping labels are not call targets.
    assert callsites._classify("switchD_004010a0::caseD_1")[0] is None


# --- artifact compatibility --------------------------------------------------


def test_ghidra_pins_record_the_validated_version():
    assert callsites.GHIDRA_PINS["version"] == _api.GHIDRA_VALIDATED_VERSION
    assert callsites.GHIDRA_PINS["backend"] == "pyghidra"

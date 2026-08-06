"""Offline tests for the layered configuration loader (clew/config.py).

The load path mutates process-global state (os.environ and sys.path), so every
test drives it through monkeypatch and an explicit tmp_path, never the real
home directory or the developer's environment.

The behaviour that matters most here is precedence. Config loading is only safe
to add to an existing tool because it is purely additive: an exported variable
must always beat a file, and the higher-precedence file must always beat the
lower one. Those two properties are what keep every pre-existing invocation
behaving exactly as it did, so they are asserted directly rather than inferred.
"""

import logging
import os
import sys

import pytest

from clew import config


@pytest.fixture(autouse=True)
def _reset_loaded(monkeypatch):
    # load_config() records its result in a module global for `doctor` to read.
    # Reset it so tests cannot observe each other's loads.
    monkeypatch.setattr(config, "_loaded", ())


# --- parse_env_file ---------------------------------------------------------


def test_parses_plain_assignments():
    parsed = config.parse_env_file("A=1\nB=two\n")
    assert parsed == {"A": "1", "B": "two"}


def test_skips_blanks_and_comments():
    parsed = config.parse_env_file("\n# a comment\n\nA=1\n   \n")
    assert parsed == {"A": "1"}


def test_accepts_export_prefix():
    # The point of accepting `export` is that a file written for `source` -- the
    # shape an environment script already has -- can be used with no edits.
    parsed = config.parse_env_file("export BN_ENTERPRISE_SERVER=https://bn.example\n")
    assert parsed == {"BN_ENTERPRISE_SERVER": "https://bn.example"}


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('A="quoted"', "quoted"),
        ("A='quoted'", "quoted"),
        ('A="with space"', "with space"),
        ("A=bare", "bare"),
        ('A="', '"'),  # a lone quote is too short to be a matched pair
        ("A=\"mismatched'", "\"mismatched'"),
    ],
)
def test_quote_handling(line, expected):
    assert config.parse_env_file(line)["A"] == expected


def test_value_may_contain_equals():
    # Split on the first '=' only: base64 and query strings both carry more.
    assert config.parse_env_file("A=b=c=d")["A"] == "b=c=d"


def test_inline_hash_is_part_of_the_value():
    # Deliberate: passwords contain '#', and silently truncating one produces a
    # login failure whose cause is invisible.
    assert config.parse_env_file("BN_ENTERPRISE_PASSWORD=pa#ss")["BN_ENTERPRISE_PASSWORD"] == "pa#ss"


def test_malformed_lines_are_skipped_not_raised(caplog):
    with caplog.at_level(logging.WARNING):
        parsed = config.parse_env_file("good=1\nnonsense\nbad key=2\n", source="cfg")
    assert parsed == {"good": "1"}
    assert "cfg:2" in caplog.text
    assert "cfg:3" in caplog.text


def test_empty_value_is_allowed():
    assert config.parse_env_file("A=\n") == {"A": ""}


# --- precedence -------------------------------------------------------------


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_file_value_is_applied_when_unset(tmp_path, monkeypatch):
    cfg = tmp_path / "clew" / "config.env"
    _write(cfg, "CLEW_CAPA_RULES=/from/file\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("CLEW_CAPA_RULES", raising=False)
    monkeypatch.chdir(tmp_path)

    config.load_config()

    assert os.environ["CLEW_CAPA_RULES"] == "/from/file"


def test_process_environment_beats_the_file(tmp_path, monkeypatch):
    cfg = tmp_path / "clew" / "config.env"
    _write(cfg, "CLEW_CAPA_RULES=/from/file\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("CLEW_CAPA_RULES", "/from/env")
    monkeypatch.chdir(tmp_path)

    loaded = config.load_config()

    assert os.environ["CLEW_CAPA_RULES"] == "/from/env"
    # The key was defined by the file but did not take effect: that distinction
    # is what explains an apparently ignored config file.
    entry = next(e for e in loaded if e.path.name == "config.env")
    assert "CLEW_CAPA_RULES" in entry.defined
    assert "CLEW_CAPA_RULES" not in entry.applied


def test_dotenv_beats_user_config(tmp_path, monkeypatch):
    _write(tmp_path / "clew" / "config.env", "CAPE_BASE_URL=http://user-config\n")
    _write(tmp_path / "work" / ".env", "CAPE_BASE_URL=http://dotenv\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("CAPE_BASE_URL", raising=False)
    monkeypatch.chdir(tmp_path / "work")

    config.load_config()

    assert os.environ["CAPE_BASE_URL"] == "http://dotenv"


def test_missing_files_are_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    assert config.load_config() == ()


def test_load_is_idempotent(tmp_path, monkeypatch):
    cfg = tmp_path / "clew" / "config.env"
    _write(cfg, "CAPE_BASE_URL=http://first\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("CAPE_BASE_URL", raising=False)
    monkeypatch.chdir(tmp_path)

    config.load_config()
    cfg.write_text("CAPE_BASE_URL=http://second\n")
    config.load_config()

    # The first load established the value; a second cannot overwrite it.
    assert os.environ["CAPE_BASE_URL"] == "http://first"


def test_world_readable_secret_file_warns(tmp_path, monkeypatch, caplog):
    cfg = tmp_path / "clew" / "config.env"
    _write(cfg, "BN_ENTERPRISE_PASSWORD=hunter2\n")
    cfg.chmod(0o644)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("BN_ENTERPRISE_PASSWORD", raising=False)
    monkeypatch.chdir(tmp_path)

    with caplog.at_level(logging.WARNING):
        config.load_config()

    assert "readable by other users" in caplog.text


def test_no_permission_warning_without_secrets(tmp_path, monkeypatch, caplog):
    cfg = tmp_path / "clew" / "config.env"
    _write(cfg, "CAPE_BASE_URL=http://cape\n")
    cfg.chmod(0o644)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("CAPE_BASE_URL", raising=False)
    monkeypatch.chdir(tmp_path)

    with caplog.at_level(logging.WARNING):
        config.load_config()

    assert "readable by other users" not in caplog.text


def test_user_config_path_honours_xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert config.user_config_path() == tmp_path / "clew" / "config.env"


def test_user_config_path_falls_back_to_home(tmp_path, monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(config.Path, "home", classmethod(lambda cls: tmp_path))
    assert config.user_config_path() == tmp_path / ".config" / "clew" / "config.env"


# --- the Binary Ninja sys.path shim -----------------------------------------


def test_bn_path_unset_is_a_noop(monkeypatch):
    monkeypatch.delenv("CLEW_BN_API", raising=False)
    assert config.ensure_bn_on_path() is None


def test_bn_path_added_to_sys_path(tmp_path, monkeypatch):
    (tmp_path / "binaryninja").mkdir()
    monkeypatch.setenv("CLEW_BN_API", str(tmp_path))
    original = list(sys.path)
    try:
        assert config.ensure_bn_on_path() == tmp_path
        assert str(tmp_path) in sys.path
    finally:
        sys.path[:] = original


def test_bn_path_is_not_added_twice(tmp_path, monkeypatch):
    (tmp_path / "binaryninja").mkdir()
    monkeypatch.setenv("CLEW_BN_API", str(tmp_path))
    original = list(sys.path)
    try:
        config.ensure_bn_on_path()
        config.ensure_bn_on_path()
        assert sys.path.count(str(tmp_path)) == 1
    finally:
        sys.path[:] = original


def test_bn_path_missing_directory_warns_and_is_ignored(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("CLEW_BN_API", str(tmp_path / "nope"))
    original = list(sys.path)
    try:
        with caplog.at_level(logging.WARNING):
            assert config.ensure_bn_on_path() is None
        assert "is not a directory" in caplog.text
        assert sys.path == original
    finally:
        sys.path[:] = original


def test_bn_path_without_package_warns_but_still_applies(tmp_path, monkeypatch, caplog):
    # The likely misconfiguration: pointing one level too deep or too shallow.
    # Warn loudly, but still apply it, since an unrecognised layout may work.
    monkeypatch.setenv("CLEW_BN_API", str(tmp_path))
    original = list(sys.path)
    try:
        with caplog.at_level(logging.WARNING):
            assert config.ensure_bn_on_path() == tmp_path
        assert "does not contain a 'binaryninja' package" in caplog.text
        assert str(tmp_path) in sys.path
    finally:
        sys.path[:] = original


def test_is_secret():
    assert config.is_secret("BN_ENTERPRISE_PASSWORD")
    assert config.is_secret("some_token")
    assert not config.is_secret("CAPE_BASE_URL")


# --- capa executable resolution ---------------------------------------------


def test_capa_bin_prefers_the_one_beside_the_interpreter(tmp_path, monkeypatch):
    # The pipx case: only clew's entry point is on PATH, so a bare `capa` lookup
    # would miss the capa pip installed as clew's own dependency.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    capa = bindir / "capa"
    capa.write_text("#!/bin/sh\n")
    capa.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(bindir / "python"))

    assert config.default_capa_bin() == str(capa)


def test_capa_bin_falls_back_to_path_lookup(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    monkeypatch.setattr(sys, "executable", str(bindir / "python"))

    assert config.default_capa_bin() == "capa"


def test_capa_bin_ignores_a_non_executable_file(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "capa").write_text("not executable")
    monkeypatch.setattr(sys, "executable", str(bindir / "python"))

    assert config.default_capa_bin() == "capa"

"""Offline tests for the preflight checks (clew/doctor.py).

Every check is a pure function returning a Check, so they are driven directly
with a monkeypatched environment rather than by standing up a real Binary Ninja,
capa, or CAPE. The one property worth stating up front is the severity policy:
only Binary Ninja, the core channel, may produce a blocking failure, because the
pipeline is designed to degrade past capa, FLOSS, and CAPE. That policy is what
the exit code means, so it is asserted rather than assumed.
"""

import logging

import pytest

from clew import cli, config, doctor


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    # Doctor reads the ambient environment, and this box has several of these
    # set for real. Clear them so results do not depend on who runs the suite.
    for key in config.CONFIG_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(config, "_loaded", ())


# --- individual checks ------------------------------------------------------


def test_python_check_passes_on_a_supported_interpreter():
    assert doctor.check_python().status == doctor.OK


def test_config_check_reports_nothing_found(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    check = doctor.check_config()
    assert check.status == doctor.SKIP
    assert "no config file found" in check.detail


def test_config_check_reports_loaded_files(tmp_path, monkeypatch):
    cfg = tmp_path / "clew" / "config.env"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("CAPE_BASE_URL=http://cape\nCLEW_CAPA_RULES=/rules\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    config.load_config()

    check = doctor.check_config()
    assert check.status == doctor.OK
    assert "2 key(s)" in check.detail


def test_bn_api_missing_is_a_blocking_failure(monkeypatch):
    monkeypatch.setattr(doctor.importlib.util, "find_spec", lambda name: None)
    check = doctor.check_bn_api()
    assert check.status == doctor.FAIL
    assert "CLEW_BN_API" in (check.fix or "")


def test_bn_api_found_reports_the_api_directory(tmp_path, monkeypatch):
    package = tmp_path / "binaryninja"
    package.mkdir()
    spec = type("Spec", (), {"origin": str(package / "__init__.py")})()
    monkeypatch.setattr(doctor.importlib.util, "find_spec", lambda name: spec)

    check = doctor.check_bn_api()
    assert check.status == doctor.OK
    # The directory reported is the one CLEW_BN_API names, not the package
    # itself, so a user can compare the row against their setting directly.
    assert check.detail.startswith(str(tmp_path))
    assert not check.detail.startswith(str(package))


def test_bn_api_configured_but_still_missing_says_so(monkeypatch):
    monkeypatch.setenv("CLEW_BN_API", "/somewhere/wrong")
    monkeypatch.setattr(doctor.importlib.util, "find_spec", lambda name: None)
    check = doctor.check_bn_api()
    assert check.status == doctor.FAIL
    assert "/somewhere/wrong" in check.detail


def test_bn_credentials_all_present(monkeypatch):
    monkeypatch.setenv("BN_ENTERPRISE_SERVER", "https://bn.example")
    monkeypatch.setenv("BN_ENTERPRISE_USERNAME", "analyst-account")
    monkeypatch.setenv("BN_ENTERPRISE_PASSWORD", "sup3rs3cret-do-not-print")
    check = doctor.check_bn_credentials()
    assert check.status == doctor.OK
    # Neither credential may be echoed, even when the check succeeds: this
    # report gets pasted into issues and shown on a projector.
    assert "sup3rs3cret-do-not-print" not in check.detail
    assert "analyst-account" not in check.detail


def test_bn_credentials_all_absent_is_a_warning_not_a_failure():
    # A seat may already be held, or --no-license-checkout passed, so this is
    # not blocking.
    check = doctor.check_bn_credentials()
    assert check.status == doctor.WARN


def test_bn_credentials_partial_names_what_is_missing(monkeypatch):
    monkeypatch.setenv("BN_ENTERPRISE_SERVER", "https://bn.example")
    check = doctor.check_bn_credentials()
    assert check.status == doctor.WARN
    assert "BN_ENTERPRISE_USERNAME" in check.detail
    assert "BN_ENTERPRISE_PASSWORD" in check.detail


def test_capa_rules_unset_is_a_warning():
    check = doctor.check_capa_rules()
    assert check.status == doctor.WARN
    assert "no_capa_signal" in check.detail


def test_capa_rules_missing_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("CLEW_CAPA_RULES", str(tmp_path / "nope"))
    assert doctor.check_capa_rules().status == doctor.WARN


def test_capa_rules_empty_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("CLEW_CAPA_RULES", str(tmp_path))
    check = doctor.check_capa_rules()
    assert check.status == doctor.WARN
    assert "empty" in check.detail


def test_capa_rules_populated_directory(tmp_path, monkeypatch):
    (tmp_path / "rule.yml").write_text("x")
    monkeypatch.setenv("CLEW_CAPA_RULES", str(tmp_path))
    assert doctor.check_capa_rules().status == doctor.OK


def test_capa_binary_found(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/usr/bin/capa")
    assert doctor.check_capa_bin().status == doctor.OK


def test_capa_binary_missing_is_a_warning(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    assert doctor.check_capa_bin().status == doctor.WARN


def test_cape_unreachable_is_a_warning(monkeypatch):
    from clew.channels.cape import client as cape_client

    class Boom:
        def __init__(self, *a, **kw):
            pass

        def list_tasks(self, **kw):
            raise cape_client.CapeError("refused")

    monkeypatch.setattr(cape_client, "CapeClient", Boom)
    check = doctor.check_cape("http://cape.invalid", timeout=1)
    assert check.status == doctor.WARN
    assert "static is unaffected" in check.detail


def test_cape_reachable(monkeypatch):
    from clew.channels.cape import client as cape_client

    class Fine:
        def __init__(self, *a, **kw):
            pass

        def list_tasks(self, **kw):
            return [{"id": 1}]

    monkeypatch.setattr(cape_client, "CapeClient", Fine)
    assert doctor.check_cape("http://cape", timeout=1).status == doctor.OK


def test_cape_storage_absent_is_skipped(tmp_path):
    check = doctor.check_cape_storage(str(tmp_path / "nope"))
    assert check.status == doctor.SKIP
    assert "cmplog-dir" in (check.fix or "")


def test_cape_storage_present(tmp_path):
    assert doctor.check_cape_storage(str(tmp_path)).status == doctor.OK


# --- report + exit code -----------------------------------------------------


def test_has_failures_only_counts_fail():
    checks = [
        doctor.Check("a", doctor.OK, ""),
        doctor.Check("b", doctor.WARN, ""),
        doctor.Check("c", doctor.SKIP, ""),
    ]
    assert not doctor.has_failures(checks)
    assert doctor.has_failures([*checks, doctor.Check("d", doctor.FAIL, "")])


def test_report_prints_fixes_for_problems_only():
    checks = [
        doctor.Check("fine", doctor.OK, "good", fix="never shown"),
        doctor.Check("broken", doctor.FAIL, "bad", fix="do the thing"),
    ]
    report = doctor.format_report(checks, version="9.9.9", location="/somewhere")
    assert "clew 9.9.9" in report
    assert "fix: do the thing" in report
    assert "never shown" not in report


def test_report_summarises_a_clean_run():
    report = doctor.format_report(
        [doctor.Check("a", doctor.OK, "")], version="1", location="/x"
    )
    assert "All checks passed." in report


def test_report_distinguishes_warnings_from_blockers():
    warn_only = doctor.format_report(
        [doctor.Check("a", doctor.WARN, "")], version="1", location="/x"
    )
    assert "No blocking problems" in warn_only

    blocked = doctor.format_report(
        [doctor.Check("a", doctor.FAIL, "")], version="1", location="/x"
    )
    assert "1 blocking problem(s)" in blocked


def test_cli_doctor_exits_nonzero_when_bn_is_missing(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(doctor.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(doctor, "check_cape", lambda url, timeout: doctor.Check("cape", doctor.SKIP, ""))

    rc = cli.main(["doctor"])

    assert rc == 1
    out = capsys.readouterr().out
    assert "binary ninja api" in out


def test_cli_doctor_exits_zero_when_only_warnings(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    spec = type("Spec", (), {"origin": str(tmp_path / "binaryninja" / "__init__.py")})()
    monkeypatch.setattr(doctor.importlib.util, "find_spec", lambda name: spec)
    monkeypatch.setattr(doctor, "check_cape", lambda url, timeout: doctor.Check("cape", doctor.SKIP, ""))

    rc = cli.main(["doctor"])

    assert rc == 0
    assert "No blocking problems" in capsys.readouterr().out


def test_doctor_does_not_import_binary_ninja_without_the_license_flag(monkeypatch, caplog):
    # The default path must not load the BN core or take a seat: that is what
    # makes doctor safe to run anywhere, including with no license free.
    called = []
    monkeypatch.setattr(doctor, "check_bn_license", lambda: called.append(True))
    with caplog.at_level(logging.DEBUG):
        doctor.run_checks(
            cape_url="http://cape",
            storage_root="/nonexistent",
            timeout=1,
            license_check=False,
        )
    assert called == []

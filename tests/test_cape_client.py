"""Offline tests for the Channel 3 CapeClient helpers (no live CAPE/network)."""

from __future__ import annotations

import pytest

from clew.channels.cape.client import CapeClient, CapeError


@pytest.fixture
def client():
    # base_url is never dialed: every test monkeypatches _get or reads the filesystem.
    return CapeClient("http://127.0.0.1:8000")


# ---------- list_tasks ----------


def _tasks():
    return [
        {"id": 3, "status": "reported"},
        {"id": 2, "status": "running"},
        {"id": 1, "status": "reported"},
    ]


def test_list_tasks_data_is_list(client, monkeypatch):
    # Shape A: data wraps a bare list of task dicts.
    monkeypatch.setattr(client, "_get", lambda path: {"error": False, "data": _tasks()})
    out = client.list_tasks()
    assert [t["id"] for t in out] == [3, 2, 1]


def test_list_tasks_data_is_dict_with_tasks(client, monkeypatch):
    # Shape B: data is a dict holding the list under 'tasks'.
    monkeypatch.setattr(
        client, "_get", lambda path: {"error": False, "data": {"tasks": _tasks()}}
    )
    out = client.list_tasks()
    assert [t["id"] for t in out] == [3, 2, 1]


def test_list_tasks_data_is_dict_with_data(client, monkeypatch):
    # Shape C: data is a dict holding the list under a nested 'data'.
    monkeypatch.setattr(
        client, "_get", lambda path: {"error": False, "data": {"data": _tasks()}}
    )
    out = client.list_tasks()
    assert [t["id"] for t in out] == [3, 2, 1]


def test_list_tasks_status_filter(client, monkeypatch):
    monkeypatch.setattr(client, "_get", lambda path: {"error": False, "data": _tasks()})
    out = client.list_tasks(status="reported")
    assert [t["id"] for t in out] == [3, 1]


def test_list_tasks_limit_slices_without_resort(client, monkeypatch):
    monkeypatch.setattr(client, "_get", lambda path: {"error": False, "data": _tasks()})
    out = client.list_tasks(limit=2)
    assert [t["id"] for t in out] == [3, 2]


def test_list_tasks_status_then_limit(client, monkeypatch):
    monkeypatch.setattr(client, "_get", lambda path: {"error": False, "data": _tasks()})
    out = client.list_tasks(limit=1, status="reported")
    assert [t["id"] for t in out] == [3]


def test_list_tasks_error_raises(client, monkeypatch):
    monkeypatch.setattr(client, "_get", lambda path: {"error": True, "error_value": "boom"})
    with pytest.raises(CapeError):
        client.list_tasks()


# ---------- fetch_cmplog_logs ----------


def _make_task_dir(tmp_path, task_id, names):
    files_dir = tmp_path / str(task_id) / "files"
    files_dir.mkdir(parents=True)
    for name in names:
        (files_dir / name).write_text("# header\nT0 pc=0x1 cmp src0=imm=0x1 src1=imm=0x2\n")
    return files_dir


def test_fetch_cmplog_logs_returns_sorted(client, tmp_path):
    _make_task_dir(tmp_path, 7, ["cmplog.b.log", "cmplog.a.log"])
    out = client.fetch_cmplog_logs(7, storage_root=tmp_path)
    assert [p.name for p in out] == ["cmplog.a.log", "cmplog.b.log"]


def test_fetch_cmplog_logs_empty_dir_returns_empty(client, tmp_path):
    # Dir exists and is readable but holds no cmplog files -> [] (not an error).
    _make_task_dir(tmp_path, 7, [])
    assert client.fetch_cmplog_logs(7, storage_root=tmp_path) == []


def test_fetch_cmplog_logs_missing_dir_returns_empty(client, tmp_path):
    # A non-existent task dir globs empty (Path.glob does not raise on absence).
    assert client.fetch_cmplog_logs(999, storage_root=tmp_path) == []


def test_fetch_cmplog_logs_permission_error_raises(client, tmp_path, monkeypatch):
    # Simulate an unreadable dir by making the glob raise PermissionError.
    def boom(self, pattern):
        raise PermissionError("denied")

    monkeypatch.setattr("pathlib.Path.glob", boom)
    with pytest.raises(CapeError) as exc:
        client.fetch_cmplog_logs(7, storage_root=tmp_path)
    assert "--cmplog-dir" in str(exc.value)


# ---------- count_cmplog_lines ----------


def test_count_cmplog_lines_skips_comments_and_blanks(client, tmp_path):
    files_dir = tmp_path / "5" / "files"
    files_dir.mkdir(parents=True)
    (files_dir / "cmplog.a.log").write_text(
        "# comment\n"
        "\n"
        "   \n"
        "T0 pc=0x1 cmp src0=imm=0x1 src1=imm=0x2\n"
        "T0 pc=0x2 test src0=reg:EAX=0x0 src1=reg:EAX=0x0\n"
    )
    assert client.count_cmplog_lines(5, storage_root=tmp_path) == 2


def test_count_cmplog_lines_sums_across_files(client, tmp_path):
    files_dir = tmp_path / "5" / "files"
    files_dir.mkdir(parents=True)
    (files_dir / "cmplog.a.log").write_text("T0 pc=0x1 cmp src0=imm=0x1 src1=imm=0x2\n")
    (files_dir / "cmplog.b.log").write_text(
        "# h\nT0 pc=0x2 cmp src0=imm=0x3 src1=imm=0x4\nT0 pc=0x3 test src0=imm=0x0 src1=imm=0x0\n"
    )
    assert client.count_cmplog_lines(5, storage_root=tmp_path) == 3


def test_count_cmplog_lines_no_files_returns_zero(client, tmp_path):
    # Readable dir, no cmplog files: zero real records (fetch returns []).
    (tmp_path / "5" / "files").mkdir(parents=True)
    assert client.count_cmplog_lines(5, storage_root=tmp_path) == 0


def test_count_cmplog_lines_unreadable_returns_none(client, tmp_path, monkeypatch):
    def boom(self, pattern):
        raise PermissionError("denied")

    monkeypatch.setattr("pathlib.Path.glob", boom)
    assert client.count_cmplog_lines(7, storage_root=tmp_path) is None


# ---------- poll ----------


def test_poll_progress_callback_no_stdout(client, monkeypatch, capsys):
    # view yields running then reported; a progress callback receives each status
    # change and nothing leaks to stdout (the CLI stdout=artifact contract).
    statuses = iter(["running", "reported"])
    monkeypatch.setattr(client, "view", lambda task_id: {"status": next(statuses)})

    seen = []
    out = client.poll(7, poll_interval=0, progress=seen.append)

    assert out == "reported"
    assert seen == ["running", "reported"]
    assert capsys.readouterr().out == ""

"""
Minimal CAPE REST client for Clew's Channel 3 (DynamoRIO comparison logging).
Targets CAPEv2 apiv2 endpoints. Tested against the services-based layout
(cape, cape-web, cape-processor, cape-rooter).

Adapted from a prior project, originally written for RL-guided mutation submission.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Callable

import requests

from clew.channels.cape.statuses import TERMINAL_STATUSES


class CapeError(RuntimeError):
    pass


class CapeClient:
    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        http_timeout: int = 15,
    ) -> None:
        self.base = base_url.rstrip("/")
        self.http_timeout = http_timeout
        self.session = requests.Session()
        if token:
            self.session.headers["Authorization"] = f"Token {token}"

    # ---------- low level ----------

    def _get(self, path: str, timeout: int | None = None) -> dict[str, Any]:
        try:
            r = self.session.get(f"{self.base}{path}", timeout=timeout or self.http_timeout)
            r.raise_for_status()
            return r.json()
        except requests.RequestException as exc:
            raise CapeError(f"CAPE request failed ({path}): {exc}") from exc

    # ---------- public API ----------

    def status(self) -> dict[str, Any]:
        """Smoke test. Returns CAPE's status blob or raises."""
        j = self._get("/apiv2/cuckoo/status/")
        if j.get("error"):
            raise CapeError(f"status error: {j}")
        return j.get("data", {})

    def submit(
        self,
        sample_path: str | Path,
        timeout: int = 60,
        enforce_timeout: bool = True,
        options: dict[str, str] | None = None,
        machine: str | None = None,
        package: str | None = None,
    ) -> int:
        """
        Submit a file. Returns the task_id (int).
        Always passes enforce_timeout=1 by default, required because sleepy
        anti-analysis samples will otherwise hang the guest.
        """
        sample_path = Path(sample_path)
        if not sample_path.is_file():
            raise FileNotFoundError(sample_path)

        data: dict[str, str] = {
            "timeout": str(timeout),
            "enforce_timeout": "1" if enforce_timeout else "0",
        }
        if options:
            # CAPE parses this string on commas, so a comma inside a value would
            # silently split into a bogus extra option rather than fail. Reject
            # it here instead of shipping a submission that means something else.
            bad = [k for k, v in options.items() if "," in str(v)]
            if bad:
                raise CapeError(
                    f"option value(s) {bad} contain a comma; CAPE's option string is "
                    f"comma-separated, so the value cannot be passed through intact"
                )
            data["options"] = ",".join(f"{k}={v}" for k, v in options.items())
        if machine:
            data["machine"] = machine
        if package:
            data["package"] = package

        try:
            with sample_path.open("rb") as f:
                files = {"file": (sample_path.name, f)}
                r = self.session.post(
                    f"{self.base}/apiv2/tasks/create/file/",
                    data=data,
                    files=files,
                    timeout=self.http_timeout,
                )
            r.raise_for_status()
            j = r.json()
        except requests.RequestException as exc:
            raise CapeError(f"submit request failed: {exc}") from exc
        if j.get("error"):
            raise CapeError(f"submit error: {j}")

        ids = j.get("data", {}).get("task_ids") or []
        if not ids:
            # Older CAPE builds return "task_id" (singular)
            tid = j.get("data", {}).get("task_id")
            if tid is None:
                raise CapeError(f"no task_id in response: {j}")
            return int(tid)
        return int(ids[0])

    def view(self, task_id: int) -> dict[str, Any]:
        j = self._get(f"/apiv2/tasks/view/{task_id}/")
        if j.get("error"):
            raise CapeError(f"view {task_id} error: {j}")
        return j.get("data", {})

    def poll(
        self,
        task_id: int,
        poll_interval: float = 2.0,
        max_wait: float = 600.0,
        progress: Callable[[str], None] | None = None,
    ) -> str:
        """
        Block until task reaches a terminal state. Returns the final status.
        Terminal states: 'reported' plus CAPE's three failure states.

        On each status change, call progress(status) if given (so a CLI caller
        can route it to stderr), else print to stdout (the __main__ harness).
        """
        deadline = time.monotonic() + max_wait
        last = None
        while time.monotonic() < deadline:
            info = self.view(task_id)
            status = info.get("status", "unknown")
            if status != last:
                if progress is not None:
                    progress(status)
                else:
                    print(f"[task {task_id}] status: {status}")
                last = status
            if status in TERMINAL_STATUSES:
                return status
            time.sleep(poll_interval)
        raise CapeError(
            f"task {task_id} did not terminate within {max_wait}s (last status: {last})"
        )

    def fetch_report(self, task_id: int) -> dict[str, Any]:
        """Fetch the full JSON report. Note: report endpoint returns raw JSON, not wrapped."""
        r = self.session.get(
            f"{self.base}/apiv2/tasks/get/report/{task_id}/json/",
            timeout=120,  # reports can be multi-MB
        )
        r.raise_for_status()
        return r.json()

    def delete(self, task_id: int) -> bool:
        """
        Delete task and associated analysis data. Returns True on success.

        Raises CapeError if CAPE refuses. The endpoint ships disabled
        (`[taskdelete] enabled = no` in conf/api.conf) and a disabled endpoint
        answers HTTP 200 with an error body, so the status code alone cannot be
        trusted -- reading it as success would report a deletion that never
        happened. GET is the only method the route accepts; POST answers 405.
        """
        try:
            r = self.session.get(
                f"{self.base}/apiv2/tasks/delete/{task_id}/",
                timeout=self.http_timeout,
            )
            r.raise_for_status()
            body = r.json()
        except requests.RequestException as exc:
            raise CapeError(f"delete task {task_id} failed: {exc}") from exc
        except ValueError as exc:  # non-JSON body
            raise CapeError(f"delete task {task_id}: unparseable response") from exc
        if body.get("error"):
            raise CapeError(f"delete task {task_id} refused: {body.get('error_value', body)}")
        return True

    # ---------- Channel 3 (cmplog) helpers ----------

    def list_tasks(self, limit: int | None = None, status: str | None = None) -> list[dict]:
        """
        List tasks via GET /apiv2/tasks/list/ (the real route; /apiv2/tasklist/ 404s).

        The payload is data-wrapped like the other task endpoints, but the exact
        shape varies across CAPE builds, so normalize defensively: data may be a
        list of task dicts, or a dict holding a 'tasks'/'data' list. Optional
        client-side filters: keep tasks whose status matches, then slice to limit.
        CAPE's list order is not reliably newest-first, so sort by task id
        descending before filtering and slicing.
        """
        j = self._get("/apiv2/tasks/list/")
        if j.get("error"):
            raise CapeError(f"list_tasks error: {j}")

        data = j.get("data", [])
        if isinstance(data, dict):
            tasks = data.get("tasks") or data.get("data") or []
        else:
            tasks = data
        tasks = [t for t in tasks if isinstance(t, dict)]
        # Sort newest-first by task id: CAPE's native order isn't reliable.
        tasks.sort(key=lambda t: t.get("id") or 0, reverse=True)

        if status is not None:
            tasks = [t for t in tasks if t.get("status") == status]
        if limit is not None:
            tasks = tasks[:limit]
        return tasks

    def fetch_cmplog_logs(
        self,
        task_id: int,
        storage_root: str | Path = "/opt/CAPEv2/storage/analyses",
    ) -> list[Path]:
        """
        Glob a task's cmplog logs on the local filesystem, sorted.

        There is no REST endpoint for per-task uploaded files, so this reads
        {storage_root}/{task_id}/files/cmplog.*.log directly. A readable but
        empty dir returns [] (not an error); an unreadable/absent dir raises
        CapeError steering to a manual copy plus clew correlate --cmplog-dir.
        """
        files_dir = Path(storage_root) / str(task_id) / "files"
        try:
            return sorted(files_dir.glob("cmplog.*.log"))
        except (PermissionError, OSError) as exc:
            raise CapeError(
                f"cannot read cmplog logs under {files_dir}: {exc}. "
                f"Copy them to a readable dir and use: clew correlate --cmplog-dir <dir>"
            ) from exc

    def fetch_trace_logs(
        self,
        task_id: int,
        storage_root: str | Path = "/opt/CAPEv2/storage/analyses",
    ) -> tuple[list[Path], str | None]:
        """
        Glob a task's Channel-3 logs, whichever client produced them.

        Returns (logs, kind) where kind is "drtrace" or "cmplog", or (
        [], None) when the task has neither. drtrace is preferred when both are
        present: a guest with both clients deployed would otherwise silently
        correlate against the older, comparison-only logs.
        """
        files_dir = Path(storage_root) / str(task_id) / "files"
        try:
            for kind in ("drtrace", "cmplog"):
                logs = sorted(files_dir.glob(f"{kind}.*.log"))
                if logs:
                    return logs, kind
            return [], None
        except (PermissionError, OSError) as exc:
            raise CapeError(
                f"cannot read Channel 3 logs under {files_dir}: {exc}. "
                f"Copy them to a readable dir and use: clew correlate --log-dir <dir>"
            ) from exc

    def count_cmplog_lines(
        self,
        task_id: int,
        storage_root: str | Path = "/opt/CAPEv2/storage/analyses",
    ) -> int | None:
        """
        Count real trace records (non-comment, non-blank) across a task's logs.

        Feeds a dashboard RECORDS column, so it degrades to None (never raises)
        when the logs are missing or unreadable. Counts whichever client's logs
        the task has, so the column stays meaningful across the drtrace
        transition rather than reading zero for every new run.
        """
        try:
            logs, _kind = self.fetch_trace_logs(task_id, storage_root)
        except CapeError:
            return None
        total = 0
        try:
            for log in logs:
                with log.open("r", errors="replace") as f:
                    for line in f:
                        s = line.strip()
                        if s and not s.startswith("#"):
                            total += 1
        except (PermissionError, OSError):
            return None
        return total


# ---------- round-trip harness ----------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument(
        "--base",
        default=os.environ.get("CAPE_BASE_URL", "http://127.0.0.1:8000"),
        help="CAPE base URL (scheme://host:port); defaults to $CAPE_BASE_URL",
    )
    p.add_argument("--sample", required=True, help="Path to benign test binary")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument(
        "--keep", action="store_true", help="Skip delete at end (keep for manual inspection)"
    )
    args = p.parse_args()

    c = CapeClient(args.base)

    print("1/5 status check")
    st = c.status()
    print(f"    tasks: {st.get('tasks')}")

    print("2/5 submit")
    tid = c.submit(args.sample, timeout=args.timeout, enforce_timeout=True)
    print(f"    task_id={tid}")

    print("3/5 poll")
    final = c.poll(tid, poll_interval=2, max_wait=args.timeout * 4)
    print(f"    final status: {final}")

    if final != "reported":
        print("    analysis did not reach 'reported' — skipping report fetch")
        raise SystemExit(1)

    print("4/5 fetch report")
    report = c.fetch_report(tid)
    behavior = report.get("behavior", {})
    processes = behavior.get("processes", [])
    apistats = behavior.get("apistats", {})

    total_from_procs = sum(len(p.get("calls", [])) for p in processes)
    total_from_apistats = sum(sum(v.values()) for v in apistats.values())

    print(f"    processes seen: {len(processes)}")
    print(f"    API calls via behavior.processes[].calls: {total_from_procs}")
    print(f"    API calls via behavior.apistats: {total_from_apistats}")

    if total_from_procs == 0 and total_from_apistats == 0:
        print("    !! both signal sources empty — debug needed")
    else:
        # Build aggregate API call counts from whichever source worked
        agg: dict[str, int] = {}
        if total_from_apistats:
            for pid_stats in apistats.values():
                for api, n in pid_stats.items():
                    agg[api] = agg.get(api, 0) + n
        else:
            for p in processes:
                for call in p.get("calls", []):
                    api = call.get("api", "?")
                    agg[api] = agg.get(api, 0) + 1
        top = sorted(agg.items(), key=lambda kv: -kv[1])[:5]
        print("    top 5 APIs:")
        for api, n in top:
            print(f"      {api:40s} {n}")

    if args.keep:
        print("5/5 skip delete (--keep)")
    else:
        print("5/5 delete")
        ok = c.delete(tid)
        print(f"    deleted: {ok}")

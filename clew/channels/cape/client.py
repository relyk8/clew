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
from typing import Any

import requests


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
        r = self.session.get(f"{self.base}{path}", timeout=timeout or self.http_timeout)
        r.raise_for_status()
        return r.json()

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
            data["options"] = ",".join(f"{k}={v}" for k, v in options.items())
        if machine:
            data["machine"] = machine
        if package:
            data["package"] = package

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
    ) -> str:
        """
        Block until task reaches a terminal state. Returns the final status.
        Terminal states: 'reported', 'failed_analysis', 'failed_processing'.
        """
        terminal = {"reported", "failed_analysis", "failed_processing"}
        deadline = time.monotonic() + max_wait
        last = None
        while time.monotonic() < deadline:
            info = self.view(task_id)
            status = info.get("status", "unknown")
            if status != last:
                print(f"[task {task_id}] status: {status}")
                last = status
            if status in terminal:
                return status
            time.sleep(poll_interval)
        raise TimeoutError(
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
        """Delete task and associated analysis data. Returns True on success."""
        # Newer CAPE builds prefer GET; if yours is 404, swap to POST.
        r = self.session.get(
            f"{self.base}/apiv2/tasks/delete/{task_id}/",
            timeout=self.http_timeout,
        )
        if r.status_code == 404:
            r = self.session.post(
                f"{self.base}/apiv2/tasks/delete/{task_id}/",
                timeout=self.http_timeout,
            )
        # Treat HTTP 200 as success; some builds omit the error field entirely
        return r.status_code == 200


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

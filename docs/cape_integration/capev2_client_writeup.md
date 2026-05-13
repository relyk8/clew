# CAPE REST Client Setup Guide

This document walks through setting up an automated Python client that can submit binaries to a CAPEv2 sandbox, poll for completion, fetch analysis reports, and delete tasks — all over the network, without touching the CAPE web UI.

It assumes you already have a working CAPE installation with a configured detonation guest. Everything here is about the client-side integration and the minimal CAPE-side config changes needed to drive it programmatically.

## Target architecture

```
Windows 11 host (runs the Python client)
        │
        │  HTTP over VMware NAT
        ▼
Ubuntu 24.04 VM (runs CAPEv2 services)
        │
        │  libvirt / KVM
        ▼
Windows 10 guest (detonation sandbox — 192.168.122.101)
```

The client runs on the Windows 11 host. It talks to CAPE's REST API on the Ubuntu VM at port 8000. CAPE in turn drives the Windows 10 guest through KVM/libvirt and reports results back.

---

## Prerequisites

- CAPEv2 installed on an Ubuntu 24.04 VM via `cape2.sh base`, with services `cape`, `cape-processor`, `cape-rooter`, `cape-web` running
- A configured detonation guest (here named `win10`) registered in CAPE's `kvm.conf`, with a clean snapshot taken
- Network path from the host to the Ubuntu VM (default VMware NAT on VMnet8 works out of the box)
- Python 3.11 available for installation on the Windows host
- A benign test binary for round-trip verification. **Do not use `calc.exe`** — on modern Windows it's a UWP stub that exits instantly and produces no meaningful trace. Use `putty.exe` (any recent release from the official PuTTY site) or compile a trivial Win32 hello-world with mingw

---

## Step 1 — Enable the CAPE status endpoint

By default CAPE's `/apiv2/cuckoo/status/` endpoint is disabled. Enabling it gives you a cheap smoke-test endpoint for health checks and queue monitoring.

On the Ubuntu VM, edit the API config:

```bash
sudo nano /opt/CAPEv2/conf/api.conf
```

Set the following in the `[cuckoo_status]` section:

```ini
[cuckoo_status]
enabled = yes
```

Also set in the `[api]` section to remove rate limiting (essential for automated clients — the default limit will throttle you within minutes):

```ini
[api]
ratelimit = no
token_auth_enabled = no
```

The task-related endpoints (`tasks_create_file`, `tasks_view`, `tasks_status`, `tasks_report`, `tasks_delete`) are enabled by default and don't need to be added to the config — CAPE only lists non-default endpoints in `api.conf`. Anything not mentioned uses its default behavior.

Restart `cape-web`:

```bash
sudo systemctl restart cape-web.service
sudo systemctl status cape-web.service --no-pager
```

You should see `Active: active (running)`. Do **not** restart `cape`, `cape-rooter`, or `cape-processor` — they're unaffected by `api.conf` and restarting them mid-analysis kills in-flight tasks.

Verify the API is responding with real JSON:

```bash
curl -s http://127.0.0.1:8000/apiv2/cuckoo/status/ | python3 -m json.tool
```

Expected output is a JSON object with `"error": false` and a `"data"` block containing CAPE version, machine counts, task counters, and server stats. You want to see `"machines": {"total": 1, "available": 1}` (or whatever matches your guest count).

---

## Step 2 — Establish the network path

### Find the Ubuntu VM's IP

On the Ubuntu VM:

```bash
ip -4 addr show dev ens33 | grep inet
```

Note the IP. It'll be on VMware's NAT subnet — something like `192.168.182.134/24`.

### Verify the host is on the matching subnet

On the Windows 11 host, in PowerShell:

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -like "*VMnet8*"
```

The host's VMnet8 address should be on the same `/24` as the Ubuntu VM (e.g. `192.168.182.1`). This means no port forwarding is needed — the host routes directly through VMnet8.

### Test reachability

```powershell
Test-NetConnection -ComputerName <ubuntu_vm_ip> -Port 8000
```

`TcpTestSucceeded : True` confirms the path works.

Round-trip the API:

```powershell
curl.exe -s http://<ubuntu_vm_ip>:8000/apiv2/cuckoo/status/
```

Use `curl.exe` explicitly — PowerShell aliases `curl` to `Invoke-WebRequest`, which returns a different output structure. You should see the identical JSON payload you got from inside the Ubuntu VM.

### Pin the VM's IP with a static DHCP lease

VMware NAT leases drift across reboots. To pin the IP permanently:

On the Ubuntu VM, grab its MAC address:

```bash
ip link show dev ens33 | grep ether
```

On the Windows 11 host, edit `C:\ProgramData\VMware\vmnetdhcp.conf` as administrator. Add a top-level `host` block inside the `# Virtual ethernet segment 8` section, **as a sibling to the existing `host VMnet8` block** (not nested inside it):

```
host VMnet8 {
    hardware ethernet 00:50:56:C0:00:08;
    fixed-address 192.168.182.1;
    option domain-name-servers 0.0.0.0;
    option domain-name "";
    option routers 0.0.0.0;
}
host cape-ubuntu {
    hardware ethernet <MAC_FROM_ABOVE>;
    fixed-address 192.168.182.134;
}
# End
```

The braces matter — `host cape-ubuntu` must be a top-level block, not nested inside `host VMnet8`. Incorrect nesting causes the DHCP service to either fail to start or silently ignore the whole `VMnet8` config.

Restart the VMware services in an admin PowerShell:

```powershell
Restart-Service "VMware DHCP Service"
Restart-Service "VMware NAT Service"
```

Verify the service came back up:

```powershell
Get-Service "VMware DHCP Service"
```

Status should be `Running`. If it's `Stopped`, the config has a syntax error — check Event Viewer → Windows Logs → System for the DHCP service failure message.

Ubuntu 24.04 uses `systemd-networkd` and doesn't ship `dhclient`, so there's no need to force-renew the lease. The binding is simply active from the next reboot onward, and the current IP is unchanged.

---

## Step 3 — Install Python and set up the client

### Install Python 3.11 on the Windows host

The `py` launcher's winget-based auto-install is unreliable on Windows 11 25H2. Install directly from python.org instead:

```powershell
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe" -OutFile "$env:TEMP\python-3.11.9.exe"
Start-Process "$env:TEMP\python-3.11.9.exe" -ArgumentList "/quiet","InstallAllUsers=0","PrependPath=1","Include_launcher=1" -Wait
```

This is a silent per-user install that adds Python to PATH and registers it with the `py` launcher. Close and reopen PowerShell after installation — PATH changes don't propagate to the current session.

Verify:

```powershell
py -3.11 --version
```

Should print `Python 3.11.9`.

### Create the project directory and venv

```powershell
py -3.11 -m venv C:\ariadnex\venv
C:\ariadnex\venv\Scripts\Activate.ps1
pip install requests
```

If PowerShell blocks the activation script with an execution policy error, run once in an admin PowerShell:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then reactivate the venv.

### Drop in the CAPE client

Save the following as `C:\ariadnex\cape_client.py`:

```python
"""
Minimal CAPE REST client.
Targets CAPEv2 apiv2 endpoints. Tested against the services-based layout
(cape, cape-web, cape-processor, cape-rooter).
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
        r = self.session.get(
            f"{self.base}{path}", timeout=timeout or self.http_timeout
        )
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
        Always passes enforce_timeout=1 by default — required because
        sleepy anti-analysis samples will otherwise hang the guest.
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
        Block until task reaches a terminal state. Returns final status.
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
            f"task {task_id} did not terminate within {max_wait}s "
            f"(last status: {last})"
        )

    def fetch_report(self, task_id: int) -> dict[str, Any]:
        """Fetch the full JSON report. Report endpoint returns raw JSON, not wrapped."""
        r = self.session.get(
            f"{self.base}/apiv2/tasks/get/report/{task_id}/json/",
            timeout=120,
        )
        r.raise_for_status()
        return r.json()

    def delete(self, task_id: int) -> bool:
        """Delete task and associated analysis data."""
        r = self.session.get(
            f"{self.base}/apiv2/tasks/delete/{task_id}/",
            timeout=self.http_timeout,
        )
        if r.status_code == 404:
            r = self.session.post(
                f"{self.base}/apiv2/tasks/delete/{task_id}/",
                timeout=self.http_timeout,
            )
        return r.status_code == 200


# ---------- round-trip harness ----------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://192.168.182.134:8000",
                   help="CAPE base URL (scheme://host:port)")
    p.add_argument("--sample", required=True, help="Path to benign test binary")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--keep", action="store_true",
                   help="Skip delete at end (keep for manual inspection)")
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
```

### Run the round-trip

Drop a benign test binary alongside the script (for example `putty.exe`) and run:

```powershell
cd C:\ariadnex
python cape_client.py --base http://192.168.182.134:8000 --sample .\putty.exe
```

Expected output:

```
1/5 status check
    tasks: {'total': 2, 'pending': 0, 'running': 0, 'completed': 0, 'reported': 2}
2/5 submit
    task_id=3
3/5 poll
[task 3] status: pending
[task 3] status: running
[task 3] status: completed
[task 3] status: reported
    final status: reported
4/5 fetch report
    processes seen: 1
    API calls via behavior.processes[].calls: 1096
    API calls via behavior.apistats: 0
    top 5 APIs:
      LdrGetProcedureAddressForCaller          133
      NtProtectVirtualMemory                   123
      NtClose                                  89
      NtAllocateVirtualMemory                  73
      RegEnumValueW                            68
5/5 delete
    deleted: True
```

The top-5 APIs listed are textbook Win32 PE-load / DLL-resolve / config-read behavior — this is exactly what you expect from a GUI binary starting up.

---

## Step 4 — Sanity checks

### Snapshot revert automation

Every analysis should run against a clean guest snapshot, with CAPE handling the revert automatically via `virsh snapshot-revert` between tasks.

The implicit confirmation: if you run three tasks back-to-back and each produces fresh, consistent results without failures or contamination from previous runs, snapshot revert is working correctly.

To explicitly verify, tail the CAPE service log while submitting:

```bash
sudo journalctl -u cape.service -f
```

Look for lines like `INFO: Reverting machine 'win10' to snapshot '<name>'`.

If revert isn't happening:

- **Permissions**: the `cape` user must be in the `libvirt` and `kvm` groups. Test with `sudo -u cape virsh list --all`.
- **Snapshot type**: use internal qcow2 snapshots only (`virsh snapshot-create-as win10 clean --atomic`). External snapshots cause delete failures on revert after repeated use.
- **Config match**: the snapshot name in `/opt/CAPEv2/conf/kvm.conf` must exactly match what `virsh snapshot-list win10` shows. Mismatch causes CAPE to silently use the VM's current state instead of reverting.

### API call data populated

The report schema in recent kevoreilly/CAPEv2 builds uses `behavior.processes[].calls` as the primary API trace source, not the older `behavior.apistats` field. The top-level keys under `behavior` in a current report are:

```
['processes', 'anomaly', 'processtree', 'summary', 'enhanced', 'encryptedbuffers', 'network_map']
```

Note that `apistats` is not present. This is normal and not a misconfiguration. The harness above reads from `behavior.processes[].calls` and derives counts from there using `collections.Counter` semantics — strictly richer information than `apistats` would have provided, since each call entry includes full arguments, return values, timestamps, and thread IDs.

If you want bare call counts derived from `.calls`:

```python
from collections import Counter
counts = Counter(
    call["api"]
    for p in report["behavior"]["processes"]
    for call in p["calls"]
)
```

The sanity check passes when the harness prints a non-zero "API calls via behavior.processes[].calls" count and displays a plausible top-5 list for the test binary.

---

## Available behavior report fields

For reference, recent CAPEv2 reports expose these fields under `behavior`:

| Field | Content |
|---|---|
| `processes` | Per-process API call traces — ordered, with args and return values |
| `summary` | Aggregated IoCs — file/registry/network/command/mutex/service lists |
| `processtree` | Process spawning relationships |
| `anomaly` | Flagged unusual behaviors |
| `enhanced` | Parsed higher-level events |
| `encryptedbuffers` | Detected crypto operations |
| `network_map` | Summarized network behavior |

The `summary` block is particularly useful for automated signal extraction. It typically contains keys like `files`, `read_files`, `write_files`, `delete_files`, `keys`, `read_keys`, `write_keys`, `delete_keys`, `executed_commands`, `resolved_apis`, `mutexes`, `created_services`, and `started_services` — each a list of the corresponding operations observed during analysis.

---

## Project layout

Final state of the project directory after setup:

```
C:\ariadnex\
├── .git/                    repo metadata
├── .gitignore               excludes venv, *.exe, caches
├── cape_client.py           the client + harness
├── requirements.txt         pinned deps (generated with `pip freeze`)
├── venv/                    local venv (not committed)
└── putty.exe                test binary (not committed)
```

Recommended `.gitignore`:

```
venv/
__pycache__/
*.pyc
*.pyo
.pytest_cache/
.vscode/
.idea/

# Test binaries — don't commit executables
*.exe
*.dll
*.msi

# Local config / secrets
.env
*.local.*
```

Pin dependencies before committing:

```powershell
pip freeze > requirements.txt
```

Anyone cloning the repo can reproduce the environment with:

```powershell
py -3.11 -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## Notes on nested virtualization

This setup runs CAPE inside a VMware VM, which in turn runs KVM for the detonation guest — a four-layer nested stack. A few points worth flagging:

- Expect 60–120 seconds per analysis even for trivial benchmark binaries. This is revert + guest boot stabilization + detonation + capemon log flush + processing. It's the baseline; later optimization (memory-backed snapshots, skipping unused processing modules) can roughly halve this.
- Windows 11 cumulative updates can silently re-enable Memory Integrity / VBS, which breaks VMware's `vhv.enable` flag. After any host update, verify with `systeminfo | findstr /C:"Virtualization-based security"` before starting the Ubuntu VM. If VBS is running, disable it in Core Isolation, reboot, and confirm `kvm-ok` still reports acceleration available inside Ubuntu.
- VMware NAT DHCP leases drift across reboots without a static lease configured. The `vmnetdhcp.conf` edit in Step 2 prevents this.

---

## What this setup gives you

At the end of these four steps you have:

- A reliable, automated Python client that round-trips arbitrary binaries through CAPE with no UI interaction
- Verified network path from the Windows host to the sandbox
- Confirmed automated snapshot lifecycle (clean guest state every analysis)
- Rich API call traces and IoC data from each analysis, accessible as Python dicts

This is the foundation. Anything built on top of it — reward functions, reinforcement learning environments, fuzzing pipelines — becomes straightforward because the sandbox integration is already solved.

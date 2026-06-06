# CAPEv2 Migration to `ml-cluster-01`

**Date:** 2026-06-06
**Operator:** capeadmin (admin), kirito / relyk8 (researchers)
**Goal:** Migrate the working CAPEv2 sandbox from the bare-metal box ("box #2") onto repurposed hardware (`ml-cluster-01`, ~10x RAM) to serve as the official build for thesis research (Clew / ariadneX).

---

## 1. Outcome

The migration is **complete and verified end-to-end**. A benign detonation test (al-khaser) was submitted and reached `reported` status with a full analysis tree and `report.json` — confirming the entire pipeline works: scheduler → guest revert → agent execution → result-server return → processing/report.

**Verified working:**
- Clean host OS, multi-user account model, Docker disabled
- CAPEv2 base + PostgreSQL + MongoDB + all services (`cape`, `cape-rooter`, `cape-processor`, `cape-web`)
- Custom anti-VM QEMU 9.2.2 + SeaBIOS + libvirt 11.1.0 (modular daemons)
- Windows 10 guest migrated from box #2, boots on new CPU, agent reachable, clean snapshot captured
- 157,030-file PE malware corpus downloaded + extracted on the 11 TB volume
- Clew environment (code + venv + capa) functional; packaging fix committed to repo

---

## 2. Host preparation

### 2.1 Hardware / disk layout (IMPORTANT)
- `/dev/sda1` → `/home` → **11 TB** (the large data volume; ext4)
- `/dev/sdb2` → `/` (root) → **468 GB** (system partition; ext4)
- `/dev/sdb1` → `/boot/efi`

**Key lesson:** `/srv` and `/opt` live on the small 468 GB root partition. All large data must be placed on `/home` (11 TB) and symlinked, or it will fill the root partition.

### 2.2 Account cleanup
- Repurposed from a graduated student's ML box (authorized handoff).
- **Deleted** `sthrelkeld` (student) — `userdel -r`, reclaimed ~10 TB.
- **Locked** `mdallmeyer` (advisor) — `usermod -L`, data preserved, login disabled.
- **Left untouched** `ansible` — provisioning account with passwordless-root sudo via an external key (commented `CDN-ZBook`); presumed cluster-management. **OPEN ITEM:** confirm owner / decide whether to keep this access path on a malware-analysis box.

### 2.3 Account / privacy model
- `capeadmin` — sole sudo/admin/maintenance account.
- `kirito`, `relyk8` — co-equal researcher accounts, **no sudo**, private homes (`chmod 750`), members of `kvm`, `libvirt`, `research` groups.
- Privacy is enforced between researchers via home-dir perms; sudo deliberately withheld so no researcher can read another's credentials.
- Shared group `research`; shared data dir with setgid so new files inherit the group.

### 2.4 System prep
- Applied 144 pending updates, rebooted onto kernel `6.8.0-124` (later `6.17.0-35`).
- Disabled Docker + containerd (`systemctl disable --now docker containerd docker.socket`) — its iptables/bridge handling conflicts with CAPE network isolation.

---

## 3. CAPEv2 installation

- Cloned to `/opt/CAPEv2`, ran `installer/cape2.sh base`.
- **`cape2.sh` config:** left sandbox network defaults (`NETWORK_IFACE=virbr1` / `IFACE_IP` are the *isolated guest* network, NOT the physical NIC — the script auto-detects the real NIC via the default route). Set DB password.
- Poetry venv at `/etc/poetry/venv/bin/poetry`; symlinked to `/usr/local/bin/poetry`.
- **Fix:** dependency install was incomplete after base run — re-ran `poetry install --no-root` to populate the venv (`pytz`, `pyzipper`, `sqlalchemy`, etc.).

---

## 4. KVM / QEMU anti-VM build

- Confirmed VT-x (`vmx`), Secure Boot disabled, KVM acceleration available.
- Derived host ACPI OEM ID for reference: **OEM ID `HPQOEM`, OEM Table ID `SLIC-WKS`**.
- Edited `installer/kvm-qemu.sh` device-disguise replacers (the `<WOOT>` placeholders — these are QEMU/Bochs/SeaBIOS device-string disguises, NOT the motherboard OEM ID):
  - `PEN_REPLACER=Wacom`, `SCSI_REPLACER=Samsung`, `ATAPI_REPLACER=Toshiba`, `MICRODRIVE_REPLACER=SanDisk`, `BOCHS_BLOCK_REPLACER=Samsung`, `BOCHS_BLOCK_REPLACER2=Seagate`, `BOCHS_BLOCK_REPLACER3=Hitachi`, `BXPC_REPLACER=HP` (kept short — length-limited ACPI field), `BOCHS_SEABIOS_BLOCK_REPLACER=AMI`.
- Set `VM_NETWORK_RANGE=192.168.122` to match box #2 / libvirt `default`.
- Ran `./kvm-qemu.sh all cape` (compiles QEMU/SeaBIOS/libvirt from source with anti-VM patches; ~30–45 min). Rebooted.
- Result: QEMU 9.2.2, modular libvirt daemons (`virtqemud`, `virtnetworkd`, `virtstoraged`) active, `default` net on `192.168.122.0/24`, host gateway `192.168.122.1` (`virbr0`).

> **Maintenance warning (from the installer):** never `apt install -f`, `make install`, or force-upgrade — it will clobber the custom-compiled QEMU/libvirt packages. When upgrading the OS, uninstall qemu/libvirt first.

---

## 5. Guest migration (from box #2)

Source: box #2 had a full working CAPE (home-dir install at `/home/user/CAPEv2`, not systemd-managed), guest `win10` on libvirt `default`.

- Transferred via `rsync` over VPN: `win10.qcow2` (65 GB, ~69.8 GB file), `guest.xml`, snapshot metadata XMLs.
  - Source qcow2 was `qemu:qemu`-owned 660 — used `sudo rsync` (read as root) to transfer.
  - Staged to `/home/capeadmin/`, then `sudo mv` into `/var/lib/libvirt/images/` (avoids permission issues writing to libvirt dir as non-root).
- Ownership: `chown libvirt-qemu:kvm`, `chmod 660`.
- Edited `guest.xml`: fresh `<uuid>` (uuidgen), confirmed disk path, left `<cpu mode='host-passthrough'>`.
- `virsh define guest.xml` → cold-boot succeeded on the new CPU (no repair loop; host-passthrough fine).
- Guest is **statically addressed `192.168.122.101`** (no DHCP lease — confirmed via `domifaddr --source arp`).
- Display is **SPICE** (`spice://127.0.0.1:5900`) — viewed via `virt-viewer`/RemoteViewer over an SSH tunnel (not VNC).
- Inherited internal snapshots (`clean_snapshot`, `drio_installed`, `drio_wrapper`) rode along inside the qcow2 but were unregistered with libvirt. Because they captured box #2's running CPU state, took a **fresh baseline** instead:
  - Agent (`update_service.pyw`, the renamed CAPE agent) started manually inside the guest; confirmed listening on `192.168.122.101:8000`.
  - `virsh snapshot-create-as win10 clean_snapshot_mlcluster ... --atomic` (running state, agent-up).

---

## 6. CAPE configuration

`/opt/CAPEv2/conf/kvm.conf`:
```ini
[kvm]
machines = win10
interface = virbr0
dsn = qemu:///system

[win10]
label = win10
platform = windows
ip = 192.168.122.101
arch = x64
snapshot = clean_snapshot_mlcluster
interface = virbr0
resultserver_ip = 192.168.122.1
resultserver_port = 2042
```

`/opt/CAPEv2/conf/cuckoo.conf`:
- `machinery = kvm`
- **Fix:** result-server `ip` was the stale installer default `192.168.1.1` → corrected to `192.168.122.1` (host's `virbr0` gateway). Without this, guest results never return.

**Critical fix — libvirt-python:** `cape` service failed at startup with `ModuleNotFoundError: No module named 'libvirt'` (the KVM machinery requires the Python binding, which the base install missed because libvirt was added later). Resolved:
```bash
sudo -u cape /etc/poetry/venv/bin/poetry run pip install libvirt-python
```
After this all four services reached `active`.

---

## 7. Smoke test

```bash
cd /opt/CAPEv2
sudo -u cape /etc/poetry/venv/bin/poetry run python3 utils/submit.py \
  /srv/shared/clew-env/clew/tests/fixtures/al-khaser_x86.exe
```
- Task ID 1 → status **`reported`**.
- `storage/analyses/1/reports/report.json` generated (283 KB).
- `analysis.log` shows clean completion (sample ran, results uploaded to result server, "Analysis completed").
- al-khaser is a VM-detection tool, so the report doubles as an anti-VM stealth check (review `signatures` in the report for evasion-detection results — relevant to Clew/ariadneX).

---

## 8. Malware corpus (VirusTotal Academic)

- Downloaded via `rclone` (Google Drive remote, read-only scope, headless OAuth) into the shared dir.
- Scope: **Win32_EXE.7z only**, all four available years (Clew is PE32-only; other file types out of scope). Drive only contains 2017, 2019(empty for this type), 2020, 2021.
- Archives (~45 GB compressed): 2017-10-20 (14G), 2017-11-20 (1.5G), 2020-05-06 (20G), 2021-11-03 (11G).
- **Per-archive passwords differ:** 2020-05-06 uses `VirusTotal`; the other three use `infected`. (Verify with `7z t -p<pw>` before extracting.)
- Extracted counts (total **157,030 files**):
  - 2017-10-20: 38,438
  - 2017-11-20: 13,762
  - 2020-05-06: 76,888
  - 2021-11-03: 27,942
- **Keep the `.7z` archives** as canonical password-protected source; do not delete.
- **Safety:** live malware extracted to disk — ensure nothing auto-scans/indexes the corpus dir; never place on the guest analysis network except via deliberate CAPE submission.

---

## 9. Clew environment

- `clew-env` (al-khaser, capa-rules, capa-src, clew, pfuzzer, .venv) present and intact (git working tree clean, matches `origin/main`).
- venv survived relocation (symlink preserves absolute paths); `capa` and `clew` import OK.
- **Packaging fix committed + pushed** (`relyk8/clew` `main`, commit `a8046d1`): added to `pyproject.toml`:
  ```toml
  [build-system]
  requires = ["setuptools>=61"]
  build-backend = "setuptools.build_meta"

  [tool.setuptools.packages.find]
  include = ["clew*"]
  ```
  Resolves "Multiple top-level packages discovered" error; `pip install -e .` now works.
- Resolved a git false-diff (copy set `+x` on all files): `git config core.fileMode true` + `git checkout -- .` to restore committed modes.

---

## 10. Storage relocation to 11 TB volume

- `/srv/shared` was on the 468 GB root partition; relocated to the 11 TB volume:
  ```bash
  sudo mkdir -p /home/shared
  sudo rsync -aP /srv/shared/ /home/shared/
  sudo rm -rf /srv/shared
  sudo ln -s /home/shared /srv/shared
  sudo chown -R root:research /home/shared && sudo chmod -R 2775 /home/shared
  ```
- `/srv/shared` → symlink → `/home/shared` (`/dev/sda1`, 11 TB). Paths unchanged for venv/configs; data now on the big disk. Verified env still imports.

---

## 11. Pending / TODO (none blocking; box is operational)

1. **Move CAPE `storage/` to 11 TB disk** — `/opt/CAPEv2/storage/` is still on the 468 GB root partition and grows per-analysis. Stop services, rsync to `/home/cape-storage`, symlink, chown `cape:cape`, restart.
2. **Rotate PostgreSQL password** — currently the installer default `SuperPuperSecret` in `cuckoo.conf` DSN. `ALTER USER cape WITH PASSWORD ...` + update the `connection` DSN to match.
3. **Network isolation review** — guest is on libvirt `default` (NAT with internet). Decide whether live-malware runs should have internet on this institutional `/21`, or switch the guest to a host-only/isolated network.
4. **`ansible` account / `CDN-ZBook` key** — confirm owner; decide whether passwordless-root external access stays on a malware box.
5. **Agent autostart (optional)** — agent currently in the guest Startup folder but cold-boot autostart not verified working (likely needs auto-login via `netplwiz`). NOT required: CAPE reverts to the agent-up snapshot before every analysis and never cold-boots in normal operation. Low priority.
6. **File-mode cleanup** on corpus dir (cosmetic; copy set `+x` on samples).

---

## Quick reference

| Item | Value |
|---|---|
| Host | `ml-cluster-01` (`10.202.1.9`, iface `eno1`) |
| Big disk | `/dev/sda1` → `/home` (11 TB) |
| Guest | `win10`, static IP `192.168.122.101`, SPICE display |
| Snapshot | `clean_snapshot_mlcluster` (running, agent-up) |
| Host gateway (guest net) | `192.168.122.1` (`virbr0`) |
| Result server | `192.168.122.1:2042` |
| QEMU | 9.2.2 (custom anti-VM build) |
| CAPE | `/opt/CAPEv2`, service user `cape`, poetry at `/etc/poetry/venv/bin/poetry` |
| Shared data | `/srv/shared` → `/home/shared` (corpus + clew-env) |
| Corpus | 157,030 PE samples, `/srv/shared/virustotal/<year>/<date>/extracted/Win32_EXE/` |
| Agent port | `192.168.122.101:8000` |

# CAPEv2 Malware Sandbox Deployment Guide

## Nested Virtualization: Windows 11 → VMware → Ubuntu 24.04 → KVM → Windows 10

This document is a step-by-step guide for deploying a working CAPEv2 malware analysis sandbox using a nested virtualization stack. It is written so that someone with no prior experience in virtualization, Linux administration, or malware analysis infrastructure can follow along and reproduce the deployment.

---

## Table of Contents

1. [What You're Building and Why](#what-youre-building-and-why)
2. [Prerequisites](#prerequisites)
3. [Phase 1: Preparing the Windows 11 Host](#phase-1-preparing-the-windows-11-host)
4. [Phase 2: Creating the Ubuntu 24.04 VM in VMware](#phase-2-creating-the-ubuntu-2404-vm-in-vmware)
5. [Phase 3: Ubuntu Configuration and Verification](#phase-3-ubuntu-configuration-and-verification)
6. [Phase 4: Custom QEMU/KVM with Anti-Detection Patches](#phase-4-custom-qemukvm-with-anti-detection-patches)
7. [Phase 5: CAPEv2 Installation](#phase-5-capev2-installation)
8. [Phase 6: Windows 10 Guest VM in KVM](#phase-6-windows-10-guest-vm-in-kvm)
9. [Phase 7: Hardening Windows 10 for Malware Analysis](#phase-7-hardening-windows-10-for-malware-analysis)
10. [Phase 8: CAPEv2 Configuration](#phase-8-capev2-configuration)
11. [Phase 9: Starting Services and First Analysis](#phase-9-starting-services-and-first-analysis)
12. [Final Architecture](#final-architecture)
13. [Recommendations for Future Work](#recommendations-for-future-work)
14. [Troubleshooting Quick Reference](#troubleshooting-quick-reference)
15. [Key Lessons Learned](#key-lessons-learned)

---

## What You're Building and Why

**What is CAPEv2?** CAPEv2 (Config And Payload Extraction, version 2) is an open-source automated malware analysis system — often called a "sandbox." You submit a suspicious file, CAPEv2 runs it inside an isolated Windows VM, watches what it does (files it touches, registry keys it modifies, network connections it opens, memory it allocates), and produces a detailed report. It extracts indicators of compromise, detects known malware families via YARA rules, and often extracts embedded C2 configurations.

**Why nested virtualization?** CAPEv2 requires KVM (a Linux hypervisor) to run its analysis guests. If your only machine runs Windows, you need to run Linux inside a VM on Windows, then run KVM inside that Linux VM. This "VM inside a VM" arrangement is called **nested virtualization**. It adds 10–30% performance overhead but is often the only practical option on Windows hardware.

**What the finished system does:**
1. You upload a suspicious file through a web UI
2. CAPEv2 reverts a Windows 10 VM to a known-clean snapshot
3. The VM boots, receives the file, and executes it
4. CAPEv2 monitors everything the malware does
5. When the analysis window ends, the VM is destroyed and reverted
6. You get a full report: behavior graph, network captures, screenshots, YARA matches, IOCs

**Stack overview:**
```
Windows 11 Host
  └─ VMware Workstation (outer hypervisor)
     └─ Ubuntu 24.04 VM (runs CAPEv2 orchestration)
        └─ KVM (nested hypervisor)
           └─ Windows 10 Guest (where malware runs)
```

---

## Prerequisites

### Hardware Requirements

This guide was performed on:

| Component | Specification |
|---|---|
| Host hardware | HP Elite Mini 800 G9 Desktop PC |
| Host OS | Windows 11 Pro (Build 26200) |
| CPU | Intel Core (13th gen, Raptor Lake), 14 threads |
| RAM | 64 GB |
| Storage | NVMe SSD |

**Minimum recommendations for anyone attempting this:**
- CPU with VT-x (Intel) or AMD-V support (any modern Intel i5/i7 or AMD Ryzen)
- At least 32 GB RAM (for a single analysis guest); 64 GB strongly preferred
- At least 500 GB SSD (NVMe strongly preferred — spinning disks are too slow)
- A CPU with at least 8 physical threads

### Software You Need to Obtain Before Starting

1. **VMware Workstation Pro** (free as of 2024 from Broadcom with account registration). VirtualBox also works but is not covered in this guide.
2. **Ubuntu 24.04 LTS Desktop ISO** from https://ubuntu.com/download/desktop
3. **Windows 10 ISO** (Enterprise or Pro) — evaluation versions are fine, available from https://www.microsoft.com/evalcenter
4. **VirtIO Drivers ISO** — downloaded later inside Ubuntu

### Skills Assumed

This guide will walk you through everything, but some basic familiarity helps:
- Running commands in a terminal (Linux) or command prompt (Windows)
- Navigating Windows Settings and Control Panel
- Editing text files
- Downloading and installing software

If you've never used Linux, don't worry — every command is written out.

### Expected Time Investment

- **Active hands-on time:** 4–6 hours
- **Waiting time** (compilations, installs, initial boots): 2–4 hours
- **Total real-world time:** typically a full day, ideally spread over two sessions

---

## Phase 1: Preparing the Windows 11 Host

**Goal:** Disable Hyper-V, VBS, and HVCI on Windows 11 so VMware can operate in CPL0 monitor mode. Without this, VMware cannot expose hardware virtualization to the Ubuntu VM, and KVM will refuse to load.

### Why This Matters

Modern Windows 11 installations have **Hyper-V** or **Virtualization-Based Security (VBS)** active by default. When Hyper-V is active, VMware Workstation runs in User-Level Monitor (ULM) mode, which does not support exposing virtualization extensions to guest VMs. For nested KVM to work, VMware must operate in CPL0 monitor mode — and that requires Hyper-V and VBS to be completely off.

### Step 1: Disable Hyper-V Windows Features

1. Press `Win+S` and search for "Turn Windows features on or off"
2. Click the result to open the Windows Features dialog
3. **Uncheck all of the following** (if they are checked):
   - Hyper-V (and all sub-items)
   - Virtual Machine Platform
   - Windows Hypervisor Platform
   - Windows Sandbox
4. Click **OK** — Windows will prompt for a restart. Restart when prompted.

### Step 2: Disable Hyper-V via PowerShell

Open **PowerShell as Administrator** (right-click Start → "Windows Terminal (Admin)" or "PowerShell (Admin)"), then run:

```powershell
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -NoRestart
```

Then open **Command Prompt as Administrator** and run:

```cmd
bcdedit /set hypervisorlaunchtype off
```

### Step 3: Disable Memory Integrity (VBS/HVCI)

1. Open **Windows Security** (search for it in Start)
2. Click **Device Security**
3. Under "Core isolation" click **Core isolation details**
4. Turn **OFF** "Memory Integrity"
5. Windows will prompt for a restart — accept it

### Step 4: Apply Registry Changes to Fully Disable VBS

Open **PowerShell as Administrator** and run:

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0 -Type DWord
```

### Step 5: Reboot and Verify

Reboot the machine. Then open **Command Prompt** and run:

```cmd
systeminfo
```

Scroll through the output and look for these specific lines:

✅ **What you want to see:**
- `Virtualization-based security:` should be **"Not enabled"**
- `Hyper-V Requirements:` should list individual capabilities:
  - `VM Monitor Mode Extensions: Yes`
  - `Virtualization Enabled In Firmware: Yes`
  - `Second Level Address Translation: Yes`
  - `Data Execution Prevention Available: Yes`

❌ **What indicates a problem:**
- `A hypervisor has been detected. Features required for Hyper-V will not be displayed.` — this means Hyper-V is still running. Go back and repeat the steps.

**If VBS persists after reboot** (common on Windows 11 24H2 due to NVRAM firmware locks):
- Option A: Temporarily disable Secure Boot in UEFI BIOS, boot, verify VBS is off, then re-enable Secure Boot
- Option B: Download Microsoft's `DG_Readiness_Tool_v3.6.ps1` and run `DG_Readiness_Tool_v3.6.ps1 -Disable`

### Step 6: Check BIOS Virtualization Settings

If `Virtualization Enabled In Firmware` shows `No` in `systeminfo`, reboot into your BIOS/UEFI and enable:
- **Intel VT-x** (sometimes called "Intel Virtualization Technology")
- **Intel VT-d** (I/O virtualization)
- For AMD systems: **AMD-V** or "SVM Mode"

---

## Phase 2: Creating the Ubuntu 24.04 VM in VMware

**Goal:** Create a VM in VMware Workstation with enough resources to run CAPEv2 and a nested Windows guest, with nested virtualization explicitly enabled.

### Step 1: Install VMware Workstation

Download VMware Workstation Pro from Broadcom's website (free with registration). Install with default settings.

### Step 2: Create a New VM

1. Open VMware Workstation
2. Click **File → New Virtual Machine** (or `Ctrl+N`)
3. Select **Custom (advanced)** → Next
4. Hardware compatibility: leave default → Next
5. **"I will install the operating system later"** → Next
6. Guest OS: **Linux**, Version: **Ubuntu 64-bit** → Next
7. Name: `CAPEv2` (or whatever you prefer). Choose a location with plenty of disk space. → Next
8. Processors: **1 socket × 8 cores** (see note below) → Next
9. RAM: **32 GB** (32768 MB) → Next
10. Network: **Use network address translation (NAT)** → Next
11. SCSI controller: **LSI Logic SAS** (default) → Next
12. Disk type: **SCSI** → Next
13. **Create a new virtual disk** → Next
14. Disk size: **500 GB**, check **"Store virtual disk as a single file"** (or split — either works), and leave **"Allocate all disk space now" UNCHECKED** (thin provisioning) → Next
15. Leave disk filename as default → Next
16. Click **Customize Hardware** before finishing:
    - Click **New CD/DVD (SATA)** → on the right, select **Use ISO image file** and browse to your Ubuntu 24.04 ISO
    - Click **Close**
17. Click **Finish**

> **Note on CPU allocation:** This VM was initially configured with 16 vCPUs but reduced to **8 vCPUs** during tuning. The host's Intel 13th-gen CPU has 14 threads, and allocating 16 vCPUs caused overcommit during Windows installation inside KVM, producing high CPU load and host sluggishness. **8 vCPUs** is the sweet spot — it leaves headroom for the Windows host and still supports 2–3 concurrent KVM analysis guests.

### Step 3: Enable Nested Virtualization (Critical)

**This is the single most important configuration step in this phase.** Without it, KVM will not work inside the Ubuntu VM.

1. With the Ubuntu VM **powered off**, select it in the VMware library
2. Click **Edit virtual machine settings**
3. Go to **Hardware → Processors**
4. Under "Virtualization engine", **check the box for "Virtualize Intel VT-x/EPT or AMD-V/RVI"**
5. Click **OK**

### Step 4: Edit the .vmx File

The `.vmx` file is the VM's configuration file. We need to add parameters that VMware's GUI does not expose.

1. **Close VMware Workstation completely** (not just the VM — the entire application). If any VMware processes are running, they will overwrite your edits.
2. Open File Explorer and navigate to your VM's folder. By default this is `C:\Users\<yourname>\Documents\Virtual Machines\CAPEv2\`
3. Find the file named `CAPEv2.vmx` (same as your VM name, with `.vmx` extension)
4. Right-click → **Open with → Notepad**
5. Scroll to the bottom of the file and add these lines:

```
vhv.enable = "TRUE"
monitor.virtual_mmu = "hardware"
monitor.virtual_exec = "hardware"
hypervisor.cpuid.v0 = "FALSE"
```

6. **Save** the file (`Ctrl+S`) and close Notepad

**What these do:**
- `vhv.enable = "TRUE"` — the main nested virtualization switch. Exposes VT-x/AMD-V to the guest.
- `monitor.virtual_mmu = "hardware"` — use hardware MMU virtualization
- `monitor.virtual_exec = "hardware"` — use hardware execution virtualization
- `hypervisor.cpuid.v0 = "FALSE"` — hide VMware's hypervisor presence from nested guests (useful for anti-detection)

### Step 5: Disable Power Throttling for VMware

Windows 11 may throttle VMware under sustained load, which causes VMs to freeze. Disable it:

1. Open **Command Prompt as Administrator**
2. Run these two commands (adjust paths if you installed VMware somewhere non-default):

```cmd
powercfg /powerthrottling disable /path "C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe"
powercfg /powerthrottling disable /path "C:\Program Files (x86)\VMware\VMware Workstation\x64\vmware-vmx.exe"
```

### Step 6: Install Ubuntu 24.04

1. Reopen VMware Workstation
2. Power on the Ubuntu VM (click the green play button)
3. The VM boots from the Ubuntu ISO. Wait for the installer.
4. Language: **English** → Continue
5. Keyboard: **English (US)** → Continue
6. Connect to the internet: use the default wired connection → Continue
7. Select **"Install Ubuntu"** (not "Try Ubuntu")
8. "How would you like to install Ubuntu?" — **Interactive installation** → Next
9. Applications: **Default selection** → Next
10. **Uncheck** "Install third-party software for graphics and Wi-Fi hardware" (not needed in a VM)
11. **Uncheck** "Download and install support for additional media formats"
12. Installation type: **Erase disk and install Ubuntu** → Next (there's nothing to erase — it's a blank virtual disk)
13. On the "Ready to install" screen, verify you see: `Disk setup: Erase disk and install Ubuntu`, `partition sda1 created`, `partition sda2 formatted as ext4 used for /`
14. Create account:
    - Name: whatever you want (e.g., "CAPE User")
    - Server name / computer name: `CAPEv2`
    - Username: `cape`
    - Password: pick something simple for a lab VM (e.g., `cape123`) — you will type this often
15. Click **Install Now**
16. Wait 10–20 minutes for installation
17. When prompted, click **Restart Now**. If the VM hangs on a black screen, press **Enter** to continue.
18. Log in as `cape`
19. Skip through the welcome tour / Ubuntu Pro signup / telemetry options (decline all)

### Step 7: Verify VMware is in CPL0 Mode

After Ubuntu is installed and running, verify VMware is exposing virtualization correctly:

1. Shut down the Ubuntu VM cleanly (Power → Shut Down)
2. On the Windows host, navigate to the VM's folder
3. Open `vmware.log` in Notepad (it's in the same folder as the `.vmx`)
4. Use `Ctrl+F` to search for: `Monitor Mode:`

✅ **What you want to see:** `Monitor Mode: CPL0`

❌ **What indicates a problem:** `Monitor Mode: ULM` — this means Hyper-V or VBS is still active on the host. Return to Phase 1.

---

## Phase 3: Ubuntu Configuration and Verification

**Goal:** Get Ubuntu fully updated, install VMware integration tools, and verify that hardware virtualization is exposed to the guest.

### Step 1: Open a Terminal

Right-click on the desktop and select **Open in Terminal**, or press `Ctrl+Alt+T`.

### Step 2: Update the System and Install Base Packages

Copy each command one at a time. When prompted, enter your password (it will not show as you type — this is normal). When asked to confirm, press `Y` and Enter.

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y git open-vm-tools open-vm-tools-desktop
sudo reboot
```

**What these packages do:**
- `git` — for cloning the CAPEv2 repository later
- `open-vm-tools` — core VMware integration (time sync, shutdown signals)
- `open-vm-tools-desktop` — enables clipboard sharing, dynamic display resizing, and the vmxnet3 network driver

After reboot, log back in. Clipboard sharing between your Windows host and Ubuntu VM should now work (try copying text from Windows and pasting into Ubuntu).

### Troubleshooting: No Internet in Ubuntu

If `sudo apt update` hangs or fails:
- Check the network icon in the top-right of the Ubuntu desktop — toggle the wired connection off and on
- On the Windows host, open an admin Command Prompt and restart VMware's networking services:
  ```cmd
  net stop "VMware NAT Service"
  net start "VMware NAT Service"
  net stop "VMware DHCP Service"
  net start "VMware DHCP Service"
  ```
- Back in Ubuntu terminal: `sudo nmcli networking off && sudo nmcli networking on`
- Last resort: shut down the VM, open VMware's **Edit → Virtual Network Editor**, click **Restore Defaults**, then power the VM back on

### Step 3: Verify Virtualization Support Inside Ubuntu

This is the verification that nested virtualization is actually working. In the Ubuntu terminal:

```bash
grep -cE 'vmx' /proc/cpuinfo
```

✅ **Expected:** A number greater than 0 (typically matches your vCPU count — 8 or 16).

If this returns `0`, nested virtualization is not exposed. Go back to Phase 2 and verify:
- The "Virtualize Intel VT-x/EPT" checkbox is checked in VM settings
- The `.vmx` file edits are saved
- `vmware.log` shows `Monitor Mode: CPL0`

> **Note for AMD systems:** Replace `vmx` with `svm` in the above command. AMD uses different CPU flags.

Next, install and run `kvm-ok`:

```bash
sudo apt install -y cpu-checker
kvm-ok
```

✅ **Expected output:**
```
INFO: /dev/kvm exists
KVM acceleration can be used
```

❌ **Problem output:**
```
KVM acceleration can NOT be used
```

If KVM cannot be used, the most common cause is that virtualization is not exposed correctly through VMware. Return to Phase 2, Step 3.

---

## Phase 4: Custom QEMU/KVM with Anti-Detection Patches

**Goal:** Compile and install a custom version of QEMU and KVM that replaces default virtual hardware identifiers with realistic ones, defeating sandbox-aware malware.

### Why This Matters

Stock QEMU stamps ACPI tables with strings like `BOCHS` and `BXPC`. Sandbox-aware malware reads these strings to detect that it's running in a VM and refuses to execute its payload. CAPEv2 ships a script that patches QEMU source code to replace these strings with realistic hardware identifiers before compiling from source.

### Step 1: Clone the CAPEv2 Repository

In the Ubuntu terminal:

```bash
cd ~
git clone https://github.com/kevoreilly/CAPEv2.git
cd CAPEv2/installer
```

This downloads the CAPEv2 source code (about 240 MB) to your home directory.

### Step 2: Install ACPI Tools and Extract an Identifier

The script needs a 4-character hardware identifier (called `<WOOT>` in the script). You need to pick one. For a lab, any 4 characters work. But the script teaches you how to find a real one — do this for learning even if you'll end up using a placeholder:

```bash
sudo apt install -y acpica-tools
sudo acpidump > acpidump.out
sudo acpixtract -a acpidump.out
sudo iasl -d dsdt.dat
sudo dmesg | grep DSDT
```

Your output will look something like:
```
[    0.010657] ACPI: DSDT 0x00000000BFEDD001 021E72 (v01 PTLTD  Custom   06040000 MSFT 03000001)
```

The OEM ID here is `PTLTD` — but this is VMware's virtual ACPI identifier, not real hardware (because the Ubuntu system you're running is itself a VMware guest). For a lab, this doesn't matter.

### Step 3: Replace the Placeholder

For a lab environment, use a realistic placeholder like `CBX3` (a known Dell Inspiron identifier):

```bash
sed -i 's/<WOOT>/CBX3/g' kvm-qemu.sh
```

This command replaces every occurrence of `<WOOT>` in the script with `CBX3`. You will not see output — no output means success.

> **For production use**, pull a real hardware identifier from the [linuxhw/ACPI](https://github.com/linuxhw/ACPI) GitHub repository. Common values: `CBX3` (Dell), `82BF` (HP), `PNP0` (generic).

### Step 4: Install and Enter tmux

`tmux` is a terminal multiplexer that keeps processes running even if your SSH connection drops or terminal window closes. The script takes 20–60 minutes, so tmux is essential.

```bash
sudo apt install -y tmux
tmux new -s cape-install
```

You are now inside a tmux session. If you ever get disconnected, you can rejoin with:
```bash
tmux attach -t cape-install
```

To detach from tmux without killing the process: press `Ctrl+B`, release, then press `D`.

### Step 5: Run the Installer Script

Inside your tmux session:

```bash
sudo chmod a+x kvm-qemu.sh
sudo ./kvm-qemu.sh all cape 2>&1 | tee kvm-qemu.log
```

Replace `cape` with your Ubuntu username if different.

**What `all cape` does:**
- `all` — install everything (QEMU, SeaBIOS, libvirt, virt-manager, network configuration)
- `cape` — username under which libvirt permissions will be granted

**Expected duration:** 20–60 minutes. The script will:
1. Install apt build dependencies
2. Download QEMU source code
3. Apply anti-detection patches
4. Compile QEMU (the longest phase — you'll see lots of `CC` compilation lines)
5. Compile SeaBIOS
6. Install libvirt and virt-manager
7. Configure iptables as the firewall backend

If you see `sed: can't read /etc/needrestart/needrestart.conf: No such file or directory` — **this is harmless** and the script continues normally.

Do NOT interrupt the script with Ctrl+C. If you need to step away, use the tmux detach (`Ctrl+B` then `D`) and reattach later.

### Step 6: Reboot

When the script finishes (you'll see the prompt return), save the log file for troubleshooting reference, then reboot:

```bash
sudo reboot
```

### Step 7: Verify KVM Functionality

After reboot, open a terminal and run these verification checks in order:

```bash
# Check KVM modules are loaded (Intel system — use kvm_amd for AMD)
lsmod | grep kvm
```

✅ **Expected:**
```
kvm_intel      569344  0
kvm           1445888  1 kvm_intel
irqbypass       16384  1 kvm
```

```bash
# Verify nested virtualization is enabled
cat /sys/module/kvm_intel/parameters/nested
```

✅ **Expected:** `Y` or `1`

If not, enable it:
```bash
echo "options kvm_intel nested=1" | sudo tee /etc/modprobe.d/kvm-intel.conf
sudo modprobe -r kvm_intel && sudo modprobe kvm_intel
```

```bash
# Check libvirt's default network exists and is running
sudo virsh net-list --all
```

✅ **Expected:** A `default` network shown as `active` and `autostart yes`.

If it's inactive:
```bash
sudo virsh net-start default
sudo virsh net-autostart default
```

```bash
# Verify virbr0 bridge is up
ip addr show virbr0
```

✅ **Expected:** An interface with IP `192.168.122.1/24`. This is the bridge your analysis VM will connect to.

```bash
# Launch virt-manager to verify the GUI works
virt-manager
```

✅ **Expected:** The Virtual Machine Manager window opens and shows "QEMU/KVM" as a connection. If it opens without errors, close it for now.

---

## Phase 5: CAPEv2 Installation

**Goal:** Install CAPEv2 itself along with PostgreSQL, MongoDB, Python dependencies, and community malware detection rules.

### Step 1: Configure Installation Variables

```bash
cd ~/CAPEv2/installer
nano cape2.sh
```

`nano` is a simple text editor. Use arrow keys to navigate. `Ctrl+W` searches, `Ctrl+X` exits (it will prompt to save — press `Y` then Enter).

Find these variables near the top of the file and verify/change them:

```bash
NETWORK_IFACE=virbr0                # KVM's default bridge interface
IFACE_IP="192.168.122.1"            # virbr0's default gateway IP
PASSWD="ChangeThisPassword123!"     # PostgreSQL password for CAPE database
```

**Choose a strong password** and remember it — you will need it for the CAPEv2 configuration in Phase 8.

Save and exit (`Ctrl+X`, `Y`, Enter).

### Step 2: Run cape2.sh

Start a tmux session (this installation also takes 15–30 minutes):

```bash
tmux new -s cape2
sudo chmod a+x cape2.sh
sudo ./cape2.sh base 2>&1 | tee cape2-base.log
```

The `base` argument runs three sub-commands in sequence: `dependencies`, `sandbox`, and `systemd`. Together these install:
- PostgreSQL database
- MongoDB database (for storing analysis reports)
- YARA from source (malware detection engine)
- Poetry (Python dependency manager)
- CAPEv2 code at `/opt/CAPEv2/`
- The `cape` system user
- systemd service files for `cape`, `cape-processor`, `cape-rooter`, and `cape-web`

### Step 3: Reboot

```bash
sudo reboot
```

### Step 4: Verify Services Exist

After reboot, check that all four CAPEv2 services were created:

```bash
sudo systemctl status cape cape-processor cape-rooter cape-web
```

Each service should be listed (it's fine if they show errors or aren't running — we haven't configured them yet). Press `q` to exit each status view.

### Step 5: Fix PostgreSQL Database Ownership (Critical)

**This step is absent from the official CAPEv2 documentation but is required.** Without it, CAPE cannot write to its database, and you will get cryptic permission errors later.

```bash
sudo -u postgres psql
```

You are now in the PostgreSQL shell. Run:

```sql
ALTER DATABASE cape OWNER TO cape;
\q
```

Verify:

```bash
sudo -u postgres psql -c "\l" | grep cape
```

✅ **Expected output:** `cape | cape | UTF8 | ...` — the owner (second field) must be `cape`.

### Step 6: Install Python Dependencies via Poetry

CAPEv2 uses Poetry to manage its Python dependencies. Poetry gets installed at `/etc/poetry/venv/bin/poetry`. It is not in root's PATH, so we use the full path.

```bash
cd /opt/CAPEv2
sudo -u cape /etc/poetry/venv/bin/poetry install
```

This takes several minutes. It resolves and downloads all CAPEv2 Python dependencies into an isolated virtual environment.

Then install optional/extra dependencies:

```bash
sudo -u cape /etc/poetry/venv/bin/poetry run pip install -r extra/optional_dependencies.txt
sudo -u cape /etc/poetry/venv/bin/poetry run pip install -U git+https://github.com/DissectMalware/batch_deobfuscator
sudo -u cape /etc/poetry/venv/bin/poetry run pip install -U git+https://github.com/CAPESandbox/httpreplay
```

> **Note on peepdf:** Older guides reference installing `peepdf` for PDF malware analysis. Both the CAPESandbox fork and the original jesparza repository have either been removed or lack proper Python packaging. **Skip peepdf** — your sandbox will work fine without it for EXE, DLL, Office macro, and other common malware types.

Verify libvirt Python bindings:

```bash
sudo -u cape /etc/poetry/venv/bin/poetry run pip install libvirt-python
```

If it says "Requirement already satisfied," you're good.

### Step 7: Install Community Signatures and YARA Rules

```bash
cd /opt/CAPEv2
sudo -u cape /etc/poetry/venv/bin/poetry run python utils/community.py -waf
```

This downloads and installs:
- YARA rules for malware family detection
- CAPA rules for capability detection
- Community-contributed signatures

You will see hundreds of "Fix permission on:" lines — **these are not errors**. The script is setting correct file ownership on every downloaded file.

### Troubleshooting: Finding Poetry

If `sudo -u cape /etc/poetry/venv/bin/poetry install` fails with "command not found":

```bash
find / -name "poetry" -type f 2>/dev/null
```

This searches the entire filesystem for the poetry binary. Use whichever path it returns. On a standard CAPEv2 install it will be `/etc/poetry/venv/bin/poetry`.

---

## Phase 6: Windows 10 Guest VM in KVM

**Goal:** Create the actual Windows 10 VM inside Ubuntu's KVM hypervisor. This is the VM where malware will execute.

### Step 1: Download Prerequisites

Inside the Ubuntu VM, open a terminal. Download the VirtIO drivers ISO:

```bash
cd ~/Downloads
wget https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
```

You also need a Windows 10 ISO. Options:
1. Download a Windows 10 Enterprise evaluation ISO from Microsoft's Evaluation Center (https://www.microsoft.com/evalcenter)
2. Use the Media Creation Tool on a Windows machine, then transfer the ISO to Ubuntu

Once you have both ISOs, copy them to libvirt's image directory:

```bash
sudo cp ~/Downloads/Win10*.iso /var/lib/libvirt/images/
sudo cp ~/Downloads/virtio-win.iso /var/lib/libvirt/images/
```

### Step 2: Launch virt-manager with sudo

**This is critical.** virt-manager must be launched with `sudo` so that the VM is created under `qemu:///system`, which is what CAPEv2 expects. Launching without sudo creates VMs under `qemu:///session` where CAPE cannot see them.

```bash
sudo virt-manager
```

### Step 3: Create the VM

1. Click **Create a new virtual machine** (the monitor-with-a-spark icon, top-left)
2. Step 1: **Local install media (ISO image or CDROM)** → Forward
3. Step 2: Click **Browse → Browse Local** and navigate to `/var/lib/libvirt/images/` to select your Windows 10 ISO. **Uncheck** "Automatically detect from the installation media" and manually type **Microsoft Windows 10** → Forward
4. Step 3: Memory: **4096 MB**, CPUs: **2** → Forward
5. Step 4: **Create a disk image for the virtual machine**, size: **65 GB** → Forward
6. Step 5: Name: **win10** (this name matters — you'll reference it in the CAPEv2 config). **Check "Customize configuration before install"** → Finish

### Step 4: Customize VM Hardware Before Installation

The customization window opens with the VM not yet started:

**Overview:**
- **Firmware:** Select **BIOS** (not UEFI — broader malware compatibility)
- **Chipset:** **i440FX** (default is fine)

**CPUs:**
- Current allocation: **2**
- Under **Configuration**, set CPU model to **host-passthrough** (passes through all real CPU features)

**Memory:**
- Current allocation: **4096 MiB**

**SATA Disk 1:**
- Click on the disk in the left panel
- **Disk bus:** Change to **SATA** (if not already)
- Keep format as qcow2

> **Note on SATA vs VirtIO for disk:** SATA was used instead of VirtIO because it avoids needing to manually load VirtIO storage drivers during Windows installation (which can freeze in nested virtualization). Performance difference in a lab is minimal.

**NIC:**
- Click on the NIC in the left panel
- **Click Remove at the bottom** — this removes the network adapter entirely during install

> **Why remove the NIC?** Without a network adapter, Windows cannot download updates or contact Microsoft during OOBE, and it will offer a "continue with limited setup" option to create a local account. This keeps your baseline VM pristine.

**Display:**
- Click on Display Spice → set **Type: QXL** (if not already)

**(Optional) Remove the VirtIO CDROM:**
- Since we're using SATA disk and e1000e NIC, the VirtIO drivers ISO is not needed during install. You can skip adding it.

Click **Begin Installation** (top-left).

### Step 5: Install Windows 10

1. The Windows 10 installer boots. Select language/keyboard → Next → Install Now
2. Enter product key — you can click **"I don't have a product key"** to install as evaluation
3. Select **Windows 10 Pro** or **Enterprise** → Next
4. Accept license → Next
5. Installation type: **Custom: Install Windows only (advanced)**
6. Select the unallocated drive → Next
7. Wait for installation (15–30 minutes in nested virtualization)

During OOBE (Out of Box Experience):
1. Region: **United States** → Yes
2. Keyboard: **US** → Yes → Skip
3. "Let's connect you to a network" — **click "I don't have Internet"** (bottom-left link)
4. Then **"Continue with limited setup"**
5. Account name: **cape** → Next
6. Password: leave empty or set a simple one → Next
7. Privacy settings: **turn all of them OFF** → Accept
8. Wait for Windows to finish setup (can take 10–15 minutes with periodic reboots)

### Step 6: Add the Network Adapter

Once Windows is at the desktop, shut it down cleanly (Start → Power → Shut Down).

Back in virt-manager:
1. Select your VM, click **Show virtual hardware details** (lightbulb icon)
2. Click **Add Hardware** (bottom-left)
3. Select **Network**:
   - **Network source:** `Virtual network 'default' : NAT`
   - **Device model:** **e1000e**
4. Click **Finish**

> **Note on e1000e vs VirtIO NIC:** The e1000e network adapter was chosen over VirtIO NIC because Windows has a built-in driver for it. This eliminates the need to install the `virtio-win-gt-x64.msi` package, which was problematic to install in nested virtualization (the installer can freeze for extended periods while loading 10+ kernel drivers).

### Step 7: Verify Networking

Power on the VM again. Once at desktop, open **PowerShell** (search in Start menu) and run:

```powershell
ipconfig
```

✅ **Expected output:**
- IPv4 Address in `192.168.122.x` range
- Subnet Mask: `255.255.255.0`
- Default Gateway: `192.168.122.1`

Then test connectivity to the host:
```powershell
ping 192.168.122.1
```

✅ **Expected:** 4 successful replies, 0% loss.

---

## Phase 7: Hardening Windows 10 for Malware Analysis

**Goal:** Turn off every Windows security feature that would interfere with malware execution, populate the system with realistic software to defeat sandbox-detection checks, deploy the CAPEv2 agent, and set a static IP.

This is a long phase. Do it in order:
- **Part 1:** Disable all security features (first, so they don't interfere with software installation)
- **Part 2:** Install realism software and create user activity
- **Part 3:** Install Python and the CAPE agent
- **Part 4:** Set a static IP
- **Part 5:** Take the clean snapshot

### Part 1: System Hardening

#### 1.1 Disable Windows Defender

**Via Windows Security app:**
1. Start → type "Windows Security" → open
2. Click **Virus & threat protection**
3. Under "Virus & threat protection settings" → **Manage settings**
4. Turn **OFF**:
   - Real-time protection
   - Cloud-delivered protection
   - Automatic sample submission
   - **Tamper Protection** (critical — without this off, the other toggles will re-enable themselves)

**Via Group Policy:**
1. Press `Win+R`, type `gpedit.msc`, hit Enter
2. Navigate to: **Computer Configuration → Administrative Templates → Windows Components → Microsoft Defender Antivirus**
3. Double-click **"Turn off Microsoft Defender Antivirus"**
4. Select **Enabled** → Apply → OK

**Via Registry (PowerShell as Administrator):**

Right-click Start → **Windows PowerShell (Admin)** (or Terminal (Admin)) → then run:

```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```

#### 1.2 Disable Windows Update

**Stop and disable the service:**
1. Press `Win+R`, type `services.msc`, hit Enter
2. Find **Windows Update** in the list
3. Right-click → **Stop**
4. Right-click → **Properties** → **Startup type: Disabled** → OK

**Disable scheduled tasks:**
1. Press `Win+R`, type `taskschd.msc`, hit Enter
2. Navigate to: **Task Scheduler Library → Microsoft → Windows → WindowsUpdate**
3. Right-click each task → **Disable**

**Via Group Policy:**
1. `gpedit.msc` → **Computer Configuration → Administrative Templates → Windows Components → Windows Update**
2. Double-click **Configure Automatic Updates** → **Disabled** → OK

#### 1.3 Disable UAC (User Account Control)

1. Open **Control Panel** → **User Accounts** → **Change User Account Control settings**
2. Drag the slider all the way down to **"Never notify"**
3. Click OK, accept the prompt

**Via Registry (PowerShell admin):**

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
```

#### 1.4 Disable Windows Firewall

In PowerShell as Administrator:

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

#### 1.5 Set PowerShell Execution Policy to Unrestricted

```powershell
Set-ExecutionPolicy Unrestricted -Force
```

(This allows malware scripts to execute without policy restrictions, which is exactly what you want in a sandbox.)

#### 1.6 Disable Teredo Tunneling

In Command Prompt as Administrator:

```cmd
netsh interface teredo set state disabled
```

#### 1.7 Additional Group Policy Settings

In `gpedit.msc`:
- **Computer Configuration → Administrative Templates → Network → DNS Client → Turn off Multicast Name Resolution** → **Enabled**
- **Computer Configuration → Administrative Templates → System → Internet Communication Management → Restrict Internet Communication** → **Enabled**

#### 1.8 Reboot

Reboot the Windows VM cleanly. After reboot, verify:
- Windows Security should show Defender as off
- Windows Update in Settings should show errors or be unreachable

### Part 2: Realism Software and User Activity

**Why this matters:** Sandbox-aware malware checks for signs that the system is a "real" user's machine. Empty user folders, no browser history, no installed software, and default wallpaper all signal "sandbox" and cause malware to exit before executing its payload.

#### 2.1 Install Browsers

- **Firefox:** https://www.mozilla.org/firefox/
- **Chrome:** https://www.google.com/chrome/
- Edge is already installed

After installing Firefox:
- Open Menu → Settings → search "update" → **"Check for updates but let you choose to install them"**

#### 2.2 Install Microsoft Office 2016 (32-bit)

**Important:** Use the 32-bit version, not Office 365. 32-bit Office is what most malicious macros target.

After installing:
1. Open Word → **File → Options → Trust Center → Trust Center Settings → Macro Settings**
2. Select **"Enable all macros"**
3. Check **"Trust access to the VBA project object model"**
4. Click OK
5. Repeat for Excel and PowerPoint
6. Disable Office updates: **File → Account → Update Options → Disable Updates**

#### 2.3 Install Adobe Acrobat Reader

Use an older version (Reader XI or DC) — newer versions are heavily sandboxed.

After installing:
- **Edit → Preferences → Security (Enhanced)** → **Uncheck "Enable Protected Mode at startup"**
- **Edit → Preferences → Updater** → **"Do not download or install updates automatically"**

#### 2.4 Install Java Runtime Environment

Download an older JRE (e.g., JRE 8) from oracle.com or adoptium.net.

After installing:
- Open Java Control Panel → **Update** tab → uncheck "Check for Updates Automatically"
- **Security** tab → set security level to **Medium**

#### 2.5 Install Utility Software

Pick a realistic mix from these (more = better, but don't overdo it):

- **7-Zip** — https://www.7-zip.org/
- **VLC** — https://www.videolan.org/
- **WinRAR** — https://www.win-rar.com/
- **PuTTY** — https://www.putty.org/
- **FileZilla** — https://filezilla-project.org/
- **Notepad++** — https://notepad-plus-plus.org/
- **Telegram Desktop** or **Discord** — optional
- **Windows Terminal** — from Microsoft Store

Decline auto-update offers during install where possible.

#### 2.6 Generate Dummy User Activity

Create files to populate user folders. The specific content does not matter — you just need files to exist:

- **Documents:** Create 5–10 files like `Resume.docx`, `Budget_2024.xlsx`, `Project_Notes.pptx`, `To_Do.txt`. Open each, type some realistic content, save.
- **Downloads:** Drop in some `.txt`, `.pdf`, `.zip` files (any benign files)
- **Desktop:** Leave 2–3 shortcuts and maybe a file or two visible
- **Pictures:** Add 5–10 random `.jpg` files (any photos)

Browse the web for 15–30 minutes in each installed browser. Visit:
- google.com
- youtube.com
- news sites (cnn.com, bbc.com)
- wikipedia.org
- reddit.com

Bookmark a few pages. This populates browser history, cookies, and autocomplete data.

#### 2.7 Set a Custom Wallpaper

Right-click desktop → **Personalize** → set any non-default wallpaper (a photo from Pictures works).

#### 2.8 Clean Up Auto-Updaters with Autoruns

Download Sysinternals Autoruns: https://learn.microsoft.com/sysinternals/downloads/autoruns

Run Autoruns as Administrator. In the **Logon** and **Scheduled Tasks** tabs, **uncheck** (don't delete) entries related to:
- Google Update (`GoogleUpdate.exe`)
- Java Update Scheduler
- Adobe Acrobat Update Service
- Microsoft Office ClickToRun updates
- Any "Updater" or "Update" services from installed software

This prevents the VM from slowly accumulating state changes as background updaters run.

#### 2.9 Reboot

Reboot the Windows VM cleanly after all this.

### Part 3: Python and the CAPEv2 Agent

#### 3.1 Install Python 3 (32-bit)

**Critical: 32-bit, not 64-bit.** CAPEv2's agent requires 32-bit Python for compatibility with its monitoring hooks.

1. In the Windows VM, open Edge and go to https://www.python.org/downloads/windows/
2. Download the **Windows installer (32-bit)** for Python 3.10 or 3.11 (not 3.12+)
3. Run the installer:
   - **Check "Add python.exe to PATH"** at the bottom
   - Click **"Customize installation"**
   - On the first Optional Features screen, leave all defaults → Next
   - On Advanced Options:
     - Check **"Install for all users"**
     - Check **"Add Python to environment variables"**
     - Check **"Precompile standard library"**
   - Click **Install**
   - On the final screen, click **"Disable path length limit"** if shown
   - Close the installer

#### 3.2 Install Pillow

Pillow is required for screenshot capture. In **Command Prompt as Administrator**:

```cmd
python -m pip install --upgrade pip
python -m pip install --upgrade Pillow
```

Verify Python:
```cmd
python --version
```
Should show `Python 3.10.x` or `Python 3.11.x`.

#### 3.3 Download the CAPEv2 Agent

In the Windows VM, open a browser and download:
```
https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/agent/agent.py
```

Save it anywhere for now (Downloads is fine).

#### 3.4 Rename and Move the Agent

**The `.pyw` extension is mandatory** — it tells Windows to run the script with `pythonw.exe` (no console window), which is required for CAPEv2's human interaction simulation to work correctly.

1. Rename `agent.py` → `update_service.pyw`
2. Move it to `C:\Users\cape\Desktop\update_service.pyw`

#### 3.5 Configure the Agent to Auto-Start

1. Press `Win+R`, type `shell:common startup`, hit Enter
2. This opens `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
3. Right-click in the folder → **New → Shortcut**
4. Browse to `C:\Users\cape\Desktop\update_service.pyw` → Next
5. Name the shortcut something innocuous like **UpdateService** → Finish

> **Why the All Users Startup folder** (not the per-user one)? This ensures the agent runs with admin context and starts before user-specific shell initialization completes.

### Part 4: Static IP Configuration

CAPEv2 needs a predictable IP to find the agent. DHCP would assign a different IP every boot.

1. Right-click the Start menu → **Network Connections** (or: Settings → Network & Internet → Change adapter options)
2. Right-click **Ethernet** → **Properties**
3. Select **Internet Protocol Version 4 (TCP/IPv4)** → **Properties**
4. Select **Use the following IP address:**
   - IP address: `192.168.122.101`
   - Subnet mask: `255.255.255.0`
   - Default gateway: `192.168.122.1`
5. Select **Use the following DNS server addresses:**
   - Preferred DNS server: `192.168.122.1`
6. Click **OK** → **OK**

### Part 5: Verify and Snapshot

#### 5.1 Reboot and Verify the Agent

Reboot the VM cleanly. After log-in, wait 1–2 minutes for the agent to start.

From the **Ubuntu host terminal**:

```bash
curl http://192.168.122.101:8000
```

✅ **Expected:** A response (JSON status or plain text from the agent). Getting any response means it's running and reachable.

If it hangs or refuses connection:
- In Windows Task Manager, check the Details tab for `pythonw.exe` — that's the agent
- If missing, right-click the shortcut in the startup folder → Run
- Check Windows Firewall is off: `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`

#### 5.2 Pre-Snapshot Checklist

Before snapshotting, confirm **all** of these:
- ✅ Windows fully booted and logged in as `cape`
- ✅ CAPEv2 agent running (verified with curl)
- ✅ Static IP is `192.168.122.101`
- ✅ All security features disabled (Defender, Updates, UAC, Firewall)
- ✅ No open applications, no pending Windows update notifications
- ✅ Realism software installed, dummy files present

#### 5.3 Take the Snapshot

From the **Ubuntu host terminal**, with the VM still running:

```bash
sudo virsh snapshot-create-as --domain "win10" --name "clean_snapshot"
```

This takes 30 seconds to a few minutes depending on RAM.

> **Note on `sudo` for virsh:** `sudo` is required because the VM was created under `qemu:///system`. CAPEv2 itself does not need sudo — the `cape` user has appropriate libvirt group permissions. Only manual CLI access from other users needs sudo.

Verify:

```bash
sudo virsh snapshot-list "win10"
```

✅ **Expected:** `clean_snapshot` listed with a creation timestamp.

You can now shut down the Windows VM — CAPEv2 will automatically revert to this snapshot before each analysis:

```bash
sudo virsh shutdown "win10"
```

---

## Phase 8: CAPEv2 Configuration

**Goal:** Wire CAPEv2 to your KVM machinery, your database, and your network layout via its configuration files.

All config files are in `/opt/CAPEv2/conf/`. We'll edit four of them.

### Step 1: Edit cuckoo.conf

```bash
sudo -u cape nano /opt/CAPEv2/conf/cuckoo.conf
```

Find and verify/change these values (most will already exist — just update them as needed):

```ini
[cuckoo]
machinery = kvm
max_analysis_count = 0
max_machines_count = 10
max_vmstartup_count = 5
machinery_screenshots = on

[resultserver]
ip = 192.168.122.1
port = 2042

[database]
connection = postgresql://cape:ChangeThisPassword123!@localhost:5432/cape

[timeouts]
default = 200
critical = 60
vm_state = 300
```

**Important:**
- Replace `ChangeThisPassword123!` with the actual password you set in `cape2.sh` (Phase 5)
- `resultserver.ip` must be `192.168.122.1` — this is the virbr0 gateway the Windows guest can reach
- `machinery = kvm` tells CAPE to use the KVM machinery module

Save with `Ctrl+X`, `Y`, Enter.

### Step 2: Edit kvm.conf

```bash
sudo -u cape nano /opt/CAPEv2/conf/kvm.conf
```

Configure it like this:

```ini
[kvm]
dsn = qemu:///system
machines = win10
interface = virbr0

[win10]
label = win10
platform = windows
ip = 192.168.122.101
snapshot = clean_snapshot
interface = virbr0
resultserver_ip = 192.168.122.1
resultserver_port = 2042
arch = x64
tags =
```

**Critical:** `label`, `snapshot`, and `ip` must match **exactly** (case-sensitive, no typos):
- `label = win10` must match the VM name from `sudo virsh list --all`
- `snapshot = clean_snapshot` must match what `sudo virsh snapshot-list "win10"` shows
- `ip = 192.168.122.101` must match the static IP you set in Windows

Save.

### Step 3: Edit routing.conf

```bash
sudo -u cape nano /opt/CAPEv2/conf/routing.conf
```

Set the `[routing]` section:

```ini
[routing]
route = none
internet = ens33
nat = yes
drop = no
```

> **Why `route = none`?** This means analysis guests have no network access by default — the safest option. Malware cannot exfiltrate data or contact real C2 servers. You can override routing per-submission from the web UI if you need to observe C2 behavior.

Save.

### Step 4: Edit reporting.conf

```bash
sudo -u cape nano /opt/CAPEv2/conf/reporting.conf
```

Find the `[mongodb]` section and verify:

```ini
[mongodb]
enabled = yes
host = 127.0.0.1
port = 27017
db = cuckoo
store_memdump = yes
```

If `enabled = no`, change it to `yes` (the web interface requires MongoDB).

Save.

### Step 5: Verify auxiliary.conf Modules

```bash
sudo -u cape nano /opt/CAPEv2/conf/auxiliary.conf
```

Verify these key modules have `enabled = yes`:
- `[sniffer] enabled = yes` with `interface = virbr0`
- `disguise = yes` (in `[auxiliary_modules]`)
- `human_windows = yes`
- `screenshots_windows = yes`
- `tlsdump = yes`
- `filecollector = yes`

These modules simulate user interaction, capture screenshots, and collect dropped files.

### Step 6: Verify processing.conf Modules

```bash
sudo -u cape nano /opt/CAPEv2/conf/processing.conf
```

Verify these are `enabled = yes`:
- `[analysisinfo]`
- `[behavior]`
- `[network]`
- `[CAPE]`
- `[strings]`

Additionally, enable these for richer reports (they default to `no`):
- `[decompression] enabled = yes` — handles packed/compressed malware
- `[dumptls] enabled = yes` — captures TLS keys for decrypting C2 traffic

Save.

---

## Phase 9: Starting Services and First Analysis

### Step 1: Start All CAPEv2 Services

```bash
sudo systemctl start cape-rooter
sudo systemctl start cape
sudo systemctl start cape-processor
sudo systemctl start cape-web
```

Enable them to start automatically on boot:

```bash
sudo systemctl enable cape-rooter cape cape-processor cape-web
```

### Step 2: Verify Services are Running

```bash
sudo systemctl status cape cape-processor cape-rooter cape-web
```

✅ **Expected:** All four should show `active (running)` in green. Press `q` to exit each status screen.

If any service fails, check its log:

```bash
sudo journalctl -u cape.service -n 50
sudo journalctl -u cape-processor.service -n 50
sudo journalctl -u cape-rooter.service -n 50
sudo journalctl -u cape-web.service -n 50
```

Also check the main CAPE log:

```bash
tail -f /opt/CAPEv2/log/cuckoo.log
```

Press `Ctrl+C` to exit. You should see CAPE initializing its machinery and recognizing your `win10` VM.

### Step 3: Access the Web Interface

Open Firefox (or any browser) inside Ubuntu and go to:

```
http://localhost:8000
```

✅ **Expected:** The CAPE Sandbox web UI loads.

❌ **If it doesn't load:** Run database migrations:

```bash
cd /opt/CAPEv2/web
sudo -u cape /etc/poetry/venv/bin/poetry run python3 manage.py migrate
sudo systemctl restart cape-web
```

Then retry.

### Step 4: Submit a Test Sample

For testing, use **EICAR** (an industry-standard test file that AV products recognize as malware but is completely benign):

```bash
cd /tmp
wget https://secure.eicar.org/eicar.com
```

Or use any harmless file (even `notepad.exe` from Windows works for testing the pipeline).

**Submit via the web UI:**
1. Go to `http://localhost:8000`
2. Click **Submit** at the top
3. Upload `/tmp/eicar.com`
4. Leave default options → **Analyze**

**Or submit via CLI:**

```bash
cd /opt/CAPEv2
sudo -u cape /etc/poetry/venv/bin/poetry run python utils/submit.py /tmp/eicar.com
```

### Step 5: Watch It Work

In one terminal:
```bash
tail -f /opt/CAPEv2/log/cuckoo.log
```

In another, open virt-manager to watch the VM:
```bash
sudo virt-manager
```

You'll see CAPE:
1. Pick up the task
2. Revert the `win10` VM to `clean_snapshot`
3. Boot the VM (you'll see it start in virt-manager)
4. Communicate with the agent on `192.168.122.101:8000`
5. Upload and execute the sample
6. Monitor behavior for the configured timeout (~3 minutes default)
7. Shut down the VM
8. Process results (takes another ~1 minute)

### Step 6: View the Report

Go back to `http://localhost:8000`, click on your submitted task. Explore the tabs:
- **Overview** — high-level summary, signatures matched
- **Static Analysis** — PE headers, imports, strings, YARA hits
- **Behavior** — process tree, API call log
- **Network** — DNS queries, HTTP requests, pcap
- **Screenshots** — what the VM looked like during execution
- **Dropped Files** — anything the sample wrote to disk
- **Memory Dumps** — process memory snapshots

**A visible report means the entire pipeline works end-to-end.** Congratulations!

---

## Final Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Windows 11 Pro Host (HP Elite Mini 800 G9)                  │
│ ├─ Hyper-V/VBS disabled                                     │
│ └─ VMware Workstation (CPL0 monitor mode)                   │
│    │                                                        │
│    └─ Ubuntu 24.04 VM (32 GB RAM, 8 vCPUs)                  │
│       ├─ Custom QEMU/KVM with anti-detection patches        │
│       ├─ CAPEv2 services (cape, processor, rooter, web)     │
│       ├─ PostgreSQL + MongoDB                               │
│       ├─ libvirt network: virbr0 (192.168.122.1/24)         │
│       └─ Windows 10 Analysis Guest (KVM)                    │
│          ├─ 4 GB RAM, 2 vCPUs                               │
│          ├─ SATA disk, e1000e NIC (192.168.122.101)         │
│          ├─ Hardened (Defender/Updates/UAC/Firewall off)    │
│          ├─ Realistic software + dummy user files           │
│          ├─ Python 3.11 (32-bit) + CAPE agent               │
│          └─ Snapshot: clean_snapshot                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Recommendations for Future Work

### Operational Security

1. **Keep the sandbox isolated.** The `route = none` default is the safest. If enabling `route = internet` for C2 observation, consider routing through Tor, a VPN, or a dedicated ISP line separate from your home/work network.

2. **Back up the Ubuntu VM now.** Take a VMware-level snapshot of the working Ubuntu VM so you can roll back if future changes break the environment. Before taking the snapshot: stop CAPE services and shut down the Windows KVM guest for a cleaner capture.

3. **Treat the sandbox as compromised.** Never copy files out of the analysis VM to your host. Use the web interface to download reports only.

### Improving Analysis Quality

4. **Expand to parallel analysis VMs.** The current single-guest setup processes samples serially — one at a time. CAPEv2 supports running multiple analysis VMs concurrently, which dramatically improves throughput for batch analysis or research workloads. A few paths to scale:

   **Clone the existing win10 VM.** Use `virt-clone` to create identical copies:
   ```bash
   sudo virt-clone --original win10 --name win10-2 --auto-clone
   sudo virt-clone --original win10 --name win10-3 --auto-clone
   ```
   Each clone needs its own static IP (e.g., `192.168.122.102`, `192.168.122.103`) set from inside Windows before snapshotting, and a fresh `clean_snapshot` on each.

   **Update kvm.conf** to register all machines:
   ```ini
   [kvm]
   machines = win10,win10-2,win10-3

   [win10-2]
   label = win10-2
   ip = 192.168.122.102
   snapshot = clean_snapshot
   # ... same structure as win10

   [win10-3]
   label = win10-3
   ip = 192.168.122.103
   snapshot = clean_snapshot
   ```
   CAPEv2 will automatically distribute submitted samples across available guests.

   **Diversify the guest pool for better coverage.** Rather than identical clones, consider building out different profiles:
   - Windows 7 SP1 with Office 2010 (still heavily targeted by older malware families)
   - Windows 10 with Office 2013 vs Office 2016
   - Guests with different locales (en-US, ru-RU, zh-CN) — some malware geofences based on locale
   - Guests with different installed software stacks (one with heavy developer tools, one with typical office user software)
   - x86 and x64 variants

   Use the `tags` field in `kvm.conf` to let analysts target specific profiles at submission time (e.g., `tags = office2016,x64`).

   **Resource planning for parallel VMs.** Each concurrent analysis VM needs 2 vCPUs and 2–4 GB RAM. On the current 8-vCPU / 32 GB Ubuntu allocation:
   - 2 concurrent guests: comfortable (4 vCPUs + 8 GB for guests, rest for Ubuntu/CAPE services)
   - 3 concurrent guests: tight but workable
   - 4+ concurrent guests: would require increasing the Ubuntu VM's VMware allocation, or reducing per-guest resources

   Monitor with `htop` and `free -h` on the Ubuntu host during parallel runs to spot contention. If the Ubuntu VM starts swapping, throughput will collapse — reduce concurrency before that point.

   **Adjust `max_machines_count` in cuckoo.conf** to match your guest count, and consider bumping `max_vmstartup_count` to control how many VMs boot simultaneously (staggered boots reduce the CPU spike).

5. **Enable InetSim.** Install InetSim on the Ubuntu host to simulate DNS, HTTP, HTTPS, SMTP, etc. Malware will get realistic-looking responses without real internet exposure. Update `routing.conf` to set `[inetsim] enabled = yes`.

6. **Install flare-capa.** This adds capability detection (MITRE ATT&CK mapping) to reports.

7. **Enable memory analysis.** Set `[memory] enabled = yes` in `processing.conf` and install Volatility3 for post-execution memory forensics.

8. **Consider your own VirusTotal API key.** Replace the shared community key in `processing.conf` for more reliable VT lookups.

### Performance Tuning

9. **Use qcow2 preallocation.** For new guest VMs:
   ```bash
   qemu-img create -f qcow2 -o preallocation=metadata win10.qcow2 100G
   ```

10. **Store all VM disks on NVMe.** Nested virtualization is I/O-sensitive. Avoid spinning disks entirely.

11. **Do not overcommit vCPUs.** Total vCPUs across all running VMs (including KVM guests) should not exceed the host's physical thread count.

### Anti-Detection Enhancements

12. **Edit the KVM guest's libvirt XML** to add SMBIOS spoofing (make it look like a real Dell/HP/ASUS), hide the KVM hypervisor flag, and disable the hypervisor CPUID leaf. Enable XML editing in virt-manager: **Edit → Preferences → Enable XML editing**. Sample additions:

   ```xml
   <features>
     <kvm>
       <hidden state='on'/>
     </kvm>
     <hyperv>
       <vendor_id state='on' value='GenuineIntel'/>
     </hyperv>
   </features>
   <cpu mode='host-passthrough'>
     <feature policy='disable' name='hypervisor'/>
   </cpu>
   ```

13. **Use real hardware ACPI identifiers.** The `CBX3` placeholder works for labs, but production anti-evasion benefits from pulling real DSDT identifiers from physical hardware (see the linuxhw/ACPI GitHub repo).

### Workflow Improvements

14. **Start with safe, well-documented samples.** Use MalwareBazaar (abuse.ch) for categorized, hash-indexed samples. Compare your reports against published analyses to validate the pipeline.

15. **Use the CAPE API.** For automated or bulk submissions:
    ```bash
    curl -F file=@/path/to/sample.exe http://localhost:8000/apiv2/tasks/create/file/
    ```

16. **Monitor the log continuously.** `tail -f /opt/CAPEv2/log/cuckoo.log` during analysis reveals issues that don't appear in the web UI.

### Maintenance

17. **Do not run `apt upgrade` casually.** The `kvm-qemu.sh` script installed custom QEMU and libvirt from source. A careless upgrade can replace them with stock packages, breaking anti-detection. The script's warnings (`NEVER install packages from apt-get that installed by this script`) should be respected.

18. **Update CAPEv2 periodically.** Pull the latest from the repository and rerun `community.py -waf` to refresh YARA rules and signatures. New malware families require updated detections.

---

## Troubleshooting Quick Reference

### KVM not loading / kvm-ok fails

- Confirm Hyper-V and VBS are disabled on the Windows host (systeminfo should show "Virtualization-based security: Not enabled")
- Confirm VMware's "Virtualize Intel VT-x/EPT" checkbox is checked
- Confirm `vhv.enable = "TRUE"` is in the .vmx file
- Check `vmware.log` for `Monitor Mode: CPL0`

### "Unable to bind result server on 192.168.122.1:2042"

virbr0 is not up. Run:
```bash
sudo virsh net-start default
ip addr show virbr0
```

### Tasks stuck in "pending"

Checklist:
1. `sudo systemctl status cape` — is it running?
2. `sudo virsh list --all` — is `win10` listed as "shut off"?
3. `sudo virsh snapshot-list "win10"` — does `clean_snapshot` exist?
4. `kvm.conf` — do `label`, `snapshot`, and `ip` exactly match reality?
5. PostgreSQL ownership: `sudo -u postgres psql -c "\l" | grep cape` shows owner as `cape`?

### Agent connection failures

From Ubuntu: `curl http://192.168.122.101:8000`

If it hangs:
- Is `pythonw.exe` running in the Windows VM's Task Manager?
- Is the Windows Firewall actually off?
- Is the static IP correctly `192.168.122.101`?
- Is the shortcut in the **All Users** startup folder (not per-user)?

### "failed_processing" status

Check `/opt/CAPEv2/log/process-<task_id>.log`. Common causes:
- Missing Python packages — install via `sudo -u cape /etc/poetry/venv/bin/poetry run pip install <package>`
- YARA regex errors — update rules: `sudo -u cape /etc/poetry/venv/bin/poetry run python utils/community.py -waf`
- Processing timeouts in nested environments — edit `/usr/lib/systemd/system/cape-processor.service` to increase the timeout, then `sudo systemctl daemon-reload && sudo systemctl restart cape-processor`

### `virsh list --all` shows empty

The VM is under `qemu:///system` and requires sudo:
```bash
sudo virsh list --all
```

Or, if you want to check both URIs:
```bash
virsh --connect qemu:///session list --all
virsh --connect qemu:///system list --all
```

If the VM is under `qemu:///session`, it was created without sudo — recreate with `sudo virt-manager`.

---

## Key Lessons Learned

- **The `.pyw` extension is mandatory** for the CAPE agent — it suppresses the console window that would otherwise interfere with the human interaction simulation module.
- **PostgreSQL database ownership** (`ALTER DATABASE cape OWNER TO cape`) is a critical step absent from official documentation. Without it, CAPE fails silently or with confusing permission errors.
- **Poetry's path is not in root's PATH** — use `/etc/poetry/venv/bin/poetry` explicitly for `sudo -u cape` commands.
- **SATA + e1000e** is a pragmatic alternative to VirtIO for lab environments, trading minor performance for eliminated driver complexity.
- **virt-manager under sudo** creates VMs under `qemu:///system`, which is what CAPEv2 requires — launching virt-manager without sudo puts VMs under `qemu:///session` where CAPE cannot see them.
- **Nested virtualization is patience-heavy.** First boots, Windows installation, and driver installation all take 5–10× longer than on bare metal. Assuming "frozen" when the system is just slow is the most common pitfall. Look at CPU and I/O activity before concluding anything is hung.
- **Core isolation / Memory Integrity** in Windows 11 24H2 can re-enable itself after reboot due to NVRAM locks. If VBS persists, temporarily disabling Secure Boot in UEFI is a reliable workaround.
- **CPU overcommit is catastrophic** in nested virtualization. If the outer VM has more vCPUs than the host has physical threads, running a nested VM causes severe slowdowns. Match or slightly under-provision.

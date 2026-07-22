# OPTIONAL: narrow passwordless-sudo proposal (Channel 3 build/deploy)

> **STATUS: PROPOSAL ONLY — NOT INSTALLED.** This file is for Kyler to review.
> Nothing here has been applied. Installing it is a security decision that only
> `capeadmin` can make, by hand, after review. I (the agent) cannot and did not.

## Why this exists

Standing up the Channel 3 build/deploy loop needs a few actions that belong to
`capeadmin`, not `relyk8` (me). Today those require an interactive `capeadmin`
sudo password each time. If you want to let me drive them unattended, a **tightly
scoped** `NOPASSWD` rule for *just those commands* is the clean way — far better
than broad sudo or "ignore permissions" (which wouldn't help anyway; see the
session discussion — the wall is OS-level identity, not a Claude prompt).

**If you'd rather not touch sudoers at all, that's fine** — just run the three
short steps yourself when you're back (they're in `BUILD_RECIPE.md`, tagged
`[USER]`). This proposal only exists to shrink that to near-zero.

## The capeadmin-only actions we hit

1. **Deploy the analyzer package** into CAPE (cape-owned dir):
   `cp exe_cmplog.py /opt/CAPEv2/analyzer/windows/modules/packages/`
2. **Reload CAPE's machine pool** after config/package changes (only if needed):
   `systemctl restart cape.service`
3. **(Maybe) modify the guest image** to save the dev snapshot, IF we go the
   `qemu-img` route rather than a libvirt (`virsh`) snapshot. TBD — a `virsh`
   internal snapshot may not need sudo at all (libvirt runs privileged). Confirm
   before adding any `qemu-img` rule.

## Candidate rule (review and TIGHTEN before use)

Drop-in file `/etc/sudoers.d/relyk8-clew-ch3`, mode `0440`, validated with
`visudo -cf`:

```sudoers
# Let relyk8 deploy exactly the cmplog analyzer package, and reload CAPE.
# Scope is deliberately narrow. Review every path before installing.
relyk8 ALL=(root) NOPASSWD: /usr/bin/install -m 0644 -o cape -g cape \
    /home/relyk8/clew/docs/cape_integration/exe_cmplog.py \
    /opt/CAPEv2/analyzer/windows/modules/packages/exe_cmplog.py
relyk8 ALL=(root) NOPASSWD: /usr/bin/systemctl restart cape.service
```

## Security caveats — READ before installing

- **Avoid wildcards.** A rule like `cp *` or `qemu-img snapshot *` is abusable
  (arbitrary source/dest, arbitrary image). The candidate above pins the *exact*
  source and destination paths and uses `install` (fixed mode/owner) instead of
  `cp` — so it can only ever place that one file. Keep it that specific.
- **No `qemu-img` rule proposed yet** — on purpose. Confirm whether a `virsh`
  snapshot works without sudo first; only add an image-write rule if truly needed,
  and pin it to the single `win10.qcow2` path and a fixed snapshot tag.
- **`relyk8` writing a file that CAPE later executes as an analyzer** is itself a
  minor trust escalation (I can change analyzer behavior without capeadmin). You
  may prefer to keep package deploys manual and only automate the harmless
  `systemctl restart`. Your call.
- Everything here is reversible: `sudo rm /etc/sudoers.d/relyk8-clew-ch3`.

## My recommendation

Keep it minimal: if anything, allow only the `systemctl restart cape.service`
line (low risk), and keep the one-time package deploy a manual `[USER]` step.
The build loop after that is already fully agent-drivable via the CAPE agent + API
— so this buys little. Easiest safe choice: **skip sudoers entirely**, run the
three `[USER]` steps yourself once, and let me drive the rest.

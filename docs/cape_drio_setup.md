# CAPE and DynamoRIO setup

Channel 3 watches a sample run. It records the environment-sensitive API calls it
makes — the call site, the arguments, anything written back into an output buffer,
and the return value — together with the `cmp` and `test` operands those values
are checked against. That is where the values a static pass could not resolve
become visible, and where calls the static pass never found show up at all. It
runs the sample inside CAPE under a DynamoRIO client, and `clew correlate` joins
what it saw back onto the static record.

Getting there takes more setup than the static channels, because the piece doing
the logging is specific to Clew and does not exist anywhere else. This document
covers that part. For installing Clew itself, see
[installation.md](installation.md); for the commands, [usage.md](usage.md).

**None of this is required for static analysis.** `clew static` runs without CAPE,
and `clew correlate --log-dir` works offline against a directory of logs someone
else produced.

## What you need first

- **A working CAPE instance** with a Windows analysis guest, reaching `reported`
  on an ordinary sample. That is CAPE's own domain: follow the
  [CAPE documentation](https://capev2.readthedocs.io/) and confirm a normal
  detonation works before adding anything below. If plain CAPE is broken, every
  symptom in this document will mislead you.
- **A 32-bit-capable Windows guest.** Clew analyses PE32 samples, so the
  DynamoRIO build, the client, and the target are all 32-bit.
- **A Windows machine with MSVC** to build the client. It does not have to be the
  analysis guest, and it should not be.

## 1. DynamoRIO in the analysis guest

Download the Windows release from the
[DynamoRIO releases page](https://github.com/DynamoRIO/dynamorio/releases) and
extract it inside the guest at:

```
C:\dynamorio
```

That exact path matters. `exe_drtrace.py` hardcodes `C:\dynamorio\bin32\drrun.exe`
and `C:\dynamorio\tools\lib32\release\drtrace.dll`; change one and you must change
the other.

Clew is validated against **DynamoRIO 11.91.20651**. Other versions may work, but
the client is compiled against a specific set of headers, so keep the build and
the runtime on the same release.

Only the 32-bit runtime is needed in the guest. A trimmed install of `bin32/`,
`lib32/`, `ext/lib32/release/` and `tools/lib32/release/` is enough, and `drrun`
will emit harmless warnings about the missing 64-bit and debug pieces. Keep
`ext/lib32/release/` in particular: the client links the `drmgr` and `drwrap`
extensions, and both load from there at runtime.

Verify inside the guest before going further:

```
C:\dynamorio\bin32\drrun.exe -version
```

Whatever mechanism you use to provision the guest, DynamoRIO must be present in
the snapshot CAPE reverts to, not merely on a running machine. CAPE restores that
snapshot for every task, so anything installed outside it disappears.

## 2. Build the client

`drtrace.dll` is Clew's DynamoRIO client. Build it per
[`cape_packages/drtrace/BUILD_RECIPE.md`](../cape_packages/drtrace/BUILD_RECIPE.md),
which covers the toolchain, the dev kit, and the 32-bit build. That recipe also
describes a syntax check you can run on Linux before booting the build machine,
which catches most mistakes without a build cycle.

No prebuilt DLL is distributed. An unsigned Windows DLL, downloaded from a
release page, that gets injected into malware-analysis VMs is exactly the sort of
artifact that should not be taken on trust. Build it yourself from the source in
this repository.

`cape_packages/cmplog/` holds an earlier client that logged comparison operands
only. It still builds and its logs still correlate, so an existing deployment
keeps working, but it produces no API observations. `drtrace` is a superset;
prefer it for a new install.

## 3. Place the client and the package

Two files have to land in two different places.

**The DLL, inside the guest:**

```
C:\dynamorio\tools\lib32\release\drtrace.dll
```

Then **re-take the analysis snapshot**, so CAPE reverts to a state that already
has the DLL in place. If the snapshot CAPE uses does not contain it, every task
will run `drrun` against a client that is not there.

**The CAPE package, on the CAPE host:**

```
cape_packages/exe_drtrace.py  ->  /opt/CAPEv2/analyzer/windows/modules/packages/
```

That directory is owned by the CAPE user, so this needs the appropriate
privileges. No CAPE restart is required: the analyzer payload is assembled per
task, so a newly deployed package is picked up by the next submission.

Finally, make sure CAPE's machinery configuration points at the snapshot you
updated. If you took a new one rather than overwriting, update the `snapshot=`
entry for that machine and restart `cape.service` so the pool reloads.

## 4. Submit with `free=yes` — the part that is not optional

**CAPE's monitor and DynamoRIO cannot coexist.** `capemon` injects into
`drrun.exe` and corrupts DynamoRIO, which self-terminates about a second in,
leaving zero log files. Nothing reports an error. The task completes, the analysis
looks successful, and the log directory is simply empty.

The fix is to run in CAPE's **free mode**, which skips the monitor injection:

```bash
curl -F file=@sample.exe \
     -F package=exe_drtrace \
     -F timeout=120 \
     -F enforce_timeout=1 \
     -F options=free=yes \
     http://127.0.0.1:8000/apiv2/tasks/create/file/
```

Note *where* `free=yes` goes. It is a **package option**, read from the
`options=` string, so a top-level `-F "free=1"` is silently ignored and you get
the empty-log behaviour with no indication why.

Free mode means no CAPE behavioural log for that task, which is the intended
trade: what Channel 3 is after is the client's own record of the run.

`clew detonate` and `clew run` set this for you. The curl form is here because
the failure is invisible, and anyone submitting by hand or debugging an empty
result needs to know it exists.

## 5. Verify

```bash
clew doctor                  # CAPE reachable, storage readable
clew detonate sample.exe     # returns a task id
clew tasks                   # RECORDS column, once the task is terminal
```

A successful run leaves logs at:

```
/opt/CAPEv2/storage/analyses/<task_id>/files/drtrace.*.log
```

There is one file per thread plus a `drtrace.<pid>.modules.log` holding the
module table, which is what lets Clew rebase addresses without being told where
the sample loaded. `clew tasks` shows a non-zero RECORDS count; a benign 32-bit
console program typically yields tens of thousands of comparison records.

Then join them onto a static record:

```bash
clew correlate --record results/<sha256>.clew.json --task <id>
```

## When RECORDS reads 0

The log directory tells you which kind of failure you have before anything else
does. **If the module table is missing too**, the client never got as far as
running — it writes that file during initialisation, before the sample's own code
executes. If the module table is there but nothing else is, DynamoRIO started and
the run produced nothing.

In rough order of likelihood:

- **`free=yes` was missing or in the wrong place.** By far the most common cause,
  and it looks identical to success. See section 4.
- **The DLL is not in the snapshot CAPE reverted to.** Placing it on a running
  guest is not enough; the snapshot has to carry it.
- **Architecture mismatch.** A 32-bit `drrun` cannot instrument a 64-bit target.
- **DynamoRIO does not survive the sample.** Some samples defeat instrumentation.
  This is real and expected: `al-khaser`, Clew's own static fixture, produces
  nothing at all — not even the module table — while a benign sample in the
  identical setup produces tens of thousands of records. An empty result is an
  honest one, not a broken pipeline.

The first three are setup problems and the fourth is a property of the sample. To
tell them apart, run a benign 32-bit console program through the same path: if it
logs and your sample does not, the setup is fine.

## When the logs are there but the record gains nothing

A sample can survive instrumentation and still exercise very little. Channel 3
sees only what actually ran, and a short sandbox timeout on a program that waits,
checks one thing and exits will yield a handful of calls. That is not a fault to
debug — it is the honest coverage of one execution.

`scripts/screen_ch3_samples.py` ranks candidate samples by how much of the
environment-sensitive API set they import, which is a cheap way to pick fixtures
worth detonating. Imports are not calls, so it narrows the field rather than
answering the question.

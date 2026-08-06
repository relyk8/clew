# Building cmplog.dll

Steps to build the Channel 3 comparison-operand logger for a Windows analysis
guest. Target: **32-bit / x86**, DynamoRIO **11.91.20651**.

**This cannot be built on Linux.** DynamoRIO's CMake config raises a
`FATAL_ERROR` on any non-MSVC compiler on Windows
(`DynamoRIOConfig.cmake`: *"DynamoRIO's CMake configuration only supports the
Microsoft compiler on Windows"*). You need a Windows machine with MSVC.

Keep this separate from the analysis guest. A CAPE analysis snapshot should stay
lean and free of a compiler toolchain; build in a second Windows VM, or on any
Windows box, and copy the resulting DLL across. If you build in a VM, snapshot it
once the toolchain is installed so the setup is a one-time cost.

For the whole Channel 3 path, of which this is one step, see
[docs/channel3_setup.md](../../docs/channel3_setup.md).

## 1. Install the toolchain

Visual Studio Build Tools with the C++ workload:

```
vs_BuildTools.exe --quiet --wait --norestart ^
  --add Microsoft.VisualStudio.Workload.VCTools ^
  --includeRecommended
```

`--includeRecommended` brings CMake and Ninja along, under
`...\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\`. Otherwise install
them separately and put them on `PATH`.

Exit code **3010 means success with a reboot pending**, not failure. `cl.exe`
works without the reboot, which matters if you are driving the machine over a
remote agent that would not survive one.

## 2. Get the DynamoRIO dev kit onto the build machine

The runtime layout used by the analysis guest is **not** enough to build against.
You need the full release package, which carries `include/`, `ext/include/`, and
`cmake/`. Download it from the
[DynamoRIO releases page](https://github.com/DynamoRIO/dynamorio/releases) and
extract it so that `cmake\` and `include\` sit directly underneath, for example
`C:\dynamorio-sdk\`.

**Include `tools/lib32/release/` if you trim the kit.** `find_package(DynamoRIO)`
loads the entire `DynamoRIOTarget32.cmake`, and raises a `FATAL_ERROR` if *any*
imported target's `.lib` or `.dll` is missing, including targets this client never
links against. A working lean set is:

```
cmake  include  ext/include  lib32  ext/lib32  bin32  ext/bin32  tools/lib32/release
```

Only `Target32` loads for a 32-bit build, so no 64-bit libraries are needed.

Copy `cmplog.c` and `CMakeLists.txt` from this directory to the build machine,
for example `C:\clew\cmplog\`.

## 3. Build

From an **x86** native tools environment, so the 32-bit compiler is selected:

```
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86
cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
  -DDynamoRIO_DIR=C:\dynamorio-sdk\cmake ^
  -S C:\clew\cmplog -B C:\clew\cmplog\build
cmake --build C:\clew\cmplog\build --target cmplog
```

Or with the Visual Studio generator, where `-A Win32` selects 32-bit:

```
cmake -G "Visual Studio 17 2022" -A Win32 -DDynamoRIO_DIR=C:\dynamorio-sdk\cmake -S ... -B ...
cmake --build ... --config RelWithDebInfo --target cmplog
```

Output is `cmplog.dll`, in the build directory for Ninja or under a configuration
subdirectory for Visual Studio. A correct build is a PE32 DLL of roughly 90 KB.

## 4. Smoke-test it

```
drrun.exe -c C:\clew\cmplog\build\cmplog.dll -logdir C:\cmp_logs -- <target.exe>
type C:\cmp_logs\cmplog.*.log
```

Three things to know before reading the result:

- **The target must be 32-bit.** On 64-bit Windows, `System32\hostname.exe` is
  64-bit and a 32-bit `drrun` cannot instrument it. Use the `SysWOW64` copy.
- **Instrumentation is slow.** The client makes a clean call per comparison, so a
  trivial program can take minutes to finish. That is expected.
- **A lean DynamoRIO install prints cosmetic warnings** about not being a valid
  root, and about missing 64-bit and debug libraries. They are harmless; the
  client still logs.

Prefer a self-exiting target for a manual smoke. The client flushes after every
record, so a killed process still leaves usable output, but a clean exit is
simpler to reason about.

## 5. Deploy

Once built, `cmplog.dll` has to reach the analysis guest and CAPE has to know
about the package. Both steps, and the `free=yes` submission requirement that
makes the difference between logs and an empty directory, are covered in
[docs/channel3_setup.md](../../docs/channel3_setup.md).

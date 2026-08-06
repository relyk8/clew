/* GENERATED FILE -- DO NOT EDIT BY HAND.
 *
 * Regenerate with:  python scripts/gen_api_table.py
 * Source of truth:  clew/tiers.py TARGET_ENV_APIS
 *
 * The APIs drtrace wraps are exactly the APIs the pipeline treats as
 * environment-sensitive. Generating this table from the Python set keeps
 * the client and the pipeline from drifting apart.
 */

#ifndef DRTRACE_API_TABLE_H
#define DRTRACE_API_TABLE_H

#define DRTRACE_API_COUNT 88

/* Sorted, so the table is stable across regenerations and a diff of this
 * file shows only genuine additions and removals. */
static const char *const drtrace_api_names[DRTRACE_API_COUNT] = {
    "CheckRemoteDebuggerPresent",
    "CreateFileA",
    "CreateFileW",
    "CreateMutexA",
    "CreateMutexW",
    "DeviceIoControl",
    "EnumDisplayDevicesW",
    "FindFirstFileA",
    "FindFirstFileW",
    "FindNextFileA",
    "FindNextFileW",
    "FindWindowA",
    "FindWindowExA",
    "FindWindowExW",
    "FindWindowW",
    "GetAdaptersAddresses",
    "GetAdaptersInfo",
    "GetComputerNameA",
    "GetComputerNameExA",
    "GetComputerNameExW",
    "GetComputerNameW",
    "GetCursorPos",
    "GetDiskFreeSpaceExA",
    "GetDiskFreeSpaceExW",
    "GetFileAttributesA",
    "GetFileAttributesExA",
    "GetFileAttributesExW",
    "GetFileAttributesW",
    "GetForegroundWindow",
    "GetKeyboardLayout",
    "GetLocalTime",
    "GetModuleFileNameA",
    "GetModuleFileNameExA",
    "GetModuleFileNameExW",
    "GetModuleFileNameW",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "GetNativeSystemInfo",
    "GetProcessImageFileNameA",
    "GetProcessImageFileNameW",
    "GetSystemDefaultLCID",
    "GetSystemFirmwareTable",
    "GetSystemInfo",
    "GetSystemTime",
    "GetTickCount",
    "GetTickCount64",
    "GetUserDefaultLCID",
    "GetUserNameA",
    "GetUserNameExW",
    "GetUserNameW",
    "GetVolumeInformationA",
    "GetVolumeInformationW",
    "GetWindowTextA",
    "GetWindowTextW",
    "GlobalMemoryStatusEx",
    "InternetGetConnectedState",
    "IsDebuggerPresent",
    "IsNativeVhdBoot",
    "IsProcessorFeaturePresent",
    "K32GetModuleBaseNameA",
    "K32GetModuleBaseNameW",
    "NtCreateFile",
    "NtOpenKey",
    "NtQueryDirectoryObject",
    "NtQueryInformationProcess",
    "NtQuerySystemInformation",
    "NtQueryValueKey",
    "Process32First",
    "Process32FirstW",
    "Process32Next",
    "Process32NextW",
    "QueryFullProcessImageNameW",
    "QueryPerformanceCounter",
    "RegEnumKeyA",
    "RegEnumKeyExA",
    "RegEnumKeyExW",
    "RegEnumKeyW",
    "RegOpenKeyA",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegOpenKeyW",
    "RegQueryValueExA",
    "RegQueryValueExW",
    "SetupDiGetDeviceRegistryPropertyW",
    "Sleep",
    "SleepEx",
    "WNetGetProviderNameA",
    "timeGetTime",
};

#endif /* DRTRACE_API_TABLE_H */

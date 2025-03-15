#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <conio.h>

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xc0000004)

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

#define GREEN "\033[1;32m"
#define RED "\033[1;31m"
#define BLUE "\033[1;34m"
#define RESET "\033[0m"

typedef NTSTATUS (NTAPI *_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
typedef NTSTATUS (NTAPI *_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
typedef NTSTATUS (NTAPI *_NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );
typedef NTSTATUS (NTAPI *_NtClose)(HANDLE Handle);

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

DWORD GetProcessIdByName(const wchar_t *processName)
{
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe))
    {
        do
        {
            if (wcscmp(pe.szExeFile, processName) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

void fancyPrint(const char *color, const char *message)
{
    printf("%s%s%s", color, message, RESET);
}

int wmain()
{
    fancyPrint(BLUE, "[INFO] Starting Handle Scanner...\n");

    _NtQuerySystemInformation NtQuerySystemInformation = 
        (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
    _NtDuplicateObject NtDuplicateObject =
        (_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
    _NtQueryObject NtQueryObject =
        (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
    _NtClose NtClose = (_NtClose)GetLibraryProcAddress("ntdll.dll", "NtClose");
    
    DWORD pid = GetProcessIdByName(L"RobloxPlayerBeta.exe");
    if (!pid)
    {
        fancyPrint(RED, "[ERROR] RobloxPlayerBeta.exe not found!\n");
        return 1;
    }
    
    fancyPrint(GREEN, "[SUCCESS] Found RobloxPlayerBeta.exe!\n");
    HANDLE processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!processHandle)
    {
        fancyPrint(RED, "[ERROR] Could not open RobloxPlayerBeta.exe!\n");
        return 1;
    }

    ULONG handleInfoSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
    NTSTATUS status;
    
    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        handleInfo,
        handleInfoSize,
        NULL
        )) == STATUS_INFO_LENGTH_MISMATCH)
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

    if (!NT_SUCCESS(status))
    {
        fancyPrint(RED, "[ERROR] NtQuerySystemInformation failed!\n");
        return 1;
    }

    for (ULONG i = 0; i < handleInfo->HandleCount; i++)
    {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];
        if (handle.ProcessId != pid)
            continue;
        
        HANDLE dupHandle = NULL;
        if (!NT_SUCCESS(NtDuplicateObject(
            processHandle,
            (HANDLE)(ULONG_PTR)handle.Handle,
            GetCurrentProcess(),
            &dupHandle,
            0,
            0,
            0)))
            continue;

        PVOID objectNameInfo = malloc(0x1000);
        UNICODE_STRING objectName;
        ULONG returnLength;
        
        if (NT_SUCCESS(NtQueryObject(
            dupHandle,
            ObjectNameInformation,
            objectNameInfo,
            0x1000,
            &returnLength)))
        {
            objectName = *(PUNICODE_STRING)objectNameInfo;
            if (objectName.Length && wcsstr(objectName.Buffer, L"singleton"))
            {
                printf(GREEN "[INFO] Forcing closure of handle: [%#x] %.*s\n" RESET,
                       handle.Handle, objectName.Length / 2, objectName.Buffer);
                NtDuplicateObject(
                    processHandle,
                    (HANDLE)(ULONG_PTR)handle.Handle,
                    NULL,
                    NULL,
                    0,
                    0,
                    DUPLICATE_CLOSE_SOURCE);
            }
        }
        
        free(objectNameInfo);
        CloseHandle(dupHandle);
    }

    free(handleInfo);
    CloseHandle(processHandle);
    fancyPrint(GREEN, "[SUCCESS] All singleton handles removed!\n");
    return 0;
}

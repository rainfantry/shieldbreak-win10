// Stage 1 Test: Cloud Files API Availability
// Tests if the Cloud Files API works on Win10 19045
//
// This is the FIRST thing to test. If this fails, the exploit won't work.

#include <windows.h>
#include <cfapi.h>
#include <stdio.h>

#pragma comment(lib, "CldApi.lib")

int main() {
    printf("[*] ShieldBreak Win10 Port - Stage 1 Test\n");
    printf("[*] Testing Cloud Files API availability...\n\n");

    // Step 1: Check if CldApi.dll exists
    HMODULE hCldApi = LoadLibraryW(L"CldApi.dll");
    if (!hCldApi) {
        printf("[-] FAILED: CldApi.dll not found\n");
        printf("[-] Cloud Files API not available on this Windows version\n");
        return 1;
    }
    printf("[+] CldApi.dll loaded successfully\n");
    FreeLibrary(hCldApi);

    // Step 2: Try to create a test sync root
    wchar_t testDir[MAX_PATH];
    GetTempPathW(MAX_PATH, testDir);
    wcscat(testDir, L"ShieldBreak_Stage1_Test");

    if (!CreateDirectoryW(testDir, NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            printf("[-] Failed to create test directory: %d\n", GetLastError());
            return 1;
        }
    }
    printf("[+] Test directory: %ws\n", testDir);

    // Step 3: Try to register a sync root
    GUID testGuid;
    CoCreateGuid(&testGuid);

    CF_SYNC_REGISTRATION reg = { 0 };
    reg.StructSize = sizeof(reg);
    reg.ProviderName = L"ShieldBreakTest";
    reg.ProviderVersion = L"1.0";
    reg.ProviderId = testGuid;

    CF_SYNC_POLICIES policies = { 0 };
    policies.StructSize = sizeof(policies);
    policies.Hydration.Primary = CF_HYDRATION_POLICY_FULL;
    policies.Population.Primary = CF_POPULATION_POLICY_PARTIAL;

    HRESULT hr = CfRegisterSyncRoot(testDir, &reg, &policies, CF_REGISTER_FLAG_NONE);
    if (FAILED(hr)) {
        printf("[-] CfRegisterSyncRoot failed: 0x%08X\n", hr);

        if (hr == E_INVALIDARG) {
            printf("[-] Invalid argument - check directory permissions\n");
        } else if (hr == E_ACCESSDENIED) {
            printf("[-] Access denied - run from a regular user (not admin)\n");
        }

        RemoveDirectoryW(testDir);
        return 1;
    }
    printf("[+] Cloud provider registered successfully!\n");

    // Step 4: Unregister
    hr = CfUnregisterSyncRoot(testDir);
    if (FAILED(hr)) {
        printf("[!] Warning: CfUnregisterSyncRoot failed: 0x%08X\n", hr);
    } else {
        printf("[+] Cloud provider unregistered\n");
    }

    RemoveDirectoryW(testDir);

    printf("\n[+] STAGE 1 PASSED: Cloud Files API works on this system!\n");
    printf("[*] Next: Test Stage 2 (Object Manager namespaces)\n");

    return 0;
}

// Compile with:
// cl.exe stage1_test_cloudfiles.cpp /Fe:stage1_test.exe /link CldApi.lib ole32.lib

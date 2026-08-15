# ShieldBreak Win10 — Research Analysis
## ASI Internship Research — Rainfantry

> **Purpose:** Vulnerability research and defensive analysis of MSNightmare's ShieldBreak privilege escalation technique, with focus on Win10 attack surface.

---

## Executive Summary

ShieldBreak is a User→SYSTEM privilege escalation chain that abuses the interaction between Windows Cloud Files API, Windows Defender scanning behavior, and CLFS (Common Log File System) race conditions. Originally targeting Windows 11, this research explores portability to Windows 10.

**Key Finding:** The core primitives (Cloud Files API, Object Manager symlinks, Defender scan triggers) function on Win10 1709+, but the full chain requires adaptation due to `phoneinfo.dll` differences between OS versions.

---

## Architecture Analysis

### The 7-Stage Exploit Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 1: Cloud Files Provider Registration                         │
│  ─────────────────────────────────────────────────────────────────  │
│  CfRegisterSyncRoot() → Register fake OneDrive-style sync provider  │
│  CfCreatePlaceholders() → Create "cloud" file that hydrates on      │
│                           access with attacker-controlled content   │
│                                                                     │
│  WHY IT WORKS: Cloud Files API allows unprivileged users to create  │
│  files that trigger callbacks when accessed — file content is       │
│  supplied by the registering process, not read from disk.           │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 2: Object Manager Namespace Manipulation                     │
│  ─────────────────────────────────────────────────────────────────  │
│  \BaseNamedObjects\Restricted\WD_TARGET_<guid>\                     │
│  \BaseNamedObjects\Restricted\WD_SHADOW_<guid>\WD_SCAN → symlink    │
│                                                                     │
│  WHY IT WORKS: Standard users can create directories and symbolic   │
│  links in \BaseNamedObjects\Restricted\. These symlinks redirect    │
│  file operations to attacker-controlled paths.                      │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 3: Windows Defender Scan Trigger                             │
│  ─────────────────────────────────────────────────────────────────  │
│  MpManagerOpen() → Connect to Defender via MpClient.dll             │
│  MpScanStart() → Trigger scan on cloud placeholder                  │
│                                                                     │
│  WHY IT WORKS: Defender runs as SYSTEM and will follow symbolic     │
│  links when scanning. The EICAR test file triggers scan behavior    │
│  without actual malware.                                            │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 4: CLFS Race Condition (TOCTOU)                              │
│  ─────────────────────────────────────────────────────────────────  │
│  ReadDirectoryChangesW() → Watch for CLFS log file creation         │
│  LockFileEx() → Lock CLFS log mid-operation                         │
│  Delete symlink → Recreate pointing to target DLL                   │
│                                                                     │
│  WHY IT WORKS: Classic time-of-check-to-time-of-use. Between        │
│  Defender checking the path and writing to it, the symlink target   │
│  is swapped to point elsewhere.                                     │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 5: DLL Payload Write via NTFS ADS                            │
│  ─────────────────────────────────────────────────────────────────  │
│  Target: C:\Windows\System32\phoneinfo.dll:stream                   │
│  Defender's file operation writes attacker DLL via alternate stream │
│                                                                     │
│  WHY IT WORKS: NTFS Alternate Data Streams allow writing to         │
│  protected locations indirectly. The ADS is later mapped as         │
│  executable code.                                                   │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 6: WER Task Trigger                                          │
│  ─────────────────────────────────────────────────────────────────  │
│  Create: C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...       │
│  ITaskService → Run "QueueReporting" scheduled task                 │
│                                                                     │
│  WHY IT WORKS: WER QueueReporting runs as SYSTEM and loads DLLs     │
│  from predictable locations. phoneinfo.dll is in the search path.  │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 7: SYSTEM Code Execution                                     │
│  ─────────────────────────────────────────────────────────────────  │
│  Payload DLL executes in SYSTEM context                             │
│  Named pipe callback to user process                                │
│  Proof: C:\SHIELDBREAK_SYSTEM.txt written as SYSTEM                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Research Journey

### Initial Approach (Dead End)
Started with standalone WER DLL hijacking research. Discovered the specific vector targeting `wer.dll` search order was patched in Win10 build 19045+.

### Pivot to ShieldBreak
Identified MSNightmare's ShieldBreak as the current state-of-art for this vulnerability class. ShieldBreak README noted: "Windows 10... are not currently supported" — became the research target.

### Stage-by-Stage Validation

| Stage | Component | Win10 Status | Notes |
|-------|-----------|--------------|-------|
| 1 | Cloud Files API | ✓ WORKS | Available Win10 1709+ |
| 2 | Object Manager | ✓ WORKS | \BaseNamedObjects\Restricted\ accessible |
| 3 | Defender API | ✓ WORKS | MpClient.dll loads, MpManagerOpen succeeds |
| 4 | CLFS Race | UNTESTED | Integrated in full chain |
| 5 | DLL Write | BLOCKED | CF_PLACEHOLDER error 0x8007017C |
| 6 | WER Trigger | UNTESTED | Depends on Stage 5 |
| 7 | Shell | BLOCKED | **Defender detects payload before execution** |

### Blocking Issue #1: CF_PLACEHOLDER Error

The simplified Win10 port encountered `0x8007017C` during `CfCreatePlaceholders()`. This indicates the sync root registration was incomplete — the original ShieldBreak uses a more sophisticated Cloud Files setup that wasn't fully replicated.

**Resolution Path:** Use MSNightmare's original ShieldBreak.cpp as reference for proper CF_SYNC_ROOT configuration.

### Blocking Issue #2: Windows Defender Detection (2026-08-16)

**Finding:** Windows Defender detects and blocks ShieldBreak components before execution.

```
Status: BLOCKED
Detection: Defender flagged payload/exploit binaries
Result: "System cannot execute" / "Virus found"
```

**What Gets Flagged:**
| Component | Detection Reason |
|-----------|------------------|
| `warden_win10.dll` | Behavioral: spawns cmd.exe, writes to C:\, named pipe connection |
| `ShieldBreak.exe` | Signature: known exploit tool pattern match |
| `eicar_com.zip` | Signature: EICAR test file (by design) |

**Defensive Implication:** This is a **positive finding** for defenders. Defender's real-time protection catches the payload through:
1. **Behavioral heuristics** — Process spawning patterns, pipe creation, privilege indicators
2. **Signature matching** — Known ShieldBreak samples in Defender's database

**The Irony:** ShieldBreak requires Defender to be running (Stage 3 uses it), but Defender also detects the payload. Real-world attackers would need additional evasion — which is outside scope of this defensive research.

### phoneinfo.dll Variance

| OS Version | phoneinfo.dll | Implication |
|------------|---------------|-------------|
| Win11 | Does not exist | Exploit creates it ✓ |
| Win10 (some builds) | May exist | Requires alternative target |

Alternative targets for Win10 if phoneinfo.dll exists:
- `fveapi.dll` (BitLocker)
- `edputil.dll` (Enterprise Data Protection)
- Other absent DLLs in SYSTEM service search paths

---

## Compilation Notes

### Macro Redefinition Warnings (C4005)

When building, 64 warnings appear:
```
warning C4005: 'STATUS_WAIT_0': macro redefinition
```

**Explanation:** Both `ntstatus.h` and `winnt.h` define `STATUS_*` constants. ShieldBreak needs NT APIs (requiring `ntstatus.h`) but `windows.h` includes `winnt.h` automatically. Since values are identical, warnings are cosmetic — build succeeds.

**Fix (optional):**
```cpp
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
```

---

## File Structure

```
shieldbreak-win10/
├── README.md                    ← This analysis document
├── original/
│   ├── ShieldBreak.cpp          ← MSNightmare's Win11 source (reference)
│   ├── Report.wer               ← WER report template
│   └── Warden_payload.cpp       ← Payload template
├── win10-port/
│   ├── shieldbreak_win10.cpp    ← Win10 adaptation (WIP)
│   ├── warden_win10.cpp         ← Payload DLL source
│   ├── stage1_test_cloudfiles.cpp   ← Cloud Files API test
│   ├── stage2_test_objmgr.cpp       ← Object Manager test
│   └── stage3_test_defender.cpp     ← Defender API test
└── .gitignore                   ← Excludes compiled binaries
```

---

## Defensive Insights

### Key Finding: Defender Blocks ShieldBreak (Win10)

✓ **Windows Defender successfully detects and prevents ShieldBreak execution on Win10.**

This validates that current Defender signatures and behavioral heuristics catch this exploit family. Organizations with Defender enabled and updated have protection against this specific technique.

### Detection Opportunities

1. **Cloud Files Provider Registration** — Monitor `CfRegisterSyncRoot()` calls from unusual processes
2. **Object Manager Symlinks** — Alert on symlink creation in `\BaseNamedObjects\Restricted\` pointing to System32
3. **CLFS Log Manipulation** — Unusual CLFS activity combined with symlink operations
4. **WER Task Execution** — QueueReporting task triggered without corresponding crash
5. **phoneinfo.dll Creation** — This DLL shouldn't exist on Win11; creation is suspicious

### Mitigations

- **Credential Guard** — Reduces impact of SYSTEM compromise
- **Attack Surface Reduction** — Block Office apps from creating child processes
- **WDAC/AppLocker** — Prevent unsigned DLL loading in System32
- **Defender Tamper Protection** — Limits MpClient.dll abuse vectors

---

## References

- **Original ShieldBreak:** https://github.com/MSNightmare/ShieldBreak
- **Cloud Files API:** https://docs.microsoft.com/en-us/windows/win32/api/cfapi/
- **CLFS Documentation:** https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-the-common-log-file-system
- **Object Manager:** Windows Internals, 7th Edition, Part 1

---

## Credits

- **MSNightmare (ASI)** — Original ShieldBreak research
- **Rainfantry** — Win10 portability analysis

---

## Disclaimer

This documentation is for authorized security research and defensive analysis only. Understanding attack techniques enables better detection and protection.

---

---

# סיכום מחקר ShieldBreak Win10
## פרויקט התמחות ASI — Rainfantry

> **מטרה:** מחקר פגיעויות וניתוח הגנתי של טכניקת הסלמת הרשאות ShieldBreak של MSNightmare, עם התמקדות במשטח התקיפה של Windows 10.

---

## תקציר מנהלים

ShieldBreak היא שרשרת הסלמת הרשאות מ-User ל-SYSTEM שמנצלת את האינטראקציה בין Windows Cloud Files API, התנהגות הסריקה של Windows Defender, ותנאי מירוץ ב-CLFS (Common Log File System). במקור מכוונת ל-Windows 11, מחקר זה בוחן ניידות ל-Windows 10.

**ממצא מרכזי:** הפרימיטיבים המרכזיים (Cloud Files API, סימלינקים של Object Manager, טריגרים לסריקת Defender) עובדים על Win10 1709+, אך השרשרת המלאה דורשת התאמה בגלל הבדלי `phoneinfo.dll` בין גרסאות מערכת ההפעלה.

---

## ניתוח ארכיטקטורה

### שרשרת הניצול בת 7 השלבים

**שלב 1: רישום ספק Cloud Files**
- `CfRegisterSyncRoot()` → רישום ספק סנכרון מזויף בסגנון OneDrive
- `CfCreatePlaceholders()` → יצירת קובץ "ענן" שמתמלא בגישה עם תוכן בשליטת התוקף

**שלב 2: מניפולציית מרחב השמות של Object Manager**
- יצירת ספריות וסימלינקים ב-`\BaseNamedObjects\Restricted\`
- הסימלינקים מפנים פעולות קבצים לנתיבים בשליטת התוקף

**שלב 3: הפעלת סריקת Windows Defender**
- `MpManagerOpen()` → התחברות ל-Defender דרך MpClient.dll
- `MpScanStart()` → הפעלת סריקה על placeholder הענן

**שלב 4: תנאי מירוץ CLFS (TOCTOU)**
- `ReadDirectoryChangesW()` → מעקב אחר יצירת קובץ לוג CLFS
- מחיקה ויצירה מחדש של סימלינק שמצביע על DLL יעד

**שלב 5: כתיבת DLL דרך NTFS ADS**
- יעד: `C:\Windows\System32\phoneinfo.dll:stream`
- פעולת הקובץ של Defender כותבת DLL תוקף דרך alternate stream

**שלב 6: הפעלת משימת WER**
- יצירת דוח ב-`C:\ProgramData\Microsoft\Windows\WER\ReportQueue\`
- הרצת המשימה המתוזמנת "QueueReporting"

**שלב 7: הרצת קוד כ-SYSTEM**
- ה-DLL של ה-payload מורץ בהקשר SYSTEM
- הוכחה: `C:\SHIELDBREAK_SYSTEM.txt` נכתב כ-SYSTEM

---

## מסע המחקר

### גישה ראשונית (מבוי סתום)
התחלנו עם מחקר DLL hijacking עצמאי של WER. גילינו שהווקטור הספציפי תוקן ב-Win10 build 19045+.

### מעבר ל-ShieldBreak
זיהינו את ShieldBreak של MSNightmare כ-state-of-the-art הנוכחי למחלקת פגיעויות זו.

### אימות שלב אחר שלב

| שלב | רכיב | סטטוס Win10 |
|-----|------|-------------|
| 1 | Cloud Files API | ✓ עובד |
| 2 | Object Manager | ✓ עובד |
| 3 | Defender API | ✓ עובד |
| 4 | מירוץ CLFS | לא נבדק |
| 5 | כתיבת DLL | חסום (שגיאה 0x8007017C) |
| 6 | טריגר WER | לא נבדק |
| 7 | Shell | חסום — **Defender מזהה את ה-payload** |

### ממצא הגנתי: זיהוי Defender (16-08-2026)

**ממצא:** Windows Defender מזהה וחוסם רכיבי ShieldBreak לפני הרצה.

| רכיב | סיבת זיהוי |
|------|-----------|
| `warden_win10.dll` | התנהגותי: מפעיל cmd.exe, כותב ל-C:\, חיבור named pipe |
| `ShieldBreak.exe` | חתימה: התאמת תבנית כלי ניצול ידוע |

**משמעות הגנתית:** זהו **ממצא חיובי** למגינים. ההגנה בזמן אמת של Defender תופסת את ה-payload.

---

## תובנות הגנתיות

### הזדמנויות זיהוי

1. **רישום ספק Cloud Files** — ניטור קריאות `CfRegisterSyncRoot()` מתהליכים חריגים
2. **סימלינקים של Object Manager** — התראה על יצירת סימלינק ב-`\BaseNamedObjects\Restricted\` שמצביע על System32
3. **מניפולציית לוג CLFS** — פעילות CLFS חריגה בשילוב עם פעולות סימלינק
4. **הרצת משימת WER** — משימת QueueReporting מופעלת ללא קריסה מתאימה
5. **יצירת phoneinfo.dll** — קובץ DLL זה לא אמור להתקיים ב-Win11; יצירתו חשודה

### הקשחות

- **Credential Guard** — מפחית את ההשפעה של פריצת SYSTEM
- **Attack Surface Reduction** — חסימת אפליקציות Office מיצירת תהליכי ילד
- **WDAC/AppLocker** — מניעת טעינת DLL לא חתום ב-System32

---

## קרדיטים

- **MSNightmare (ASI)** — מחקר ShieldBreak המקורי
- **Rainfantry** — ניתוח ניידות ל-Win10

---

## הצהרת אחריות

תיעוד זה מיועד למחקר אבטחה מורשה וניתוח הגנתי בלבד. הבנת טכניקות תקיפה מאפשרת זיהוי והגנה טובים יותר.

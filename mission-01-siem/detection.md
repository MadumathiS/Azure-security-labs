# Mission 01 — Getting Eyes on Your Perimeter: Anomaly Detection

## Mission Context
**Mission:** Mission 01 — Getting Eyes on Your Perimeter  
**Step:** Step 6 — Coach-run unannounced activity detection  
**Objective:** Detect and document anomalous activity on WKS-L57 using Microsoft Sentinel KQL queries  
**Environment:** hamilton.corp domain | Log Analytics workspace: log-sentinel-lab

---

## Overview
This document records the anomalous activity detected during **Step 6** of the SIEM mission, where the coach ran unannounced activity on the workstation that was identified and documented using Microsoft Sentinel.

**Monitoring Period:** October 9, 2026 - **INTRUSION DETECTED** ✅  
**Machine:** WKS-L57.hamilton.corp  
**Detection System:** Microsoft Sentinel on Log Analytics (log-sentinel-lab)  
**Attack Timeframe:** October 9, 2026 from 1:09 PM to 2:07 PM UTC (58-minute window)  
**Detection Confirmed:** ✅ Coach confirmed as unannounced intrusion activity

---

## Detection Queries Used

### Query 1 — Broad sweep: all event types on WKS-L57
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-10-09T13:00:00Z)
| where Computer == "WKS-L57.hamilton.corp"
| summarize Count = count() by EventID
| sort by Count desc
```

### Query 2 — Core attack events (privilege escalation + registry)
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-10-09T13:00:00Z)
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4672, 4799, 5379)
| project TimeGenerated, EventID, Account
| order by TimeGenerated asc
```

### Query 3 — Group membership changes (who was added to which group)
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-10-09T13:00:00Z)
| where Computer == "WKS-L57.hamilton.corp"
| where EventID == 4799
| project TimeGenerated, Account, TargetAccount, TargetUserName
| order by TimeGenerated asc
```

### Query 4 — Logon activity during attack window
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-10-09T13:00:00Z)
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4624, 4625, 4648)
| project TimeGenerated, EventID, Account, LogonType, IpAddress
| order by TimeGenerated asc
```

### Query 5 — Registry modification details
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-10-09T13:00:00Z)
| where Computer == "WKS-L57.hamilton.corp"
| where EventID == 5379
| project TimeGenerated, Account, EventData
| order by TimeGenerated asc
```

### Query 6 — New account creation check
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-10-09T13:00:00Z)
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4720, 4722, 4728, 4732)
| project TimeGenerated, EventID, Account, TargetAccount
| order by TimeGenerated asc
```

---

## Event Count Summary

| EventID | Count | Description |
|---|---|---|
| 5379 | 70 | Credential Manager read operations (registry) |
| 4672 | 28 | Special privileges assigned to new logon |
| 4624 | 28 | Successful logon (all service logons, LogonType 5) |
| 4799 | 19 | Security-enabled local group membership enumerated/changed |
| 4798 | 6 | User's group membership enumerated |
| 4634 | 2 | Account logoff |
| 5061 | 2 | Cryptographic operation |
| 5058 | 2 | Key file operation |

**Total critical security events:** 155+ in a 58-minute window

---

## Anomalous Activity Findings

### Activity Summary
**✅ INTRUSION CONFIRMED — Privilege Escalation + Credential Theft Attempt**

- **Activity Type:** Privilege Escalation, Group Membership Manipulation, Credential Theft Attempt
- **First Event Detected:** October 9, 2026 at 1:09:12 PM UTC
- **Attack Duration:** 58 minutes (1:09 PM – 2:07 PM UTC)
- **Primary Event IDs:** 4799 (group membership), 4672 (special privileges), 5379 (credential manager reads)
- **Accounts Involved:** HAMILTON\WKS-L57$ (machine account), NT AUTHORITY\SYSTEM, HAMILTON\madumathi
- **Source:** Local machine — no external IP, no interactive human logon

---

## Detailed Event Results

### Group Membership Attack — 4 Waves

| Time (UTC) | Account | Group Added | Wave |
|---|---|---|---|
| 1:09:12 PM | HAMILTON\WKS-L57$ | Builtin\Backup Operators | Wave 1 |
| 1:17:40 PM | HAMILTON\madumathi | Builtin\Administrators | Enumeration of existing membership |
| 1:19:09 PM | HAMILTON\WKS-L57$ | Builtin\Administrators | Wave 1 continued |
| 1:19:09 PM | HAMILTON\WKS-L57$ | Builtin\Backup Operators | Wave 1 continued |
| 1:35:15 PM | HAMILTON\WKS-L57$ | Builtin\Administrators | Wave 2 |
| 1:35:15 PM | HAMILTON\WKS-L57$ | Builtin\Backup Operators | Wave 2 |
| 1:51:23 PM | HAMILTON\WKS-L57$ | Builtin\Administrators | Wave 3 |
| 1:51:23 PM | HAMILTON\WKS-L57$ | Builtin\Backup Operators | Wave 3 |
| 2:07:30 PM | HAMILTON\WKS-L57$ | Builtin\Administrators | Wave 4 (final) |
| 2:07:30 PM | HAMILTON\WKS-L57$ | Builtin\Backup Operators | Wave 4 (final) |

### Privilege Escalation Waves — EventID 4672

| Time (UTC) | Account | Note |
|---|---|---|
| 1:39:42 PM | NT AUTHORITY\SYSTEM | Wave 1 — service logon with privileges |
| 1:51:18 PM | NT AUTHORITY\SYSTEM | Wave 2 |
| 1:51:23 PM | NT AUTHORITY\SYSTEM | Wave 3 |
| 1:53:14 PM | NT AUTHORITY\SYSTEM | Wave 4 |
| 1:54:52 PM | NT AUTHORITY\SYSTEM | Wave 5 |
| 2:01:39 PM | NT AUTHORITY\SYSTEM | Wave 6 |
| 2:04:55 PM | NT AUTHORITY\SYSTEM | Wave 7 |
| 2:07:25 PM | NT AUTHORITY\SYSTEM | Wave 8 |
| 2:07:30 PM | NT AUTHORITY\SYSTEM | Wave 9 — final |

### Credential Theft Attempt — EventID 5379

**Time:** 1:53:15 PM UTC  
**Process ID:** 2240  
**Operation:** Windows Credential Manager reads (ReadOperation %%8100)  
**Targets queried:**
- `WindowsLive:(token):name=02ihlnzaqquvunhr` — WKS-L57$ account → **FAILED** (ReturnCode: 3221226021 = Access Denied)
- `WindowsLive:(cert):name=02ihlnzaqquvunhr` — WKS-L57$ account → **FAILED**
- `WindowsLive:target=virtualapp/didlogical` — WKS-L57$ account → **SUCCEEDED** (1 credential returned)
- `WindowsLive:(token):name=02qqtqrglkbrcfxd` — madumathi account → **FAILED**
- `WindowsLive:(cert):name=02qqtqrglkbrcfxd` — madumathi account → **FAILED**
- `WindowsLive:target=virtualapp/didlogical` — madumathi account → **SUCCEEDED** (1 credential returned)
- `MicrosoftAccount:user=02qqtqrglkbrcfxd` — madumathi account → **FAILED**

**Result:** Partial credential access — `virtualapp/didlogical` token read for both accounts. Most credential reads blocked.

### Logon Activity — EventID 4624

All 28 logon events were **LogonType 5 (Service logon)** by **NT AUTHORITY\SYSTEM**.  
**No interactive human logon detected.** The attack was fully automated — no attacker logged in manually.

### New Account Creation — EventID 4720/4722/4728/4732

**No results.** No new accounts were created during the attack. No backdoor user planted.

---

## Analysis

### Attack Phases

**Phase 1 — Initial Group Manipulation (1:09 PM):**
- Machine account WKS-L57$ first added to Backup Operators group
- Establishes data read access before full admin control

**Phase 2 — Full Escalation (1:19 PM):**
- Machine account added to Administrators group (full system control)
- Both groups targeted simultaneously for maximum access

**Phase 3 — Persistence via Repetition (1:35 PM – 2:07 PM):**
- Same group additions repeated every ~16 minutes across 4 waves
- Ensures persistence even if one assignment is reverted
- 9 privilege assignment waves (4672) run in parallel

**Phase 4 — Credential Theft Attempt (1:53 PM):**
- Process 2240 queries Windows Credential Manager for stored tokens
- Targets both machine account and user account credentials
- Mostly blocked — only `virtualapp/didlogical` tokens accessed

### Why No Human Logon?
All activity driven by **NT AUTHORITY\SYSTEM** via service logons (LogonType 5). This indicates:
- A script or scheduled task running as SYSTEM
- Or a service installed by the attacker
- No interactive RDP or console session needed — attack runs silently in background

### Why Multiple Waves?
- Redundancy: if Group Policy or a defender removes the group membership, it gets re-added
- ~16-minute interval matches typical Group Policy refresh cycle
- Classic persistence mechanism used in real-world attacks

---

## Key Indicators of Compromise (IOCs)

**Suspicious Accounts:**
- `HAMILTON\WKS-L57$` — machine account with repeated admin group additions (abnormal)
- `NT AUTHORITY\SYSTEM` — repeated privilege assignment in short window (9 waves)

**Suspicious Event IDs:**
- **4799** — 19 instances of group membership changes (normal baseline: 0-2/hour)
- **4672** — 28 instances of privilege assignment (normal baseline: low single digits)
- **5379** — 70 credential manager reads in burst at 1:53 PM

**Suspicious Groups Targeted:**
- `Builtin\Administrators` — full local system control
- `Builtin\Backup Operators` — can read all files regardless of permissions

**Suspicious Timing:**
- 4 group manipulation waves at ~16-minute intervals — automated, not human
- Credential theft burst (10 reads in <20ms) at 1:53 PM — script behavior
- No user interaction logs — fully automated attack

**Process of Interest:**
- PID 2240 — ran at 1:53:14 PM UTC, queried Credential Manager for both accounts

---

## Why Was It Detected?

**Data Collection Rule Used:** `dcr-securityevents`
- Collects Security event logs in structured format (SecurityEvent table)
- Events 4799, 4672, and 5379 are Security-specific — only captured with this DCR
- Without this DCR, all privilege escalation events would be invisible

**Detection Method:**
1. Ran broad summary query (Query 1) — identified unusual spike in EventIDs 5379, 4672, 4799
2. Ran targeted query (Query 2) — confirmed clustering in narrow time window
3. Ran group membership query (Query 3) — identified exact groups targeted and 4-wave pattern
4. Ran logon query (Query 4) — confirmed automated attack (no human logon)
5. Ran registry query (Query 5) — revealed credential theft attempt via Credential Manager
6. Ran new account query (Query 6) — confirmed no backdoor accounts created

---

## SOC Response

### Incident Severity: CRITICAL

**Immediate Actions (0–30 minutes):**
1. Isolate WKS-L57 — disconnect from network immediately
2. Preserve evidence — do NOT reboot (volatile logs would be lost)
3. Alert incident response team — escalate to security leadership
4. Notify system owner — machine is compromised

**Remediation Steps (within 1 hour):**
1. Remove HAMILTON\WKS-L57$ from Builtin\Administrators
2. Remove HAMILTON\WKS-L57$ from Builtin\Backup Operators
3. Reset all local admin passwords
4. Identify and terminate process PID 2240 (or its parent service)
5. Check for persistence mechanisms:
   - Scheduled tasks (`schtasks /query /fo LIST /v`)
   - Startup folders
   - Registry autorun keys: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
   - New or modified services
6. Revoke any credentials accessed via Credential Manager (virtualapp/didlogical tokens)

**Forensic Investigation (24–48 hours):**
1. Full disk forensics of WKS-L57
2. Identify what process PID 2240 was and how it was launched
3. Review all event logs for lateral movement to other machines
4. Check network logs for C2 communication during attack window
5. Determine how SYSTEM-level script was deployed (GPO abuse? Service install? WMI?)
6. Review if other machines in hamilton.corp were similarly targeted

**Who to Notify:**
- 🔴 CRITICAL — IT Security team
- 🔴 CRITICAL — System owner / WKS-L57 stakeholder
- 🟡 MEDIUM — Incident Response team
- 🟡 MEDIUM — Network security team

---

## Detection Gaps & Recommended Alert Rules

### Current Gaps
- No automated alert for EventID 4799 (group membership changes)
- No automated alert for EventID 4672 spike (privilege escalation)
- No alerting on machine account added to Administrators
- No alerting on Credential Manager bulk reads (5379 burst)
- Manual query required — detection time was 15+ minutes

### Recommended Alert Rules

```kql
// Alert Rule 1: Machine/User Added to Administrators Group
SecurityEvent
| where EventID == 4799
| where TargetAccount contains "Administrators"
| where Account !contains "SYSTEM"
// Severity: CRITICAL

// Alert Rule 2: Privilege Escalation Spike (>3 in 5 minutes)
SecurityEvent
| where EventID == 4672
| where TimeGenerated > ago(5m)
| summarize Count = count() by bin(TimeGenerated, 5m), Account
| where Count > 3
// Severity: HIGH

// Alert Rule 3: Backup Operators Group Addition
SecurityEvent
| where EventID == 4799
| where TargetAccount contains "Backup Operators"
// Severity: MEDIUM

// Alert Rule 4: Credential Manager Bulk Read Burst
SecurityEvent
| where EventID == 5379
| where TimeGenerated > ago(1m)
| summarize Count = count() by bin(TimeGenerated, 1m), Account
| where Count > 5
// Severity: HIGH
```

**Target detection time with these rules:** Under 2 minutes  
**Current detection time (manual):** 15+ minutes

---

## Lessons Learned

**What the SIEM Did Well:**
- Captured all privilege escalation events (4799, 4672)
- Captured credential theft attempt (5379) with full EventData including process ID
- Provided exact timestamps enabling event correlation and wave pattern identification
- Structured SecurityEvent table enabled fast KQL querying
- Confirmed no new accounts — limited attacker's persistence options

**What Needs Improvement:**
- Automated alerting — manual queries are too slow for production
- Baseline alerting — no threshold set for abnormal 4672 or 4799 counts
- Process tracking — EventID 4688 (process creation) not in current DCR, so PID 2240 origin unknown
- Consider adding `dcr-processcreation` to capture 4688 events for process lineage

---

## Current Status

**Step 6 Status:** ✅ COMPLETED — INTRUSION DETECTED AND DOCUMENTED

**Results:**
- ✅ Intrusion detected using KQL queries in Microsoft Sentinel
- ✅ Attack timeline established (1:09 PM – 2:07 PM UTC, October 9, 2026)
- ✅ Attacker actions identified: privilege escalation + credential theft attempt
- ✅ 4-wave persistence pattern documented
- ✅ No new backdoor accounts confirmed
- ✅ IOCs documented for future reference
- ✅ SOC response procedures outlined
- ✅ Detection gaps identified and remediation alert rules provided

**Overall Assessment:** The SIEM infrastructure successfully captured the full attack. Manual detection worked but took too long. Automated alert rules are required for production-grade response times.

---

**Document Last Updated:** October 9, 2026  
**Analyst:** HAMILTON\madumathi  
**Mission Status:** ✅ COMPLETE
# Mission 01 — Getting Eyes on Your Perimeter: Anomaly Detection

## Mission Context
**Mission:** Mission 01 — Getting Eyes on Your Perimeter  
**Step:** Step 6 — Coach-run unannounced activity detection  
**Objective:** Detect and document anomalous activity on WKS-L57 using Microsoft Sentinel KQL queries  
**Environment:** hamilton.corp domain | Log Analytics workspace: log-sentinel-lab

---

## Overview
This document records the anomalous activity detected during **Step 6** of the SIEM mission, where the coach ran unannounced activity on the workstation that was identified and documented using Microsoft Sentinel.

> ⚠️ **Correction Notice:** An earlier version of this report incorrectly identified EventID 4799 (group membership *enumeration*) as group membership additions, and flagged normal Windows baseline events (4672 SYSTEM service logons, LogonType 5, 5379 virtualapp/didlogical reads) as attack indicators. The initial query window (starting 13:00 UTC) also missed the real attack at 12:30 PM UTC. This version reflects corrected findings verified against host state using PowerShell and a widened query window.

**Monitoring Period:** October 9, 2026 - **INTRUSION DETECTED** ✅  
**Machine:** WKS-L57.hamilton.corp  
**Detection System:** Microsoft Sentinel on Log Analytics (log-sentinel-lab)  
**Attack Timeframe:** October 9, 2026 at **12:30:01 PM UTC** (single automated burst)  
**Detection Confirmed:** ✅ Coach confirmed as unannounced intrusion activity  
**Cleanup Confirmed:** October 12, 2026 at 7:38 AM UTC (coach removed svc_backup from Administrators)

---

## Detection Queries Used

### Query 1 — Widen window: look for actual account/group changes from 12:00 UTC
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-10-09T12:00:00Z)
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4720, 4726, 4728, 4732, 4733)
| project TimeGenerated, EventID, Account, TargetAccount, MemberName
| order by TimeGenerated asc
```

### Query 2 — Confirm exact attack moment (narrow window)
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-10-09T12:29:00Z) .. datetime(2026-10-09T12:32:00Z))
| where Computer == "WKS-L57.hamilton.corp"
| project TimeGenerated, EventID, Account, TargetAccount, MemberName
| order by TimeGenerated asc
```

### Query 3 — Full event sweep for the attack day
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-10-09T12:00:00Z)
| where Computer == "WKS-L57.hamilton.corp"
| summarize Count = count() by EventID
| sort by Count desc
```

### Query 4 — Logon activity during attack window
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-10-09T12:29:00Z) .. datetime(2026-10-09T12:32:00Z))
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4624, 4625, 4648)
| project TimeGenerated, EventID, Account, LogonType, IpAddress
| order by TimeGenerated asc
```

### Query 5 — Verify cleanup (group membership removal)
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-10-12T00:00:00Z)
| where Computer == "WKS-L57.hamilton.corp"
| where EventID == 4733
| project TimeGenerated, Account, TargetAccount, MemberName
| order by TimeGenerated asc
```

### Query 6 — Verify no remaining backdoor account (post-cleanup)
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-10-09T12:00:00Z)
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4720, 4726)
| project TimeGenerated, EventID, Account, TargetAccount
| order by TimeGenerated asc
```

---

## Event Count Summary (Corrected)

| EventID | Count | Description | Signal or Noise? |
|---|---|---|---|
| 4720 | 1 | User account created (svc_backup) | **SIGNAL** |
| 4732 | 1 | Member ADDED to Administrators | **SIGNAL** |
| 4728 | 1 | Member added to domain-level group | **SIGNAL** |
| 4733 | 1 | Member REMOVED from Administrators (cleanup) | Cleanup |
| 4799 | 19 | Group membership **enumerated** (read-only) | Noise — baseline |
| 4798 | 6 | User group membership enumerated | Noise — baseline |
| 4672 | 28 | Special privileges assigned (SYSTEM service logon) | Noise — baseline |
| 4624 | 28 | Logon (all LogonType 5, SYSTEM) | Noise — baseline |
| 5379 | 70 | Credential Manager read (virtualapp/didlogical) | Noise — baseline |
| 4634 | 2 | Account logoff | Noise — baseline |
| 5061 | 2 | Cryptographic operation | Noise — baseline |
| 5058 | 2 | Key file operation | Noise — baseline |

**Real attack events:** 3 events (4720 + 4732 + 4728) at 12:30:01 PM UTC — single automated burst.

---

## Anomalous Activity Findings (Corrected)

### Activity Summary
**✅ INTRUSION CONFIRMED — Unauthorized Account Creation + Privilege Escalation**

- **Activity Type:** Account creation, local group privilege escalation
- **Attack Timestamp:** October 9, 2026 at **12:30:01 PM UTC** (all three events in the same second)
- **Attack Duration:** Instantaneous — single automated burst
- **Primary Event IDs:** 4720 (account created), 4732 (added to Administrators), 4728 (domain group)
- **Actor:** HAMILTON\WKS-L57$ (machine account — should never create users or modify groups)
- **Source:** Local machine — no external IP, no interactive human logon

---

## Detailed Event Results

### The Attack — Three Events at 12:30:01 PM UTC

On EventID 4732 (and 4733), Windows records two distinct roles:
- **Subject** = who performed the action (the actor running the script)
- **Member** = who was actually added to or removed from the group

| Time (UTC) | EventID | Description | Subject (Actor) | Member (Affected) |
|---|---|---|---|---|
| 12:30:01 PM | 4720 | User account CREATED | HAMILTON\WKS-L57$ | svc_backup (new account) |
| 12:30:01 PM | 4728 | Default primary group assigned | HAMILTON\WKS-L57$ | svc_backup (Windows auto-assigns "None" group to every new local user — not a domain group addition) |
| 12:30:01 PM | 4732 | Added to Builtin\Administrators | HAMILTON\WKS-L57$ | **svc_backup** (not WKS-L57$) |

All three events occurred in **the same second** — fully automated, scripted.

**Critical distinction:** WKS-L57$ was the **actor** (Subject) that ran the script as SYSTEM — it was never itself *added* to Administrators. What was added to Administrators was **svc_backup**. The host verification confirms this: `Get-LocalGroupMember` never showed WKS-L57$ in Administrators, because it was never there.

**On 4728:** This is Windows automatically assigning the default "None" primary group to every newly created local user. It is not svc_backup joining a domain group. Any real domain-side change (such as svc_backup being added to a domain group) would be logged on DC01, which WKS-L57 does not collect — so that event is genuinely outside our visibility.

### Cleanup Event

| Time (UTC) | EventID | Description | Subject (Actor) | Member (Affected) |
|---|---|---|---|---|
| Oct 12, 7:38 AM | 4733 | Removed from Builtin\Administrators | (coach) | **svc_backup** (not WKS-L57$) |

### Why the Initial Report Was Wrong

**Error 1 — Wrong EventID for group additions:**
EventID 4799 = group membership *enumerated* (read-only). Windows automatically reads group lists after any group change. The 19 instances of 4799 were noise triggered by the real change (4732), not 4 attack waves. The actual addition event is **4732**.

**Error 2 — Wrong time window:**
All initial Step 6 queries started at `datetime(2026-10-09T13:00:00Z)`. The real attack happened at 12:30:01 PM UTC — 30 minutes before the query window started. The initial query for EventID 4720 (account creation) returned no results because the window missed it entirely.

**Error 3 — Baseline events flagged as IOCs:**
- 4672 + SYSTEM + LogonType 5 = normal Windows service logon behavior. Not an IOC.
- 5379 virtualapp/didlogical = Windows live token cache read during authentication. Normal.
- These events appear on any healthy Windows machine. Establishing a baseline before calling something suspicious is essential.

### Host Verification (PowerShell on WKS-L57)

Run on October 12, 2026 to verify SIEM conclusions against machine reality:

```powershell
Get-LocalGroupMember -Group "Administrators"
# HAMILTON\Domain Admins, HAMILTON\madumathi, WKS-L57\Administrator, WKS-L57\becode
# WKS-L57$ NOT present — confirms the 4733 cleanup event removed it

Get-LocalGroupMember -Group "Backup Operators"
# (empty)
# WKS-L57$ was NEVER added here — the 4799 events were enumeration, not additions

Get-LocalUser
# helpdesk, labuser, WDAGUtilityAccount, Guest, Administrator, becode, DefaultAccount
# svc_backup not shown locally — likely a domain account or already cleaned up
```

Host verification confirmed: the "4-wave group manipulation" reported earlier never happened. Only one real addition (4732) occurred at 12:30:01 PM, which was then reversed by the 4733 cleanup.

---

## Analysis

### Attack Phases

**Phase 1 — Automated account creation (12:30:01 PM):**
The script, running as SYSTEM (machine account HAMILTON\WKS-L57$), created a new local user account `svc_backup`. Machine accounts should never create user accounts — this is an immediate IOC regardless of volume.

**Phase 2 — Privilege escalation (12:30:01 PM, same second):**
The same script added `svc_backup` to `Builtin\Administrators`, giving it full local admin rights. WKS-L57$ was the **actor** performing this action via EventID 4732, not the account being added. The 4728 in the same second is Windows auto-assigning the default "None" primary group — not a domain group change.

**Phase 3 — Coach cleanup (October 12, 7:38 AM UTC):**
EventID 4733 confirms the coach removed `svc_backup` from Administrators. svc_backup itself was also cleaned up (not visible in local users on Oct 12 — likely deleted or was a domain account).

### Why a Single Second?

All three attack events share the exact same timestamp (12:30:01 PM UTC). This is script behavior — a human clicking through UI cannot produce three distinct AD operations in one second. A script or scheduled task executed a pre-written payload in one call.

### What Was the Noise?

After the 4732 event, Windows automatically:
- Read group membership lists (4799) to verify the change
- Ran normal SYSTEM service logons (4672, LogonType 5)
- Read credential cache entries (5379 virtualapp/didlogical)

This produced 155+ events over the next 58 minutes — all noise generated by normal Windows post-change behavior. The original report mistook this noise for an ongoing multi-wave attack.

---

## Key Indicators of Compromise (IOCs) — Corrected

**Suspicious Events:**
- `4720` — `svc_backup` account created by a **machine account** (WKS-L57$ as Subject) — abnormal
- `4732` — `svc_backup` added to **Builtin\Administrators** by WKS-L57$ (Subject = actor, Member = svc_backup) — abnormal

**Suspicious Actor:**
- `HAMILTON\WKS-L57$` (Subject) — machine accounts should never create users or modify local groups. Any 4720 or 4732 where the **Subject** account ends in `$` is an immediate IOC.

**Important:** On EventID 4732, always read **Member** (who was added) separately from **Subject** (who performed the action). WKS-L57$ was never in Administrators — svc_backup was. The host check confirms it: `Get-LocalGroupMember -Group "Administrators"` never returned WKS-L57$.

**Suspicious Timing:**
- All three events at the exact same second (12:30:01 PM) — scripted/automated

**What Was NOT an IOC (previously misreported):**
- 4799 (group enumeration) — noise after legitimate group changes
- 4672 with SYSTEM (service logon privilege assignment) — normal Windows baseline
- 5379 virtualapp/didlogical reads — normal Windows credential cache behavior
- LogonType 5 logons by NT AUTHORITY\SYSTEM — normal service logon pattern

---

## Why Was It Detected?

**Data Collection Rule Used:** `dcr-securityevents`
- Collects Security event logs in structured format (SecurityEvent table)
- Events 4720, 4732 are Security-specific — only captured with this DCR
- Without this DCR, all privilege escalation events would be invisible

**Detection Method (corrected approach):**
1. Widen time window to 12:00 UTC → found 12:30 PM events missed by initial 13:00 window
2. Filter to actual change events (4720, 4732, 4733) → signal isolated from noise
3. Narrow to 12:29–12:32 window → confirmed exact attack timestamp
4. Host pivot via PowerShell → confirmed SIEM findings against machine state

---

## SOC Response

### Incident Severity: HIGH

**Immediate Actions (0–30 minutes):**
1. Isolate WKS-L57 — disconnect from network (machine account is compromised)
2. Preserve evidence — do NOT reboot (volatile memory may contain the attacker's script/process)
3. Alert incident response team — machine account compromise implies domain-level risk
4. Check if svc_backup account was used anywhere in the domain

**Remediation Steps (within 1 hour):**
1. Remove HAMILTON\WKS-L57$ from Builtin\Administrators (or verify 4733 cleanup is complete)
2. Disable/delete svc_backup account — verify it has no active sessions or permissions
3. Reset machine account password: `Reset-ComputerMachinePassword` or via ADUC
4. Identify the script/process that ran at 12:30:01 PM (check scheduled tasks, WMI, services)
5. Check for persistence mechanisms:
   - Scheduled tasks: `schtasks /query /fo LIST /v`
   - Registry autorun keys: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
   - New or modified services: `sc query type= all`

**Forensic Investigation (24–48 hours):**
1. Enable EventID 4688 (process creation) via a `dcr-processcreation` rule to capture future process lineage
2. Review Active Directory logs for any use of svc_backup credentials in the domain
3. Determine how WKS-L57$ gained the ability to create domain users (rights delegation? GPO misconfiguration?)
4. Check network logs for C2 communication around 12:30 PM
5. Review all machines in hamilton.corp for similar 4720/4732 patterns involving machine accounts

**Who to Notify:**
- 🔴 HIGH — IT Security team (machine account compromise)
- 🔴 HIGH — Active Directory administrators (domain-level risk from machine account abuse)
- 🟡 MEDIUM — System owner / WKS-L57 stakeholder
- 🟡 MEDIUM — Incident Response team

---

## Detection Gaps & Recommended Alert Rules (Corrected)

**Current Gaps:**
- Initial query window (13:00 UTC) missed the real attack at 12:30 PM — need always-on alerting
- No automated alert for machine accounts (ending in `$`) creating users (4720)
- No automated alert for machine accounts being added to privileged groups (4732)
- EventID 4688 (process creation) not collected — cannot trace what spawned the attack script

**Recommended Alert Rules (corrected EventIDs — see queries.kql Q14-18):**

| Rule | Trigger | Severity | Run Every |
|---|---|---|---|
| Machine account creates user | EventID 4720 + actor ends with $ | Critical | 5 min |
| Machine account → Administrators | EventID 4732 + actor ends with $ + Administrators | Critical | 5 min |
| Any account → Administrators (non-domain-admin) | EventID 4732 + Administrators | High | 5 min |
| Account → Backup Operators | EventID 4732 + Backup Operators | Medium | 5 min |
| Account creation burst | EventID 4720 > 2 in 10 min | High | 5 min |

> **Note:** Alert rules using EventID **4799** for group additions are incorrect — 4799 is read-only enumeration and fires constantly as noise. Use **4732** for actual membership additions.

**Deployment Note:** Automated rule creation requires Microsoft Sentinel Contributor role. Student account has read-only access to Sentinel Analytics. Rules saved as named queries in Log Analytics workspace (Q14-18 in queries.kql) for manual execution. With these rules active, the 12:30 PM attack would have triggered an alert within 5 minutes.

---

## Lessons Learned

**Key Lesson — Know Your Event IDs Before Drawing Conclusions:**
- 4799 = group membership **read** (enumeration). Windows triggers this automatically after any group change. It is NOT evidence of group manipulation.
- 4732 = member **added** to a group. This is the real addition event.
- Confusing the two led to a completely fabricated "4-wave attack" that never happened.

**Key Lesson — Establish Baseline Before Calling Something Suspicious:**
- 4672 + NT AUTHORITY\SYSTEM + LogonType 5 = normal Windows. It fires dozens of times per hour on any running Windows machine.
- 5379 + virtualapp/didlogical = Windows live token cache read during authentication. Normal.
- Volume alone (70 events in 58 minutes) is not an IOC if the event type is baseline.

**Key Lesson — Time Window Selection Is Critical:**
- The initial 13:00 UTC query window missed the real attack at 12:30:01 PM.
- For unknown intrusion investigations, start the query window well before any suspected activity. Use 12:00 or even 00:00 for a full-day sweep first.

**Key Lesson — Always Pivot to Host:**
- SIEM analysis alone showed 4799 events suggesting group manipulation. PowerShell on the host showed Backup Operators was empty — those events never represented real additions.
- SIEM + host verification together give the true picture.

**What the SIEM Did Well:**
- Captured the real attack events (4720, 4732) with full structured data
- Retained event history long enough to find the 12:30 PM event days later
- Structured SecurityEvent table enabled fast KQL pivoting once the right EventIDs were known

**Key Lesson — Read Subject vs. Member on Group Events:**
- On EventID 4732/4733, **Subject** = who performed the action, **Member** = who was added/removed.
- WKS-L57$ was the Subject (the script ran as SYSTEM = machine account). svc_backup was the Member (the account actually added to Administrators).
- WKS-L57$ was never itself in Administrators — confirmed by `Get-LocalGroupMember` returning no WKS-L57$ entry.
- On 4728: Windows automatically fires this when creating any new local user to assign the default "None" primary group. It is not evidence of a domain group change. Domain-side changes are logged on DC01, which is outside WKS-L57's collection scope.

**What Needs Improvement:**
- No automated alerting — attack ran and was cleaned up before it was detected
- Process tracking — EventID 4688 not collected, so the script that ran at 12:30:01 PM has no parent process trail
- Add `dcr-processcreation` DCR to capture 4688 events for complete process lineage

**Time to Detect (manual, initial wrong window):** Not detected until after coach feedback  
**Time to Detect (manual, corrected window):** Found within first query after widening window  
**Time to Detect with Alert Rules:** Under 5 minutes  

---

## Current Status

**Step 6 Status:** ✅ COMPLETED — INTRUSION DETECTED, CORRECTED, AND DOCUMENTED

**Results:**
- ✅ Real attack timestamp identified: 12:30:01 PM UTC, October 9, 2026
- ✅ Real attack events: EventID 4720 (svc_backup created by WKS-L57$) + 4732 (svc_backup added to Administrators by WKS-L57$)
- ✅ Cleanup confirmed: EventID 4733 on October 12 (coach removed svc_backup from Administrators)
- ✅ Subject/Member distinction clarified: WKS-L57$ was the actor (Subject), svc_backup was the one added (Member) — WKS-L57$ was never itself in Administrators
- ✅ 4728 correctly identified: auto-assigned "None" primary group to new local user, not a domain group addition (DC01 not in scope)
- ✅ False positives identified and explained: 4799, 4672, 5379 = baseline, not IOCs
- ✅ Initial query window error documented and corrected
- ✅ Host verification completed (PowerShell confirms SIEM findings)
- ✅ IOCs corrected (4720 + 4732, not 4799)
- ✅ Alert rules corrected to use 4732 (actual addition) not 4799 (enumeration)

**Overall Assessment:** SIEM infrastructure successfully captured the real attack. Initial analysis was incorrect due to wrong EventID interpretation and a too-narrow query window. Corrected analysis confirmed by host-side verification. Automated alerts using correct EventIDs (4720 + 4732) would detect this attack in under 5 minutes.

---

**Document Last Updated:** October 12, 2026  
**Analyst:** Madumathi  
**Mission Status:** ✅ COMPLETE
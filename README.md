# Mission 01 — Getting Eyes on Your Perimeter

**Analyst:** Madumathi S  
**Date:** October 7–12, 2026  
**Environment:** hamilton.corp Active Directory domain  
**Platform:** Microsoft Sentinel on Azure Log Analytics (log-sentinel-lab)  
**Machine Monitored:** WKS-L57.hamilton.corp (Windows 10, Azure Arc)

---

## What This Mission Covers

Set up a complete SIEM stack on Azure to monitor a Windows 10 workstation on a lab Active Directory network, then use it to detect and investigate an unannounced intrusion by the coach.

---

## Files in This Repository

| File | Description |
|---|---|
| `runbook.md` | Step-by-step setup documentation for the full SIEM infrastructure (Steps 0–6) |
| `detection.md` | Full incident analysis for the Step 6 intrusion — findings, IOCs, SOC response |
| `queries.kql` | All KQL queries used: agent checks, baseline queries, detection queries, and alert rules |
| `README.md` | This file |

---

## What Was Built

| Resource | Name | Region |
|---|---|---|
| Resource Group | `rg-sentinel-lab` | switzerlandnorth |
| Log Analytics Workspace | `log-sentinel-lab` | switzerlandnorth |
| Microsoft Sentinel | Enabled on log-sentinel-lab | switzerlandnorth |
| DCR — General events | `dcr-windowsevents` | switzerlandnorth |
| DCR — Security events | `dcr-securityevents` | switzerlandnorth |

The machine (WKS-L57) was connected via **Azure Arc** with the **Azure Monitor Agent (AMA)**. Two data collection chains were configured:

- **Chain A** (`dcr-windowsevents` → `Event` table): Application and System logs, unstructured text format
- **Chain B** (`dcr-securityevents` → `SecurityEvent` table): Security logs only, pre-structured columns — used for all detection work

---

## What Was Detected

The coach ran an unannounced intrusion on **October 9, 2026 at 12:30:01 PM UTC**.

**Attack summary — 3 events in a single second:**

| EventID | Description | Actor | Target |
|---|---|---|---|
| 4720 | User account created | HAMILTON\WKS-L57$ | svc_backup |
| 4728 | Member added to domain group | HAMILTON\WKS-L57$ | svc_backup |
| 4732 | Member added to Builtin\Administrators | HAMILTON\WKS-L57$ | HAMILTON\WKS-L57$ |

**Cleanup — October 12, 2026 at 7:38 AM UTC:**

| EventID | Description |
|---|---|
| 4733 | WKS-L57$ removed from Builtin\Administrators (coach cleanup) |

The attack was fully automated — no interactive human logon. A machine account (`WKS-L57$`) created a new user (`svc_backup`) and added itself to the local Administrators group in one scripted burst.

---

## Analysis Was Corrected After Initial Errors

The first version of `detection.md` contained several errors, identified through coach feedback and follow-up investigation:

**Error 1 — Wrong EventID for group additions:**  
EventID 4799 is group membership *enumeration* (read-only). The initial report misread 19 instances of 4799 as four waves of group manipulation. In reality, 4799 fires automatically after any group change as Windows reads the updated list. The actual addition event is **4732**. Host verification (PowerShell `Get-LocalGroupMember`) confirmed Backup Operators was empty — no machine account was ever added there.

**Error 2 — Wrong query window:**  
All initial detection queries started at `datetime(2026-10-09T13:00:00Z)`, missing the real attack at 12:30:01 PM UTC. Widening the window to 12:00 UTC immediately revealed the 4720 and 4732 events.

**Error 3 — Baseline events flagged as IOCs:**  
EventID 4672 + SYSTEM + LogonType 5, and EventID 5379 virtualapp/didlogical reads are normal Windows behavior that appears on any running Windows machine. These were incorrectly included in the initial IOC list.

The corrected analysis used **4732** (actual group addition) and **4720** (account creation) as the real attack indicators, verified against host state via PowerShell.

---

## Alert Rules (Saved as Named Queries)

Five alert rules were written and saved to Log Analytics as named queries. Deployment as automated Sentinel analytics rules requires Contributor role (student account is read-only).

| Rule | EventID | Severity |
|---|---|---|
| Machine account creates user | 4720 + actor ends with $ | Critical |
| Machine account → Administrators | 4732 + Administrators + actor ends with $ | Critical |
| Any account → Administrators | 4732 + Administrators | High |
| Account → Backup Operators | 4732 + Backup Operators | Medium |
| Account creation burst | 4720 > 2 in 10 min | High |

With these rules active, the 12:30 PM attack would have triggered an alert within 5 minutes.

---

## Key Lessons

- **4799 ≠ group addition.** 4799 is read-only enumeration. Use 4732 for actual membership additions.
- **Start query windows early.** A 13:00 UTC window missed a 12:30 PM attack. Always sweep from well before suspected activity.
- **Establish baseline before calling something suspicious.** 4672 SYSTEM service logons and 5379 virtualapp reads are normal. Volume alone is not an IOC.
- **Pivot to host.** PowerShell `Get-LocalGroupMember` confirmed the SIEM data and caught the false positive.
- **Machine account in 4720/4732 = immediate IOC.** Machine accounts (ending in `$`) should never create user accounts or add themselves to privileged groups.

---
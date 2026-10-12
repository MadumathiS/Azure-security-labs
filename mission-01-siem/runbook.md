# Mission 01 — Getting Eyes on Your Perimeter: Runbook

## Overview
This runbook documents the setup of a complete SIEM (Security Information and Event Management) infrastructure on Azure for monitoring a Windows 10 workstation on the lab network. The setup includes Azure Arc registration, log collection via Azure Monitor Agent, and Sentinel configuration for security event analysis.

**Completed by:** Madumathi S  
**Date:** October 7-9, 2026  
**Workstation:** WKS-L57 (hamilton.corp)

---

## Step 0: Tailscale Setup
**Status:** ✅ Completed

- Connected to Tailscale VPN on MacBook Air using BeCode school account
- Waited for coach approval of device on the network
- Verified connectivity using `ping <workstation-address>`
- Workstation became reachable on lab network

**Key Learning:** Always verify network connectivity before attempting RDP connection to avoid confusing network timeouts with machine issues.

---

## Step 1: Remote Desktop Connection
**Status:** ✅ Completed

- Downloaded Windows App (formerly Microsoft Remote Desktop) from Mac App Store
- Established RDP connection to workstation at provided address
- Changed initial password on first login
- Successfully accessed Windows 10 desktop environment

**Issues:** None

---

## Step 2: Azure Setup

### 2.0 — Activate Azure for Students
**Status:** ✅ Completed

- Signed into Azure portal with BeCode school account (NOT personal Microsoft account)
- Navigated to Education → Sign up now
- Selected Belgium as country/region (cannot be changed later)
- Used BeCentral campus address: Cantersteen 15, 1000 Brussels
- Confirmed: $100 USD credit available, 365 days remaining

**Critical Warning:** Using a personal Microsoft account instead of BeCode school account results in landing in wrong subscription with no resources visible.

### 2.1 — Find Allowed Regions
**Status:** ✅ Completed

- Accessed Policy → Assignments → "Allowed resource deployment regions"
- Identified allowed regions: switzerlandnorth, germanywestcentral, polandcentral, austriaeast, belgiumcentral
- **Selected:** `switzerlandnorth` (final choice after troubleshooting)

**Issue Encountered:**
- Initially intended to use `belgiumcentral` (preferred for EU data residency)
- Attempted to create Log Analytics workspace in `belgiumcentral`
- Azure rejected deployment with `RequestDisallowedByAzure` error
- Root cause: `belgiumcentral` appeared in policy allowlist but was NOT available in the Log Analytics workspace region dropdown
- **Resolution:** Switched to `switzerlandnorth` which was available in all service dropdowns
- **Lesson:** Allowed regions ≠ available regions in specific service dropdowns. Always test region availability when creating each resource.

### 2.2 — Create SIEM Infrastructure
**Status:** ✅ Completed

Created three resources in **switzerlandnorth** region:

1. **Resource Group:** `rg-sentinel-lab`
   - Standard creation, no issues

2. **Log Analytics Workspace:** `log-sentinel-lab`
   - Region: switzerlandnorth
   - Pricing tier: Pay-as-you-go (Per GB 2018)
   - Standard creation, no issues

3. **Microsoft Sentinel:** Enabled on log-sentinel-lab
   - Free trial automatically activated (31 days, 10 GB/day)
   - After trial: ~19 GB annual budget from $100 credit

### 2.3 — Set Daily Spending Cap
**Status:** ✅ Completed

- Navigated to Log Analytics workspace → Settings → Usage and estimated costs
- Set Daily cap to **On** with value **0.2 GB/day**
- Rationale: Protects $100 Azure credit from runaway costs. 0.2 GB/day is:
  - Far above what a quiet workstation generates
  - Allows ~2 months of continuous use before depleting credit
  - Provides safety net without crippling monitoring

---

## Step 3: Connect Machine to SIEM

### 3.1 — Azure Arc Registration
**Status:** ✅ Completed (with MFA workaround)

**Process:**
1. Generated Arc onboarding script from portal: Azure Arc → Machines → Onboard existing machines
2. Connected to workstation via RDP
3. Opened PowerShell as Administrator
4. Ran: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`
5. Pasted and executed Arc script

**Issue Encountered — MFA Required:**
- Script installed Connected Machine agent successfully
- Then failed with: `RequestDisallowedByAzure` — "without authenticating through MFA"
- Root cause: As of 2025, Azure requires MFA for resource creation. Browser sign-in inside VM doesn't trigger MFA.
- **Resolution:**
  1. Copied device code from PowerShell output
  2. On MacBook (NOT inside VM), opened `https://login.microsoft.com/device`
  3. Signed in with BeCode school account (MFA was triggered by system)
  4. Entered the device code
  5. PowerShell in VM completed with "Machine connected to Azure" message

**Result:**
- Machine WKS-L57 registered in Azure Arc
- Status: **Connected**
- Region: switzerlandnorth

**Key Learning:** MFA errors don't mean the agent failed — agent installed fine. Authentication happened from the VM browser (no MFA), so re-authenticate from your laptop WITH MFA enabled.

### 3.2 — Data Collection Rule (Azure Monitor)
**Status:** ✅ Completed

**Initial Problem — Resources Attachment:**
- Created DCR successfully but forgot to attach machine to Resources
- DCR showed empty Resources list
- Agent would not install without machine attachment
- Error didn't appear until trying to verify installation

**Solution:**
- Returned to DCR → Resources tab
- Clicked "+ Add resources"
- Selected subscription → resource group → ticked WKS-L57
- Clicked Apply

**Final Configuration:**
- Rule name: `dcr-windowsevents`
- Region: switzerlandnorth
- Type: Agent-based - Windows or Linux (most common)
- Resources: WKS-L57
- Data sources: Windows Event Logs
  - Application: Critical, Error, Warning
  - System: Critical, Error, Warning
  - Security: Audit success, Audit failure (later moved to Chain B)
- Destination: `log-sentinel-lab` Log Analytics workspace
- Destination table: `Event` (unstructured, full text)

**Agent Installation:**
- AzureMonitorWindowsAgent extension installed on machine
- Status: Succeeded after ~10 minutes
- Monitored via Azure Arc → Machines → Extensions

---

## Step 4: Verify Logs Are Arriving
**Status:** ✅ Completed

**Query Used:**
```kql
Heartbeat
| take 10
```

**Results:**
- Machine WKS-L57.hamilton.corp sending heartbeats
- Multiple heartbeats on 10/7/2026 starting 10:01 AM
- Agent: Azure Monitor Agent
- OS: Microsoft Windows 10

**Key Learning:** Always check Heartbeat first. If Heartbeat is empty, the problem is connection. If Heartbeat is present, the connection works and data issues are elsewhere.

---

## Step 5: Query Your Data
**Status:** ✅ Completed

Executed four queries to understand data:

**Query 1 — Machine Health:**
```kql
Heartbeat
| summarize LastSeen = max(TimeGenerated) by Computer
```
Result: WKS-L57 last seen at 11:54 AM (current)

**Query 2 — Data Freshness:**
```kql
Heartbeat
| project TimeGenerated, ingestion_time(), Delay = ingestion_time() - TimeGenerated
| take 20
```
Result: Data is current, not delayed

**Query 3 — Event Types:**
```kql
Event
| summarize count() by EventLevelName
```
Result: Shows distribution of Critical/Error/Warning events

**Query 4 — Security Logons (Event Table):**
```kql
Event
| where EventLog == "Security" and EventID == 4624
| project TimeGenerated, Computer, RenderedDescription
| order by TimeGenerated desc
```
Result: Logon events returned, but data embedded in RenderedDescription (unstructured)

---

## Step 5b: SOC-Style Security Event Collection
**Status:** ✅ Completed

### Why Two Collection Chains?

**Chain A (dcr-windowsevents → Event table):**
- Collects any Windows log (Application, System, Security)
- Data arrives as unstructured text
- Requires string parsing in KQL
- Used by IT operations for general monitoring

**Chain B (Sentinel connector → SecurityEvent table):**
- Collects **Security log only**
- Data arrives pre-structured: Account, LogonType, IpAddress, etc.
- Ready for Sentinel detection rules
- Used by security teams/SOC

**The Problem:** Both were collecting the same Security logs = double cost

### Setup Process:

**Attempt 1 — Marketplace Solution:**
- Searched for "Windows Security Events" in Content Hub
- Tried to install via marketplace
- Deployment failed with errors
- **Resolution:** Accessed connector directly from Data Connectors page instead

**Create Data Collection Rule (dcr-securityevents):**
1. Navigated to Sentinel → Configuration → Data connectors
2. Searched for "Windows Security Events via AMA"
3. Clicked "Open connector page"
4. Clicked "+ Create data collection rule"
5. Filled in:
   - Rule name: `dcr-securityevents`
   - Region: switzerlandnorth
   - Resources: WKS-L57
   - Events: **Common** (not "All Security Events")
6. Status: Created and active

**Remove Duplicate from Chain A:**
1. Opened dcr-windowsevents
2. Went to Configuration → Data sources → Windows Event Logs
3. Unchecked Security: Audit success and Audit failure
4. Clicked Save
5. Left Application and System logs intact

**Result:** Security events now collected only once by dcr-securityevents → SecurityEvent table

### Query for SecurityEvent Table:
```kql
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Computer, Account, LogonType, IpAddress
| order by TimeGenerated desc
```

---

## Step 6: Anomalous Activity Detection
**Status:** ✅ Completed (with corrections — see below)

**Overview:** Coach ran unannounced activity on WKS-L57 on October 9, 2026. The attack was detected using KQL queries against the SecurityEvent table in Microsoft Sentinel.

> ⚠️ **Correction:** The initial Step 6 analysis contained errors. See `detection.md` for the corrected full report. The summary below reflects corrected findings.

**Attack Detected:** Unauthorized account creation + privilege escalation  
**Attack Timestamp:** **12:30:01 PM UTC, October 9, 2026** (single automated burst — not 1:09 PM)  
**Detection Method:** Manual KQL investigation (widened query window to 12:00 UTC)  
**Detection Time:** Missed initially due to wrong time window; found after widening

### What Was Detected (Corrected)

**Real attack events (3 events at the same second):**

| EventID | Description | Actor | Target |
|---|---|---|---|
| 4720 | User account CREATED | HAMILTON\WKS-L57$ | svc_backup |
| 4728 | Added to domain group | HAMILTON\WKS-L57$ | svc_backup |
| 4732 | Added to Builtin\Administrators | HAMILTON\WKS-L57$ | HAMILTON\WKS-L57$ |

**Cleanup event:**

| EventID | Description | Time |
|---|---|---|
| 4733 | WKS-L57$ removed from Administrators | Oct 12, 7:38 AM UTC |

**What the initial report got wrong:**

| Wrong Finding | Correct Finding |
|---|---|
| 4-wave group manipulation via 4799 | 4799 is read-only enumeration — fired as noise after real 4732 change |
| Attack window: 1:09 PM – 2:07 PM (58 min) | Real attack: 12:30:01 PM UTC (3 events in 1 second) |
| 4672 SYSTEM logons = IOC | 4672 + SYSTEM + LogonType 5 = normal Windows baseline |
| 5379 virtualapp/didlogical = credential theft | Normal Windows credential cache read — baseline behavior |
| No new accounts created | svc_backup created at 12:30:01 PM — missed because query window started at 13:00 |

### Primary Detection Query (Corrected)
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-10-09T12:00:00Z)
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4720, 4726, 4728, 4732, 4733)
| project TimeGenerated, EventID, Account, TargetAccount, MemberName
| order by TimeGenerated asc
```

See `detection.md` for full incident analysis, IOCs, host verification results, and SOC response steps.  
See `queries.kql` Q8–Q18 for all investigation and corrected alert queries.

---

## Naming Convention Used

| Resource | Name | Pattern |
|---|---|---|
| Resource Group | `rg-sentinel-lab` | Type: rg-, Purpose: sentinel-lab |
| Log Analytics | `log-sentinel-lab` | Type: log-, Purpose: sentinel-lab |
| DCR (Monitor) | `dcr-windowsevents` | Type: dcr-, Purpose: windowsevents |
| DCR (Sentinel) | `dcr-securityevents` | Type: dcr-, Purpose: securityevents |

**All resources in: switzerlandnorth region**

---

## Lessons Learned

1. **Region restrictions are complex.** Allowed regions ≠ available regions in dropdowns.

2. **MFA now required (2025).** VM browser doesn't trigger MFA. Re-authenticate from your laptop with device code flow.

3. **Check Heartbeat first.** It answers 90% of "why no data?" questions.

4. **Attach resources to DCR immediately.** Don't create the rule, then forget to attach machines.

5. **Two chains, one purpose = waste.** Remove the duplicate Security log collection immediately to save costs.

6. **Naming matters.** Type+Purpose naming makes resources discoverable weeks later.

7. **Data structure matters.** Event table requires string parsing; SecurityEvent table has ready-made columns.

8. **Agent installation takes time.** Allow 10-15 minutes after creating a DCR for the agent to appear.

9. **Know your EventIDs before drawing conclusions.** EventID 4799 = group membership *enumerated* (read-only). It fires automatically after any group change and is not evidence of an attack. EventID 4732 = member *added* to a group. Using the wrong EventID led to a fabricated "4-wave attack" that never happened.

10. **Establish baseline before calling something suspicious.** EventID 4672 with NT AUTHORITY\SYSTEM and LogonType 5 fires dozens of times per hour on any running Windows machine. EventID 5379 virtualapp/didlogical reads are normal Windows authentication behavior. Neither is an IOC on its own — both require context and baseline comparison.

11. **Time window selection is critical.** Starting a query at 13:00 UTC missed the real attack at 12:30:01 PM. For unknown intrusion investigations, start the query window well before suspected activity — use 12:00 or even 00:00 for a full-day sweep first.

12. **Always pivot to host for verification.** SIEM analysis alone is not enough. PowerShell on the host (Get-LocalGroupMember) confirmed that Backup Operators was empty — the 4799 events never represented real additions. SIEM + host verification together give the true picture.

13. **Student account limits Sentinel.** Sentinel Contributor role required to deploy automated analytics rules. Save queries manually as a workaround.

14. **PowerShell must be run from PowerShell, not cmd.exe.** `Get-LocalGroupMember` is a PowerShell cmdlet. Running it in cmd.exe gives "not recognized." Type `powershell` in cmd first to switch shells.

---

## Coach Review — October 12, 2026

**Feedback received:**
1. Query window started at 13:00 UTC — may have missed earlier activity
2. EventID 4799 = group membership enumerated (read), not added — 4732 is the addition event
3. 4672 SYSTEM service logons, LogonType 5, and 5379 virtualapp reads are normal baseline
4. Pivot to host: run Get-LocalGroupMember to verify SIEM conclusions

**Action taken:**
1. Widened window to 12:00 UTC → found real attack at 12:30:01 PM
2. Corrected EventID usage throughout — 4732/4720 replace 4799 in all alert rules
3. Removed 4672/5379 from IOC list, added baseline explanation to detection.md
4. Ran PowerShell on WKS-L57 → confirmed Backup Operators empty, Admins cleaned up

## Coach Review — Round 2 (October 12, 2026)

After submitting the corrected detection report, the coach identified one remaining error in the actor/target wording on EventID 4732 and 4733.

**What was wrong:**
The corrected report stated "WKS-L57$ added *itself* to Administrators." This was still incorrect. On EventID 4732, Windows records two separate roles:

- **Subject** = who performed the action → `HAMILTON\WKS-L57$` (the script running as SYSTEM)
- **Member** = who was actually added → `svc_backup`

WKS-L57$ was never *in* Administrators. It was the actor that put svc_backup there. The host check (`Get-LocalGroupMember`) confirmed this — WKS-L57$ never appeared in the output because it was never added.

**What was also clarified:**
- **4733 (cleanup):** Removed `svc_backup` from Administrators, not WKS-L57$.
- **4728:** Windows automatically fires this when any new local user is created, to assign the default "None" primary group. It is not evidence of svc_backup joining a domain group. Any real domain-side group change would be logged on DC01 — outside WKS-L57's collection scope.

**Corrected summary of the attack:**
> SYSTEM (running as WKS-L57$) created local account svc_backup (4720), then added svc_backup to Builtin\Administrators (4732). WKS-L57$ was the actor throughout — never the target.

**Fix applied to:** `detection.md` — event table columns renamed to Subject/Member, attack phases reworded, new key lesson added.

## Current Status

- ✅ Machine registered in Azure Arc
- ✅ Logs flowing into Log Analytics workspace
- ✅ Sentinel SIEM operational
- ✅ Two data collection chains configured (Security consolidated to Chain B)
- ✅ Step 6: Anomalous activity detected, corrected, and documented
- ✅ Initial analysis errors identified and corrected after coach feedback
- ✅ Host verification completed via PowerShell
- ✅ IOCs corrected (4720 + 4732, not 4799)
- ✅ 5 automated alert rules documented with correct EventIDs (saved as named queries)

---

**Mission Status:** ✅ All 6 steps complete.
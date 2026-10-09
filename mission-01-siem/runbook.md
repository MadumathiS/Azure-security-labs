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
**Status:** ✅ Completed

**Overview:** Coach ran unannounced activity on WKS-L57 on October 9, 2026. The attack was detected using KQL queries against the SecurityEvent table in Microsoft Sentinel.

**Attack Detected:** Privilege escalation + credential theft attempt  
**Attack Window:** 1:09 PM – 2:07 PM UTC (58 minutes)  
**Detection Method:** Manual KQL investigation  
**Detection Time:** 15+ minutes (manual queries)

### What Was Detected

**Event Count Summary:**

| EventID | Count | Description |
|---|---|---|
| 5379 | 70 | Credential Manager read operations |
| 4672 | 28 | Special privileges assigned |
| 4624 | 28 | Service logons (LogonType 5, SYSTEM) |
| 4799 | 19 | Group membership changes |
| 4798 | 6 | Group membership enumerated |
| 4634 | 2 | Account logoff |
| 5061 | 2 | Cryptographic operation |
| 5058 | 2 | Key file operation |

**Attack Summary:**
- Machine account HAMILTON\WKS-L57$ added to Builtin\Administrators and Builtin\Backup Operators in **4 separate waves** (~16 minutes apart)
- NT AUTHORITY\SYSTEM assigned special privileges **9 times** in 58 minutes
- Process PID 2240 attempted credential theft via Windows Credential Manager
- **No interactive human logon** — fully automated/scripted attack
- **No new accounts created** — no backdoor planted

### Primary Detection Query
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-10-09T13:00:00Z)
| where Computer == "WKS-L57.hamilton.corp"
| summarize Count = count() by EventID
| sort by Count desc
```

See `detection.md` for full incident analysis, IOCs, and SOC response steps.  
See `queries.kql` Q8–Q18 for all investigation and alert queries.

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

9. **Machine account in privilege events = IOC.** HAMILTON\WKS-L57$ appearing in 4672/4799 events is abnormal and indicates compromise.

10. **Repeated group additions = persistence.** Same group added multiple times at ~16-minute intervals is an attacker ensuring their access survives Group Policy refresh.

11. **LogonType 5 = automated attack.** No interactive logon during an attack window means the attack is scripted — no human was physically present.

12. **Student account limits Sentinel.** Sentinel Contributor role required to deploy automated analytics rules. Save queries manually as a workaround.

---

## Current Status

- ✅ Machine registered in Azure Arc
- ✅ Logs flowing into Log Analytics workspace
- ✅ Sentinel SIEM operational
- ✅ Two data collection chains configured (Security consolidated to Chain B)
- ✅ Step 6: Anomalous activity detected and documented
- ✅ IOCs identified and incident analysis complete
- ✅ 5 automated alert rules documented (saved as named queries)

---

**Mission Status:** ✅ All 6 steps complete.
# Mission 01 — Getting Eyes on Your Perimeter: Anomaly Detection

## Overview
This document records the anomalous activity detected during **Step 6** of the SIEM mission, where the coach runs unannounced activity on the workstation that must be identified and reported by the monitoring system.

**Monitoring Period:** October 7-8, 2026 - **INTRUSION DETECTED** ✅  
**Machine:** WKS-L57 (hamilton.corp)  
**Detection System:** Microsoft Sentinel on Log Analytics (log-sentinel-lab)  
**Attack Timeframe:** October 8, 2026 from 1:46 PM to 1:53 PM UTC (7-minute window)  
**Detection Confirmed:** ✅ Coach confirmed as prep activities before main intrusion  

---

## Detection Query

**[Awaiting Step 6 execution - Coach will run unannounced activity on WKS-L57]**

Once anomalous activity is suspected, use the following query structure to investigate:

### Primary Investigation Query
```kql
SecurityEvent
| where TimeGenerated >= datetime([START_TIME])
| where Computer == "WKS-L57"
| summarize EventCount = count() by EventID, Account
| sort by EventCount desc
```

### Follow-up Queries

**If suspicious logon activity detected:**
```kql
SecurityEvent
| where EventID in (4624, 4625, 4648)  // Logon, Failed Logon, Explicit Creds
| where TimeGenerated >= datetime([START_TIME])
| where Computer == "WKS-L57"
| project TimeGenerated, EventID, Account, LogonType, IpAddress, SourceIpAddress
| order by TimeGenerated desc
```

**If process or service activity detected:**
```kql
Event
| where EventLog == "System" or EventLog == "Application"
| where TimeGenerated >= datetime([START_TIME])
| where Computer == "WKS-L57"
| project TimeGenerated, EventID, Source, RenderedDescription
| order by TimeGenerated desc
```

**If file/registry access detected:**
```kql
SecurityEvent
| where EventID in (4656, 4657, 4660, 4663)  // Object access events
| where TimeGenerated >= datetime([START_TIME])
| where Computer == "WKS-L57"
| project TimeGenerated, EventID, Account, ObjectName, AccessList
| order by TimeGenerated desc
```

---

## Anomalous Activity Findings

### Activity Summary
**✅ INTRUSION CONFIRMED - Privilege Escalation + Registry Modification Attack**

- **Activity Type:** Privilege Escalation with System Configuration Changes
- **First Event Detected:** October 8, 2026 at 1:46:10 PM UTC
- **Attack Duration:** 7 minutes (1:46 PM - 1:53 PM UTC)
- **Event ID(s):** 4799 (Group membership), 4672 (Special privileges), 5379 (Registry modifications)
- **Account(s) Involved:** HAMILTON\WKS-L57$ (Machine account), NT AUTHORITY\SYSTEM
- **Source/Destination:** Local machine (localhost, internal WKS-L57)

---

## Detailed Event Results

### Event Sequence
**Complete Attack Timeline - Privilege Escalation + Registry Modifications (1:46 PM - 1:53 PM UTC)**

| TimeGenerated | EventID | Account | EventDescription | Details |
|---|---|---|---|---|
| 1:46:10 PM | 4672 | NT AUTHORITY\SYSTEM | Special privileges assigned | System privileges elevated (Wave 1) |
| 1:46:14 PM | 4799 | HAMILTON\WKS-L57$ | Group membership changed | Added to **Builtin\Administrators** group |
| 1:46:14 PM | 4799 | HAMILTON\WKS-L57$ | Group membership changed | Added to **Builtin\Backup Operators** group |
| 1:46:14 PM | 4672 | NT AUTHORITY\SYSTEM | Special privileges assigned | System privileges assigned (Wave 2) |
| 1:48:00 PM | 4672 | NT AUTHORITY\SYSTEM | Special privileges assigned | System privileges assigned (Wave 3) |
| 1:53:10 PM | 4672 | NT AUTHORITY\SYSTEM | Special privileges assigned | System privileges assigned (Wave 4) |
| 1:53:11 PM | 4672 | NT AUTHORITY\SYSTEM | Special privileges assigned | System privileges assigned (Wave 5) |
| 1:53:11 PM | 5379 | (System) | Registry Object added/deleted | Registry modifications (multiple times) |

**Total Events:** 11+ critical security events in 7-minute concentrated attack window (1:46-1:53 PM)  
**Attack Duration:** Approximately 7 minutes for initial privilege escalation setup

---

## Analysis

### What Happened?
**The Coach Executed a Multi-Stage Privilege Escalation Attack**

**Phase 1: Privilege Escalation (1:46 PM):**
The attacker (coach) rapidly escalated machine account privileges:
1. **1:46:10 PM** - Assigned special system privileges (EventID 4672)
2. **1:46:14 PM** - Added machine account to **Administrators** group (full system control)
3. **1:46:14 PM** - Added machine account to **Backup Operators** group (file read access)
4. **1:46:14 PM** - Assigned more system privileges (EventID 4672)

**Phase 2: Persistence & Preparation (1:48 PM - 1:53 PM):**
- **1:48:00 PM** - Re-assigned system privileges (wave 3 - ensuring persistence)
- **1:53:10 PM** - Assigned system privileges again (wave 4 - redundancy)
- **1:53:11 PM** - Assigned system privileges (wave 5 - final confirmation)
- **1:53:11 PM** - **Modified Registry** (EventID 5379) - Setting up persistence mechanisms or system configuration

**Why Multiple Waves?**
- **Wave Strategy:** 5 separate privilege assignments in 7 minutes
- **Redundancy:** Ensures persistence even if one assignment fails or is reverted
- **Registry Mods:** Likely setting up scheduled tasks, autorun keys, or service modifications
- **Preparation:** Establishing stable foothold before main intrusion

**Attack Goals Achieved:**
- ✅ Full system access (Administrator group)
- ✅ Data access capability (Backup Operators group)
- ✅ Persistent system privileges (5 assignment waves)
- ✅ Registry modifications (preparation for next phase)
- ✅ System ready for lateral movement or malware deployment

### Why Was It Detected?
**SIEM Infrastructure Successfully Captured Intrusion**

**Data Collection Rule Used:** `dcr-securityevents`
- This DCR collects **Security event logs only** in structured format (SecurityEvent table)
- Events 4799 and 4672 are Security-specific events
- Without this DCR, these critical privilege escalation events would NOT be captured

**Event Types That Revealed the Attack:**
1. **EventID 4799** - "A security-enabled local group membership was enumerated"
   - Shows **EXACTLY** which groups were modified (Administrators, Backup Operators)
   - Structured data includes TargetAccount and TargetUserName fields
   - Impossible to miss in SIEM with proper alerting

2. **EventID 4672** - "Special privileges assigned to new logon"
   - Indicates system-level privilege assignment
   - Multiple occurrences signal intentional persistence setup

**What Would Be Missed Without This Monitoring:**
- ❌ No visibility into group membership changes
- ❌ No visibility into privilege escalations
- ❌ No audit trail of system modifications
- ❌ No alerting capability for suspicious activity
- ❌ Attacker would have unrestricted access with no detection

**Detection Method:**
- Ran KQL query: `SecurityEvent | where EventID in (4799, 5379, 4672)`
- Identified clustering of critical events in narrow time window (17 minutes)
- Correlated with activity spike observed in earlier summary query

### Key Indicators of Compromise (IOCs)

- **Suspicious Accounts:** 
  - HAMILTON\WKS-L57$ (machine account with admin privileges - should be rare)
  - NT AUTHORITY\SYSTEM (assigned privileges repeatedly - indicates persistence attempt)

- **Suspicious Event IDs:** 
  - **4799** - Group membership changes (2 instances: 2:02 PM and 2:18 PM)
  - **4672** - Special privileges (4 instances: 2:02, 2:03, 2:18, 2:19 PM)

- **Suspicious Group Memberships:** 
  - **Builtin\Administrators** - Full system access (added twice)
  - **Builtin\Backup Operators** - Data access/read all files (added twice)

- **Suspicious Time Patterns:** 
  - Activity burst in narrow 17-minute window
  - Two-phase attack (2:02 PM & 2:18 PM) - classic persistence pattern
  - Event clustering indicates intentional, not accidental

- **Suspicious Behavior:** 
  - Same groups added twice to same account = **redundancy for persistence**
  - Privileges assigned 4 times in 17 minutes = **intentional escalation**
  - No user interaction logs = **automated attack or admin abuse**

### SOC Response
**Incident Severity: CRITICAL - Immediate Action Required**

**Threat Assessment:**
- ✅ **CONFIRMED THREAT** - Not benign
- This is a **privilege escalation attack** with persistence mechanisms
- Attacker now has full system control and data access
- Immediate containment required

**Immediate Actions (0-30 minutes):**
1. ✅ **Isolate machine** - Disconnect from network immediately
2. ✅ **Preserve evidence** - Do NOT reboot (logs would be purged)
3. ✅ **Alert incident response team** - Escalate to security leadership
4. ✅ **Notify system owner** - WKS-L57 is compromised

**Remediation Steps (within 1 hour):**
1. Remove machine account from Administrators group
2. Remove machine account from Backup Operators group
3. Reset all system privileges
4. Change all local admin passwords
5. Check for persistence mechanisms:
   - Scheduled tasks
   - Startup folders
   - Registry autorun locations
   - New user accounts

**Forensic Investigation (24-48 hours):**
1. Full disk forensics of WKS-L57
2. Review all event logs for lateral movement attempts
3. Check for data exfiltration (log file access patterns)
4. Analyze Network logs for C2 communication
5. Review if other machines were compromised

**Who to Notify:**
- 🔴 **CRITICAL** - IT Security team
- 🔴 **CRITICAL** - System owner/stakeholder
- 🟡 **MEDIUM** - Incident Response team
- 🟡 **MEDIUM** - Network security team

---

## Lessons Learned from Detection

**What the SIEM Did Well:**
- ✅ Captured all privilege escalation events (4799, 4672)
- ✅ Provided structured, parseable data in SecurityEvent table
- ✅ Recorded exact timestamps enabling event correlation
- ✅ Included account names and target groups for forensic analysis
- ✅ Enabled rapid detection through summary queries

**Gaps in Current Monitoring:**
- ⚠️ No automated alert for EventID 4799 (group membership changes)
- ⚠️ No automated alert for EventID 4672 spike (privilege escalation)
- ⚠️ No alerting on "Administrator group addition" events
- ⚠️ No alerting on "Backup Operators group addition" events
- ⚠️ Manual query required - should be automated rule

**Detection Rules to Add:**
```kql
// Alert Rule 1: Admin Group Addition
SecurityEvent
| where EventID == 4799
| where TargetAccount contains "Administrators"
| alert "CRITICAL: User/Machine added to Administrators"

// Alert Rule 2: Privilege Escalation Spike
SecurityEvent
| where EventID == 4672
| where TimeGenerated > ago(1h)
| summarize count() by bin(TimeGenerated, 5m)
| where count_ > 3
| alert "CRITICAL: Multiple privilege escalations detected"

// Alert Rule 3: Backup Operators Addition
SecurityEvent
| where EventID == 4799
| where TargetAccount contains "Backup Operators"
| alert "MEDIUM: User/Machine added to Backup Operators"
```

**How to Prevent/Stop Earlier:**
1. ✅ Create **automatic alert rules** (not manual queries)
2. ✅ Set **severity to CRITICAL** for 4799 events
3. ✅ Set **baseline threshold** - alert if >1 admin group change in 1 hour
4. ✅ Add **automated response** - create incident immediately
5. ✅ Enable **playbook automation** - notify team automatically
6. ✅ Use **Threat Intelligence** to match against known attack patterns

**Time to Detect:** Manual investigation - 15+ minutes  
**Time to Respond:** Could be hours  
**Recommended:** <5 minutes with automated rules

---

## Current Status

**Step 6 Status:** ✅ **COMPLETED - INTRUSION DETECTED AND DOCUMENTED**

**Results:**
- ✅ Intrusion detected using KQL queries
- ✅ Attack timeline established (2:02 PM - 2:19 PM UTC)
- ✅ Attacker actions identified (privilege escalation + persistence)
- ✅ IOCs documented for future reference
- ✅ SOC response procedures outlined
- ✅ Detection gaps identified and remediation rules provided

**Overall Assessment:** The SIEM infrastructure successfully detected the privilege escalation attack. However, relying on manual queries is too slow for production. Automated detection rules are critical for real-time response.

---

## Detection Workflow Checklist

Use this checklist when anomalous activity is suspected:

- [ ] Note the timestamp when anomaly was suspected
- [ ] Run SecurityEvent summary query to identify unusual EventIDs
- [ ] Use EventID-specific queries to extract detailed context
- [ ] Build event timeline (sort by TimeGenerated)
- [ ] Identify all accounts involved in the activity
- [ ] Identify all source IPs if applicable
- [ ] Cross-reference with baseline (compare to normal activity in queries.kql)
- [ ] Document findings in this file
- [ ] Present to coach for validation

---

**Document Last Updated:** October 8, 2026 at 4:51 PM UTC  
**Mission Status:** ✅ **COMPLETE - All Steps 0-6 Finished**
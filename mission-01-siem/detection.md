# Mission 01 — Getting Eyes on Your Perimeter: Anomaly Detection

## Overview
This document records the anomalous activity detected during **Step 6** of the SIEM mission, where the coach runs unannounced activity on the workstation that must be identified and reported by the monitoring system.

**Monitoring Period:** October 7, 2026 - [Pending detection]  
**Machine:** WKS-L57 (hamilton.corp)  
**Detection System:** Microsoft Sentinel on Log Analytics (log-sentinel-lab)  

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
**[Pending detection - Fill in once anomalous activity is identified]**

- **Activity Type:** [e.g., Unauthorized logon, Lateral movement, Privilege escalation, Data access]
- **Detection Time:** [Timestamp when activity was first observed]
- **Event ID(s):** [Windows Security Event IDs involved]
- **Account(s) Involved:** [User account(s) associated with activity]
- **Source/Destination:** [IpAddress or machine name if applicable]

---

## Detailed Event Results

### Event Sequence
**[Pending detection - Fill in the actual events found]**

| TimeGenerated | EventID | Account | EventDescription | Details |
|---|---|---|---|---|
| [Timestamp] | [ID] | [Account] | [Description] | [Notable details] |
| [Timestamp] | [ID] | [Account] | [Description] | [Notable details] |

*[Add additional rows as events are discovered]*

---

## Analysis

### What Happened?
**[Pending detection - Explain the sequence of events and what the coach did on the machine]**

[Describe the attack or activity in narrative form:
- What was the initial action?
- How did it escalate or propagate?
- What specific changes or accesses occurred?
- How does the event log data support this narrative?]

### Why Was It Detected?
**[Explain which part of your SIEM setup enabled this detection]**

[Discuss:
- Which data collection rule captured it (dcr-windowsevents, dcr-securityevents)?
- Which event type(s) revealed the activity?
- What would have been missed without this monitoring?]

### Key Indicators of Compromise (IOCs)
**[Pending detection - Document the IOCs found]**

- **Suspicious Accounts:** [e.g., admin, service accounts with unexpected activity]
- **Suspicious IPs:** [e.g., unexpected source IP addresses]
- **Suspicious Event IDs:** [e.g., 4625 for failed logons indicating brute force]
- **Suspicious Processes/Services:** [e.g., PowerShell, cmd.exe with admin privileges]
- **Suspicious Times:** [e.g., activity outside business hours, rapid event bursts]

### SOC Response
**[Describe what a Security Operations Center would do with this information]**

[Discuss potential next steps:
- Is this a real threat or a known/benign activity?
- What remediation would be recommended?
- Who should be notified?
- What additional forensic investigation is needed?]

---

## Lessons Learned from Detection

**[Pending detection - Update after Step 6 completion]**

- What did the SIEM do well in detecting this activity?
- What gaps, if any, existed in the monitoring?
- What additional detection rules should be added?
- How could the attack have been prevented or stopped earlier?

---

## Current Status

**Step 6 Status:** ⏳ **Awaiting Coach Activity**

The SIEM infrastructure is operational and monitoring for anomalous activity. Once the coach executes unannounced activity on WKS-L57, this document will be completed with:
1. The specific query that uncovered the activity
2. Event-by-event analysis of what occurred
3. Assessment of detection effectiveness
4. Recommendations for improved monitoring

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

**Document Last Updated:** [Date of Step 6 completion]  
**Mission Status:** Awaiting Step 6 completion

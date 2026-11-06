# BeCode Cybersecurity Lab — SIEM Portfolio

**Analyst:** Madumathi S  
**Environment:** hamilton.corp Active Directory domain  
**Platform:** Microsoft Sentinel on Azure Log Analytics (log-sentinel-lab)  
**Machine:** WKS-L57.hamilton.corp (Windows 10, Azure Arc)

---

## Repo Structure

```
.
├── README.md
├── mission-01-siem/
│   ├── detection.md       # Incident analysis, IOCs, SOC response (corrected)
│   ├── queries.kql        # KQL queries: agent checks, baseline, detection, alerts
│   └── runbook.md         # Step-by-step SIEM setup (Steps 0–6)
├── mission-02-intrusion/
│   ├── case-file.md       # Full investigation: auth story, MITRE mapping, IOCs
│   ├── queries.kql        # Warm-up, hunt, gap, post-policy, alert rule queries
│   └── runbook.md         # Step-by-step investigation walkthrough (Parts 1–4)
├── mission-03-locked-out/
│   ├── case-file.md       # GPP credential recovery, breach assessment, ATT&CK mapping
│   ├── queries.kql        # KQL queries: failed logons, SMB access, re-entry, full timeline
│   └── runbook.md         # Step-by-step recovery walkthrough (Parts 1–4)
└── mission-04-service-account/
    ├── dfir-report.md     # DFIR report: service account takeover, staged data, persistence
    └── queries.kql        # KQL queries: batch logons, discovery, staging, scheduled tasks, post-containment check
```

---

## Missions

### Mission 01 — Getting Eyes on Your Perimeter
**Status:** ✅ Complete  
**Folder:** `mission-01-siem/`

Set up a complete SIEM stack on Azure to monitor a Windows 10 workstation, then detected and investigated an unannounced intrusion run by the coach.

**What was built:** Azure Arc registration, Azure Monitor Agent, two Data Collection Rules (dcr-windowsevents, dcr-securityevents), Microsoft Sentinel.

**What was detected:** Machine account HAMILTON\WKS-L57$ created a user (svc_backup) and added itself to Builtin\Administrators at 12:30:01 PM UTC on October 9, 2026 — three events in a single automated second.

**Key lesson:** EventID 4799 is group membership *enumeration* (read-only), not addition. EventID 4732 is the real addition event. Initial analysis incorrectly flagged 4799 as a 4-wave attack; corrected after coach review and host verification via PowerShell.

| File | Description |
|---|---|
| `detection.md` | Full incident analysis, IOCs, SOC response, corrected findings |
| `queries.kql` | All KQL queries: agent checks, baseline, detection, alert rules |
| `runbook.md` | Step-by-step SIEM setup documentation (Steps 0–6) |

---

### Mission 02 — Your First Intrusion
**Status:** ✅ Complete  
**Folder:** `mission-02-intrusion/`

Detected and reconstructed a real RDP brute-force intrusion on WKS-L57 using Sentinel and host forensics. Covers the full authentication story, the logging gap with default settings, and recovery of attacker artifacts from disk.

**What was found:** Attacker used account `helpdesk` from `10.50.0.100`, made 8 failed RDP attempts then succeeded at 12:39:05 UTC. Default logging showed the login but not the commands run. Proof of access (`HAM{redacted}`) was recovered from `C:\Users\helpdesk\Desktop\flag.txt` using an elevated command prompt — invisible to Sentinel without Audit Process Creation (EventID 4688) enabled.

| File | Description |
|---|---|
| `case-file.md` | Full investigation: auth story, MITRE mapping, IOCs, logging gap analysis |
| `queries.kql` | KQL warm-up, hunt, gap check, post-policy, and alert rule queries |
| `runbook.md` | Step-by-step walkthrough of all 4 parts including disk forensics |

---

### Mission 03 — Locked Out
**Status:** ✅ Complete  
**Folder:** `mission-03-locked-out/`

Capstone penetration-testing exercise. The analyst's own account was locked out of WKS-L57 and Sentinel by a simulated intruder. Recovery required enumerating the domain's Group Policy infrastructure with a low-privilege account, locating a stored credential left in SYSVOL via the MS14-025 Group Policy Preferences vulnerability, decrypting it, and using it to regain local administrator access to the workstation.

**What was found:** A per-seat GPP item in SYSVOL (GPO `{BAFE699E}` for WKS-L57) containing a `cpassword` field for a local `svc_deploy` account — encrypted with the publicly known AES key from MS14-025, decryptable by any domain user. The account was configured with `RID_ADMIN` group membership, giving local administrator rights on workstations. Additionally, `\\WKS-L57\Public` contained a plaintext credential file staged by the intruder, constituting a data breach of internal account credentials. A staged CSV of employee records on the `svc_deploy` desktop added personal-data exposure. The domain account `madumathi` was disabled during the lockout; that domain-side event is outside workstation monitoring and is recorded as a control gap.

**Key lesson:** GPP cpassword is a dead vulnerability that should have been removed from every domain after MS14-025 in 2014. Any domain user with SYSVOL read access can recover any password stored this way. LAPS replaces it correctly.

| File | Description |
|---|---|
| `case-file.md` | GPP recovery chain, MITRE ATT&CK mapping, control gaps, data breach assessment |
| `queries.kql` | KQL queries: failed logons, anonymous SMB, svc_deploy re-entry, intruder activity, full timeline |
| `runbook.md` | Step-by-step recovery walkthrough: share enumeration, GPP decryption, password change, Sentinel evidence |

---

### Mission 04 — A service account goes rogue
**Status:** 🔄 In progress  
**Folder:** `mission-04-service-account/`

Investigated a service account (`svc-app57`) used on WKS-L57 during a coach-set window. The account ran discovery commands, staged a customer file on the public desktop, and created two scheduled tasks for persistence. The root cause is reasoned to be Kerberoasting of the account's SQL Server SPN, since the domain-side ticket request is not visible from the workstation.

**What was found:** The first task ran once at 13:41 UTC to stage the data. The second repeats every 15 minutes and was still active on 2 November. On 4 November both tasks were still registered, and Sentinel showed `svc-app57` batch logons continuing until 09:26 UTC on 6 November (query 1a), so the intruder was inside until then. Containment: both tasks removed on WKS-L57, and the account disabled and reset by the identity team at 10:33 UTC on 6 November 2026. Sentinel confirmed no successful logons after the disable. Removing the staged data is pending the coach's review of the report, and it will be logged as an eradication step.

**Key lesson:** A service account with an SPN can be cracked offline by any domain user. Use group managed service accounts, and alert on scheduled tasks created by SYSTEM for user accounts.

**Part 2:** Reproduced the Kerberoasting path against my own seat's account from my laptop, recovered its password offline, and signed on to my workstation. Section 6 of the report maps each step to what the workspace could and could not see.

| File | Description |
|---|---|
| `dfir-report.md` | DFIR report: kill chain, MITRE ATT&CK mapping, impact, evidence, containment, remediation, Part 2 attack path |
| `queries.kql` | KQL queries: batch logons, discovery, payload, scheduled tasks, post-containment check |

---

## Key Lessons Across Missions

- **Know your EventIDs.** 4799 = enumeration (read). 4732 = actual group addition. 4625 = failed logon. 4624 = successful logon. 4688 = process created.
- **One RDP login = two 4624 events.** LogonType 3 (network auth) + LogonType 10 (desktop session). Never double-count.
- **Start query windows wide.** A 13:00 UTC window missed a 12:30 PM attack in Mission 01.
- **Filter your own noise first.** Exclude your own IP before hunting — makes the attacker's traffic immediately visible.
- **Establish baseline before calling something suspicious.** SYSTEM service logons (4672, LogonType 5) and virtualapp/didlogical reads (5379) are normal Windows behavior.
- **Pivot to host.** SIEM + filesystem together give the true picture. Sentinel showed the login; elevated cmd revealed the flag file.
- **Default logging has gaps.** Authentication is visible by default; what the attacker *did* after login requires Audit Process Creation (EventID 4688) to be explicitly enabled.
- **Admin rights matter for forensics.** NTFS permissions protect user profiles — investigating another user's Desktop requires running as local Administrator.
- **SYSVOL is world-readable.** Every domain user can enumerate Group Policy files. Any credential stored in GPP (cpassword) is recoverable by any authenticated domain user in minutes.
- **MS14-025 is still live in the wild.** GPP password entries from pre-2014 deployments often survive domain migrations and cleanups. Always audit SYSVOL for cpassword fields before declaring a domain clean.
- **Service accounts leave a pattern, not a failure.** A service account that logs on as a batch job (LogonType 4) every 15 minutes is automation, not a person. Regular timing is the signal.
- **Kerberoasting leaves no logon trail on the workstation.** The ticket request (EventID 4769) is logged on the domain controller, so you need DC logs to see it. Without them, write the root cause as reasoned.
- **A password reset breaks persistence but doesn't remove it.** A scheduled task logs on with the password stored in it. After a reset that logon fails, but the task stays registered, and anyone with local admin can store a new password and restart it. Remove the tasks first, then reset the account.
- **"Created by SYSTEM" doesn't mean benign.** Check what a scheduled task runs, and as whom, before you dismiss it.
- **Normalise time zones before comparing sources.** Sentinel shows UTC, and `schtasks` shows local time. Convert both to UTC before you match them.
- **Check who made a change before you call it an attack.** A task deletion and re-creation at 14:56 UTC looked like persistence being rebuilt, but it was the analyst's own OneDrive update task. Check `SubjectUserName` and `TaskName` first.
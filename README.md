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
└── mission-02-intrusion/
    ├── case-file.md       # Full investigation: auth story, MITRE mapping, IOCs
    ├── queries.kql        # Warm-up, hunt, gap, post-policy, alert rule queries
    └── runbook.md         # Step-by-step investigation walkthrough (Parts 1–4)
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

**What was found:** Attacker used account `helpdesk` from `10.50.0.100`, made 8 failed RDP attempts then succeeded at 12:39:05 UTC. Default logging showed the login but not the commands run. Proof of access (`HAM{rdp_pwned_seat57}`) was recovered from `C:\Users\helpdesk\Desktop\flag.txt` using an elevated command prompt — invisible to Sentinel without Audit Process Creation (EventID 4688) enabled.

| File | Description |
|---|---|
| `case-file.md` | Full investigation: auth story, MITRE mapping, IOCs, logging gap analysis |
| `queries.kql` | KQL warm-up, hunt, gap check, post-policy, and alert rule queries |
| `runbook.md` | Step-by-step walkthrough of all 4 parts including disk forensics |

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
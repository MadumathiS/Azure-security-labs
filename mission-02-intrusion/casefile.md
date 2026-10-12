# Mission 02 — Your First Intrusion: Case File

**Analyst:** Madumathi S  
**Date:** October 12, 2026  
**Machine:** WKS-L57.hamilton.corp  
**Environment:** hamilton.corp domain | Log Analytics workspace: log-sentinel-lab  
**Attack Window:** 2026-10-12T00:00:00Z – 2026-10-12T23:59:00Z UTC

---

## Summary

An intrusion was detected on WKS-L57.hamilton.corp during the window above. The attacker used a password-guessing (brute-force) attack via Remote Desktop Protocol (RDP) to gain access, then executed a command on the machine. The attack was partially visible with default logging; full command visibility required a process creation logging policy change.

---

## Part 1 — Warm-Up: My Own Footprint (labuser)

Before hunting the real intrusion, I logged in as `.\labuser` to see what a login leaves in the logs.

**What I did:**
- Made 3 failed login attempts (wrong password)
- Made 1 successful login (correct password)
- Ran `whoami`
- Signed out properly

**What I found in Sentinel:**

| EventID | Count | Description |
|---|---|---|
| 4625 | 3 | Failed logon attempts (wrong password) |
| 4624 | 2 | Successful logon (LogonType 3 network auth + LogonType 10 RDP desktop) |

**Key observation:** One RDP login produces two 4624 events — LogonType 3 (network auth) then LogonType 10 (desktop session). Don't count these as two separate logins.

**My source IP:** 10.50.0.1

---

## Part 2 — The Real Intrusion

### Authentication Story

The attacker targeted the `helpdesk` account on WKS-L57 using RDP.

**Pattern detected:** 8 failed 4625 events followed by a successful 4624 — classic brute-force shape.

| Time (UTC) | EventID | Description | Source IP |
|---|---|---|---|
| 2026-10-12T12:38:xx | 4625 | Failed logon | 10.50.0.100 |
| 2026-10-12T12:38:xx | 4625 | Failed logon | 10.50.0.100 |
| 2026-10-12T12:38:xx | 4625 | Failed logon | 10.50.0.100 |
| 2026-10-12T12:38:xx | 4625 | Failed logon | 10.50.0.100 |
| 2026-10-12T12:38:xx | 4625 | Failed logon | 10.50.0.100 |
| 2026-10-12T12:38:xx | 4625 | Failed logon | 10.50.0.100 |
| 2026-10-12T12:38:xx | 4625 | Failed logon | 10.50.0.100 |
| 2026-10-12T12:38:xx | 4625 | Failed logon | 10.50.0.100 |
| 2026-10-12T12:39:05 | 4624 | **Successful logon** | 10.50.0.100 |

**Total failed attempts before success:** 8

### Answers (CTFd flags)

| Question | Answer | Flag |
|---|---|---|
| Which account was used to get in | `helpdesk` | HAM{helpdesk} ✅ |
| Where the connection came from | `10.50.0.100` | HAM{10.50.0.100} ✅ |
| What kind of attack this was | Password brute-force via RDP | HAM{brute_force} ✅ |
| Proof of access (file left by attacker) | flag.txt on helpdesk Desktop | HAM{rdp_pwned_seat57} ✅ |

**Proof of access:** The attacker dropped `flag.txt` (content: `HAM{rdp_pwned_seat57}`) on `C:\Users\helpdesk\Desktop\` at 14:39 UTC, confirming they had an interactive desktop session as the helpdesk user. The file was only accessible by running an elevated command prompt as administrator.

### How I Found It

```kql
// Step 1 — broad sweep for logon events in attack window
SecurityEvent
| where TimeGenerated between (datetime(2026-10-12T00:00:00Z) .. datetime(2026-10-12T23:59:00Z))
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4624, 4625)
| where IpAddress != "10.50.0.1"  // filter out my own IP
| summarize Count = count() by EventID, TargetUserName, IpAddress
| sort by Count desc

// Step 2 — read the story in time order
SecurityEvent
| where TimeGenerated between (datetime(2026-10-12T00:00:00Z) .. datetime(2026-10-12T23:59:00Z))
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4624, 4625)
| where TargetUserName == "helpdesk"
| sort by TimeGenerated asc
| project TimeGenerated, EventID, IpAddress, LogonType
```

// Step 3 — confirmed successful logon details (TargetLogonId: 0x8413e5d, LogonProcess: User32)
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-10-12T00:00:00Z) .. datetime(2026-10-12T23:59:00Z))
| where Computer == "WKS-L57.hamilton.corp"
| where EventID == 4624
| where TargetUserName == "helpdesk"
| where LogonType == 10
| project TimeGenerated, TargetUserName, IpAddress, LogonType, TargetLogonId, WorkstationName, LogonProcessName
```

---

## Part 3 — The Gap (Default Logging)

**Question:** What command did the attacker run once inside?

**Result:** No results. Default logging does not capture process creation (EventID 4688 was not enabled). The SIEM could see the login but not what happened after the attacker's session started.

**Why:** Windows only logs process creation events (4688) if the "Audit Process Creation" policy is explicitly enabled. With default settings, an attacker can run any command after logging in and leave no trace in the Security event log.

---

## Part 4 — After the Policy Change

After the coach enabled process creation logging (Audit Process Creation policy → EventID 4688), the intrusion was replayed.

**Proof found on disk:** `C:\Users\helpdesk\Desktop\flag.txt` — content: `HAM{rdp_pwned_seat57}`  
Created at 2026-10-12T14:39 UTC by the attacker's helpdesk session.

**Note:** The file was not visible via EventID 4688 in Sentinel (Part 4 policy replay pending coach confirmation). The file was recovered directly from disk using an elevated command prompt (`cmd` as Administrator), confirming the attacker had write access to the helpdesk Desktop during their RDP session.

**EventID 4688 details (to be completed after coach enables policy and replays attack):**

| Field | Value |
|---|---|
| Time | [pending Part 4 replay] |
| Account | helpdesk |
| Process | [pending] |
| Command line | `[pending]` |
| Parent process | [pending] |

### How I Found It (disk forensics)

```cmd
:: Elevated cmd as Administrator
dir C:\Users\helpdesk\Desktop\
type C:\Users\helpdesk\Desktop\flag.txt
```

### KQL Query (for Part 4 replay once policy enabled)

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-10-12T00:00:00Z) .. datetime(2026-10-12T23:59:00Z))
| where Computer == "WKS-L57.hamilton.corp"
| where EventID == 4688
| where SubjectUserName == "helpdesk"
| project TimeGenerated, SubjectUserName, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated asc
```

---

## Before vs. After: Logging Gap

| What | Default logging | After policy change |
|---|---|---|
| Failed logins (4625) | ✅ Visible | ✅ Visible |
| Successful login (4624) | ✅ Visible | ✅ Visible |
| Source IP | ✅ Visible | ✅ Visible |
| Command run by attacker | ❌ Not logged | ✅ Visible (4688) |
| Process that ran the command | ❌ Not logged | ✅ Visible (4688) |

**Lesson:** Default Windows logging tells you *someone got in* but not *what they did*. Process creation logging (4688) is the difference between knowing an attacker entered and knowing what they touched.

---

## MITRE ATT&CK Mapping

| Phase | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Brute Force: Password Guessing | T1110.001 | 8 failed 4625 events then successful 4624 for helpdesk from 10.50.0.100 |
| Initial Access | External Remote Services (RDP) | T1133 | LogonType 10, LogonProcess User32, source 10.50.0.100 |
| Impact / Persistence | File dropped on Desktop | — | flag.txt created on helpdesk Desktop at 14:39 UTC, proving interactive access |

---

## IOCs

| Type | Value |
|---|---|
| Source IP | 10.50.0.100 |
| Account targeted | helpdesk |
| Logon type | 10 (RDP / RemoteInteractive) |
| Session LogonId | 0x8413e5d |
| File dropped by attacker | C:\Users\helpdesk\Desktop\flag.txt |
| Flag content | HAM{rdp_pwned_seat57} |

---

## What My Monitoring Missed (and Why)

With default logging, Sentinel showed the attacker got in (EventID 4624) but nothing about what they did afterward. The flag file written to the helpdesk Desktop was invisible in the SIEM until I checked the filesystem directly with an elevated command prompt — a reminder that logs alone don't tell the full story without process creation auditing (EventID 4688) enabled.

---

**Document Last Updated:** 2026-10-12  
**Analyst:** Madumathi  
**Mission Status:** ✅ Complete (pending GitHub push)
# Mission 02 — Your First Intrusion: Runbook

**Analyst:** Madumathi S  
**Date:** October 12, 2026  
**Machine:** WKS-L57.hamilton.corp  
**Workspace:** log-sentinel-lab (Microsoft Sentinel on Azure)

---

## Overview

This runbook documents the step-by-step process used to detect, investigate, and reconstruct a real RDP brute-force intrusion on WKS-L57. The mission is split into four parts: understanding your own footprint, hunting the real intrusion, discovering what default logging misses, and finding the attacker's actions after enabling process creation logging.

---

## Step 0 — Prerequisites

Before starting:

- RDP access to WKS-L57.hamilton.corp (via Tailscale)
- Log in as `HAMILTON\madumathi` (domain account)
- Microsoft Sentinel open in Azure portal (log-sentinel-lab workspace)
- Local admin rights on WKS-L57 (needed for Part 4 disk check)
- CTFd open at `http://10.50.0.240:8000`

---

## Part 1 — Warm-Up: Establish Your Own Footprint

**Goal:** Before hunting the attacker, understand what a normal RDP login looks like in Sentinel.

### Step 1 — Log in as labuser via RDP

1. Open Remote Desktop Connection
2. Connect to `WKS-L57.hamilton.corp`
3. Log in as `.\labuser` (local account — note the `.\` prefix)
4. Enter the **wrong** password 3 times deliberately
5. Enter the correct password and log in successfully
6. Open cmd and run `whoami`
7. Sign out cleanly (Start → Sign out)

### Step 2 — Query Sentinel for your footprint

Open Sentinel → Logs and run:

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where TargetUserName == "labuser"
| where EventID in (4624, 4625)
| sort by TimeGenerated asc
| project TimeGenerated, EventID, IpAddress, LogonType
```

**What to look for:**
- 3 × EventID 4625 (failed logons) — your deliberate wrong passwords
- 2 × EventID 4624 (successful logons) — **one RDP login always produces two 4624 events**:
  - LogonType 3 (network authentication)
  - LogonType 10 (RemoteInteractive — the actual desktop session)
- Your source IP in the IpAddress field

**Key lesson:** One RDP login = two 4624 events. Don't double-count.

**Results from this investigation:**
- Source IP: `10.50.0.1`
- Failed attempts: 3 (4625)
- Successful logons: 2 (4624 — LogonType 3 + LogonType 10)

---

## Part 2 — Hunt the Real Intrusion

**Goal:** Find the attacker's account, source IP, and confirm the attack technique.

### Step 3 — Broad sweep for all logon events

Run a wide query across the full day, excluding your own IP:

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-10-12T00:00:00Z) .. datetime(2026-10-12T23:59:00Z))
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4624, 4625)
| where IpAddress != "10.50.0.1"
| summarize Count = count() by EventID, TargetUserName, IpAddress
| sort by Count desc
```

**What to look for:** An account you don't recognise with many 4625 failures and a 4624 success, from an IP that is not yours.

**Result:** `helpdesk` account, `10.50.0.100`, 8 failures + 1 success.

### Step 4 — Read the attack story in time order

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-10-12T00:00:00Z) .. datetime(2026-10-12T23:59:00Z))
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4624, 4625)
| where TargetUserName == "helpdesk"
| sort by TimeGenerated asc
| project TimeGenerated, EventID, IpAddress, LogonType
```

**Pattern:** 8 × 4625 in rapid succession → 4624 success at 12:39:05 UTC. Classic brute-force shape.

### Step 5 — Confirm successful logon details

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-10-12T00:00:00Z) .. datetime(2026-10-12T23:59:00Z))
| where Computer == "WKS-L57.hamilton.corp"
| where EventID == 4624
| where TargetUserName == "helpdesk"
| where LogonType == 10
| project TimeGenerated, TargetUserName, IpAddress, LogonType, TargetLogonId, WorkstationName, LogonProcessName
```

**Result:**
- Time: 2026-10-12T12:39:05Z
- Source IP: 10.50.0.100
- LogonType: 10 (RDP)
- LogonProcess: User32 (confirms interactive desktop session)
- TargetLogonId: 0x8413e5d

### Step 6 — Submit CTFd flags

| Challenge | Flag |
|---|---|
| M2 — Compromised account | HAM{helpdesk} |
| M2 — Attack source | HAM{10.50.0.100} |
| M2 — Attack technique | HAM{brute_force} |

---

## Part 3 — Document the Logging Gap

**Goal:** Try to find what command the attacker ran — and discover you can't.

### Step 7 — Search for process creation events

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-10-12T00:00:00Z) .. datetime(2026-10-12T23:59:00Z))
| where Computer == "WKS-L57.hamilton.corp"
| where EventID == 4688
| project TimeGenerated, SubjectUserName, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated asc
```

**Result:** No results.

**Why:** EventID 4688 (Process Creation) is not logged by default. Windows only writes these events if the **Audit Process Creation** policy is explicitly enabled via Group Policy or Local Security Policy. With default settings, the SIEM shows that someone logged in but not a single command they ran.

**Lesson documented:** Default logging confirms access but not actions. An attacker can run any command after RDP login and leave no trace in the Security event log without this policy.

---

## Part 4 — Find the Attacker's Proof of Access

**Goal:** Recover the file the attacker left on the machine proving they had a live session.

### Step 8 — Search the filesystem for attacker artifacts

Since 4688 logs were unavailable, pivot to the filesystem directly.

Open **cmd as Administrator** (Win+R → cmd → Ctrl+Shift+Enter):

```cmd
:: Search for files with flag/proof/HAM in the name
dir C:\ /s /b /a-d | findstr /i "flag proof HAM"

:: Check top-level C:\ for unexpected files
dir C:\ /a-d

:: Check helpdesk Desktop (accessible only as admin)
dir C:\Users\helpdesk\Desktop\

:: Read the flag file
type C:\Users\helpdesk\Desktop\flag.txt
```

**Result:** `C:\Users\helpdesk\Desktop\flag.txt` — created at 14:39 UTC, content: `HAM{rdp_pwned_seat57}`

**Why admin was needed:** The helpdesk Desktop is protected by NTFS permissions. As `madumathi`, access is denied. Running cmd as Administrator (local admin rights) bypasses this restriction.

### Step 9 — Submit the proof of access flag

| Challenge | Flag |
|---|---|
| M2 — Proof of access | HAM{rdp_pwned_seat57} |

---

## Part 4b — After Policy Change: Hunt the Command

**Status:** ✅ Complete — coach enabled Audit Process Creation on 2026-10-13 and replayed the attack.

### Step 10 — Find the new attack window

EventID 4688 now appears where it didn't before. Start with a wide sweep:

```kql
SecurityEvent
| where TimeGenerated > ago(2h)
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4624, 4625, 4688)
| summarize Count = count() by EventID, bin(TimeGenerated, 5m)
| sort by TimeGenerated desc
```

Look for a cluster of 4625 → 4624 → 4688 in the same time bucket — that's the replay window.

### Step 11 — Find the attacker's command

```kql
SecurityEvent
| where TimeGenerated > ago(2h)
| where Computer == "WKS-L57.hamilton.corp"
| where EventID == 4688
| where SubjectUserName == "helpdesk"
| project TimeGenerated, SubjectUserName, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated asc
```

**Result — full process chain at 08:33 UTC on 2026-10-13:**

| Time | Process | CommandLine | Parent |
|---|---|---|---|
| 08:33:30 | rdpinit.exe | rdpinit.exe | userinit.exe |
| 08:33:37 | rdpshell.exe | rdpshell.exe -2057584248 | rdpinit.exe |
| 08:33:37 | **cmd.exe** | **"cmd.exe" /c echo HAM{rdp_pwned_seat57}> %USERPROFILE%\Desktop\flag.txt** | rdpinit.exe |
| 08:33:37 | conhost.exe | conhost.exe 0xffffffff -ForceV1 | cmd.exe |

**The attacker's command:** `cmd.exe /c echo HAM{rdp_pwned_seat57}> %USERPROFILE%\Desktop\flag.txt`

This is what wrote the flag.txt to `C:\Users\helpdesk\Desktop\` — confirmed by the disk forensics in Step 8. Now we know exactly how it got there.

**MITRE:** T1059.003 — Command and Scripting Interpreter: Windows Command Shell

---

## Before vs. After: Logging Gap Summary

| What | Default logging | After Audit Process Creation |
|---|---|---|
| Failed logins (4625) | ✅ Visible | ✅ Visible |
| Successful login (4624) | ✅ Visible | ✅ Visible |
| Source IP | ✅ Visible | ✅ Visible |
| Account used | ✅ Visible | ✅ Visible |
| Command run after login | ❌ Not logged | ✅ Visible (4688 — cmd.exe + full CommandLine) |
| Parent process of command | ❌ Not logged | ✅ Visible (4688 — rdpinit.exe → cmd.exe) |
| File written by attacker | ❌ Not in SIEM (found by disk check only) | ✅ Visible (4688 CommandLine shows the echo command) |

**The core lesson:** Default logging answers *who got in and from where*. Audit Process Creation answers *what they did once inside*. Without 4688, the only way to find the flag file was to manually check the filesystem with elevated privileges — which requires knowing where to look. With 4688, Sentinel shows the exact command, its parent process, and the timestamp automatically.

---

## Stretch Goals

### Full MITRE ATT&CK Chain

| Step | Technique | ID | Evidence |
|---|---|---|---|
| Password guessing over RDP | Brute Force: Password Guessing | T1110.001 | 8 × 4625 from 10.50.0.100 → 4624 success |
| RDP as entry point | External Remote Services | T1133 | LogonType 10, port 3389, LogonProcess User32 |
| cmd.exe runs attacker command | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | EventID 4688 — cmd.exe spawned by rdpinit.exe |

### Detection Question (plain English, for next week's alert rule)

> "Alert me whenever a successful RDP login (EventID 4624, LogonType 10) is followed within 5 minutes by a process creation event (EventID 4688) from the same logon session, where the command line is not a known Windows system process."

### What the Attacker Could Have Done Next (for a non-technical manager)

The attacker had full control of a workstation logged in as `helpdesk` — an account with local administrator rights. From that position, they could have read every file on the machine, installed software that runs silently in the background, or used the workstation as a stepping stone to attack other systems on the network. The only reason they stopped at leaving a flag file is because this was a controlled exercise; a real attacker would have used that same access to move deeper into the organisation.

---

## Key Lessons

1. **One RDP login = two 4624 events.** LogonType 3 (network) + LogonType 10 (desktop). Never count them as two separate logins.
2. **Start with a wide time window.** A narrow window risks missing the attack entirely (lesson from Mission 01).
3. **Filter your own noise first.** Exclude your own IP before hunting — makes the attacker's traffic immediately visible.
4. **Default logging has a blind spot.** Authentication is always visible. What the attacker *does* after login is invisible without Audit Process Creation (EventID 4688).
5. **SIEM + filesystem together.** When logs don't tell the whole story, pivot to the host. An elevated cmd revealed the flag file that Sentinel couldn't see.
6. **Admin rights matter for forensics.** The attacker's Desktop was NTFS-protected. Investigating it required running as local Administrator.

---

**Document Last Updated:** 2026-10-12  
**Analyst:** Madumathi S  
**Mission Status:** ✅ Complete
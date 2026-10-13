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

**Proof of access:** The attacker dropped `flag.txt` (content: `HAM{rdp_pwned_seat57}`) on `C:\Users\helpdesk\Desktop\` at **12:39 UTC** (file timestamp shown as 14:39 local time / CEST = UTC+2), confirming they had an interactive desktop session as the helpdesk user. The file was only accessible by running an elevated command prompt as administrator.

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

After the coach enabled Audit Process Creation (EventID 4688) and replayed the attack on **2026-10-13**, the full command chain became visible in Sentinel.

**Command found:**
```
"C:\Windows\System32\cmd.exe" /c echo HAM{rdp_pwned_seat57}> %USERPROFILE%\Desktop\flag.txt
```

This confirms what was found on disk in Part 4 disk forensics — the attacker used `cmd.exe` to write the flag file to the helpdesk Desktop in a single command.

**EventID 4688 — Full process chain:**

| Time (UTC) | Subject | NewProcessName | CommandLine | ParentProcessName |
|---|---|---|---|---|
| 08:33:30 | helpdesk | C:\Windows\System32\rdpinit.exe | C:\Windows\System32\rdpinit.exe | C:\Windows\System32\userinit.exe |
| 08:33:37 | helpdesk | C:\Windows\System32\rdpshell.exe | "C:\Windows\System32\rdpshell.exe" -2057584248 | C:\Windows\System32\rdpinit.exe |
| 08:33:37 | helpdesk | C:\Windows\System32\cmd.exe | **"C:\Windows\System32\cmd.exe" /c echo HAM{rdp_pwned_seat57}> %USERPROFILE%\Desktop\flag.txt** | C:\Windows\System32\rdpinit.exe |
| 08:33:37 | helpdesk | C:\Windows\System32\conhost.exe | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1 | C:\Windows\System32\cmd.exe |

**Process chain explained:**
1. `userinit.exe` → `rdpinit.exe` — RDP session initialised by Windows
2. `rdpinit.exe` → `rdpshell.exe` — RDP desktop shell started
3. `rdpinit.exe` → `cmd.exe` — **attacker's command executed**
4. `cmd.exe` → `conhost.exe` — console host spawned to run the command

### How I Found It

```kql
// Step 1 — find the new attack window (look for 4688 events that didn't exist before)
SecurityEvent
| where TimeGenerated > ago(2h)
| where Computer == "WKS-L57.hamilton.corp"
| where EventID in (4624, 4625, 4688)
| summarize Count = count() by EventID, bin(TimeGenerated, 5m)
| sort by TimeGenerated desc

// Step 2 — find the attacker's command
SecurityEvent
| where TimeGenerated > ago(2h)
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
| Initial Access | Brute Force: Password Guessing | T1110.001 | 8 × 4625 failures then 4624 success for helpdesk from 10.50.0.100 |
| Initial Access | Remote Desktop Protocol | T1021.001 | LogonType 10, LogonProcess User32, source 10.50.0.100 (internal LAN — T1021.001 not T1133 which is internet-facing) |
| Defense Evasion / Persistence | Valid Accounts | T1078 | Attacker used real helpdesk credentials gained via brute-force; successful logon = valid-account abuse |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | EventID 4688 — cmd.exe spawned by rdpinit.exe, wrote flag.txt to Desktop |

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
| Attacker command | `cmd.exe /c echo HAM{rdp_pwned_seat57}> %USERPROFILE%\Desktop\flag.txt` |
| Parent process of cmd.exe | C:\Windows\System32\rdpinit.exe |

---

## What My Monitoring Missed (and Why)

With default logging, Sentinel showed the attacker got in (EventID 4624) but nothing about what they did afterward. The flag file on the helpdesk Desktop was invisible in the SIEM — I only found it by checking the filesystem with an elevated command prompt. After the Audit Process Creation policy was enabled and the attack replayed, EventID 4688 showed the exact command (`cmd.exe /c echo ...`) that created the file, which parent process launched it (`rdpinit.exe`), and the precise timestamp. Same attack, two completely different pictures: default logging tells you someone got in; 4688 tells you what they did.

---

## Current Status

- [x] Part 1 — labuser warm-up complete (IP: 10.50.0.1, 3 failures + 1 success)
- [x] Part 2 — account (helpdesk), IP (10.50.0.100), attack type (brute force) found and submitted to CTFd
- [x] Part 3 — logging gap documented (no 4688 events without policy change)
- [x] Part 4 — proof of access flag found on disk: HAM{rdp_pwned_seat57}
- [x] Part 4b — attacker command found via EventID 4688 after policy change: cmd.exe /c echo HAM{rdp_pwned_seat57}> %USERPROFILE%\Desktop\flag.txt
- [ ] Case file pushed to GitHub

---

---

## Review History

### Coach Review — 2026-10-13

**Reviewer:** Coach  
**Overall:** Excellent — reads like a real analyst case file.

**Fixes applied:**

1. **Timezone consistency** — Flag file timestamp corrected from "14:39 UTC" to "12:39 UTC". 14:39 was local CEST (UTC+2). All timestamps now in UTC.
2. **MITRE mapping** — T1133 (External Remote Services) replaced with T1021.001 (Remote Desktop Protocol): T1133 is for internet-facing access; 10.50.0.100 is an internal LAN address. Added T1078 (Valid Accounts): once the brute-force succeeded, the attacker logged in with real helpdesk credentials — that is valid-account abuse.
3. **Alert #2 time-binding** — Brute-force correlation alert now binds failures and success to the same 15-minute window using `LookbackWindow = ago(15m)` and `bin(TimeGenerated, 15m)` in the join key, preventing false positives from unrelated historical failures matching a later success on the same IP.

**Commendations noted:** Noise discipline (labuser footprint first, own IP filtered), 2×4624 insight (no double-counting), SubjectUserName = WKS-L57$ catch, before/after logging-gap narrative, stretch goals (plain-English detection question, manager paragraph, alert rules).

---

**Document Last Updated:** 2026-10-13  
**Analyst:** Madumathi  
**Mission Status:** ✅ Complete
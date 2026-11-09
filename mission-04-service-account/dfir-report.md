# Mission 04 — A service account goes rogue: DFIR report

**Analyst:** Madumathi S
**Report date:** 2026-11-06 (updated after containment)
**Environment:** hamilton.corp — WKS-L57 (10.50.0.57), Microsoft Sentinel workspace `log-sentinel-lab`
**Times:** all times are UTC unless stated. Query IDs (for example 2a) refer to `queries.kql`.

---

## 1. Executive summary

A service account used to run a SQL Server service, `svc-app57`, was taken over and used on our workstation WKS-L57. On 2 November 2026 at 13:41 UTC, the intruder ran discovery commands under the account, staged a customer file on the machine's public desktop, and created two scheduled tasks to keep access. The first task ran once to stage the data. The second repeats every 15 minutes, and it was still firing until 09:26 UTC on 6 November (query 1a), when the tasks were removed. The intruder was inside until then.

The staged file holds customer names, email addresses, subscription plans and monthly revenue. It was in a folder readable by every user of the machine. The logs show no transfer of the file off the network, but they do not cover outbound traffic, so whether it left is unknown.

Containment comes first: remove both scheduled tasks, disable and reset the service account, and check every host the account has logged on to. The root cause happened on the domain and is not visible from this workstation.

## 2. Technical narrative

**Stage 0 — how the account was obtained (reasoned, not in Sentinel).** `svc-app57` carries the service principal name `MSSQLSvc/app57.hamilton.corp`, which `setspn -Q` returned from a domain session. Any authenticated domain user can request a Kerberos service ticket for an account with an SPN, and the ticket is encrypted with that account's password. The ticket can be taken away and the password cracked offline, which leaves no failed logons on this machine. The ticket request (EventID 4769) is logged on the domain controller, which is outside this workstation's monitoring. I therefore reason that the password was obtained by Kerberoasting before 13:41 UTC on 2 November. This is my reasoning, not something these logs show.

**Stage 1 — the logon.** At 13:41:13 UTC, `svc-app57` signed in to WKS-L57 with logon type 4 (batch), which is how a scheduled task signs in (query 1a). The same logon repeats every 15 minutes (query 1b), so the pattern is regular and automated. The task logs on with the password stored in it, which means the logons keep working only while that password is valid.

**Stage 2 — discovery.** Five commands ran as `svc-app57` within about 0.6 seconds, from 13:41:14.825 to 13:41:15.409 (query 2a):

- `whoami` and `whoami /all`, to read the account's identity and privileges
- `net user svc-app57`, to read the account's own details
- `net localgroup administrators`, to list the members of the local Administrators group
- `ipconfig /all`, to read the network configuration

The commands belong to the session of the 13:41:13 batch logon, identified by logon ID (query 2c). The payload that issued them was started by the machine account `WKS-L57$`, which is the scheduler's context, not the account that ran the commands (query 2b). The speed points to a script rather than a person typing.

**Stage 3 — staging.** The payload ran once, at 13:41:14 UTC (query 2b). It created `C:\Users\Public\Desktop\staging\`, wrote `customers.csv` and `staging-proof.txt` into it, and both files were last written at 13:41:14 UTC. The payload wrote the file itself, so the source of the data is not established from these logs. No later write is recorded.

**Stage 4 — persistence.** At 13:41:13 and 13:41:15 UTC, the machine account created two scheduled tasks (query 3a):

- `\M4-SvcApp57-Session` runs the payload on demand, as `HAMILTON\svc-app57`. It last ran at 13:41:14.
- `\M4-SvcApp57-Persistence` runs as `HAMILTON\svc-app57` every 15 minutes, with no end date. Each run appends a line to `C:\ProgramData\m4-persistence-log.txt` (query 3c). The first scheduled run was at 13:56 UTC. Query 3d records 370 matching launches, from 13:41:15 UTC on 2 November to 09:26:14 UTC on 6 November: 368 `cmd.exe` writes to the log, and 2 Notepad openings of the log by the analyst (`madumathi`), which the search string also matches. The last launch matches the last batch logon (query 1a) and the log file's last-write time. The first match, at 13:41:15 UTC, is the payload writing a proof line during its own run. It was started by the machine account `WKS-L57$` and ran in the `svc-app57` session (logon ID `0xbe6274a`). Of the 368 `cmd.exe` writes, that one is the payload's proof write, and 367 are scheduled persistence runs. The 373 batch logons (query 1a) reconcile to those: 367 scheduled runs, one every 15 minutes from 13:56 UTC on 2 November to 09:26 UTC on 6 November, plus 6 logons at 13:41 UTC from the session run, which include the logon that carries the proof write.

Both tasks were created by SYSTEM, so something with SYSTEM rights made them on the account's behalf. How SYSTEM was reached is an open question for the root-cause analysis. No update event (4702) is recorded for either task (query 3b). Both tasks were still registered on 4 November.

## 3. MITRE ATT&CK mapping

| Stage | Tactic | Technique (ID + name) | What I observed | Where I can prove it |
|---|---|---|---|---|
| 0 — root cause | Credential Access | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting | `svc-app57` has an SPN (`MSSQLSvc/app57`), so any domain user can request its ticket | Reasoned. SPN from `setspn -Q` output. The ticket request is on DC01 and is not in the workspace |
| 1 — initial access | Initial Access / Persistence | T1078.002 — Valid Accounts: Domain Accounts | Batch logons (type 4) as `svc-app57` from 13:41 UTC, every 15 minutes | Queries 1a, 1b (EventID 4624) |
| 2 — discovery | Discovery | T1033 — System Owner/User Discovery; T1087.001 — Account Discovery (Local); T1069.001 — Permission Groups Discovery (Local); T1016 — System Network Configuration Discovery | `whoami`, `net user`, `net localgroup administrators`, `ipconfig /all` within 0.6 s | Queries 2a, 2c (EventID 4688, logon ID) |
| 3 — collection / staging | Collection | T1074.001 — Data Staged: Local Data Staging | `customers.csv` and `staging-proof.txt` written to `C:\Users\Public\Desktop\staging\` at 13:41:14 | Query 2b (payload launch); file timestamps on WKS-L57 |
| 4 — persistence | Persistence | T1053.005 — Scheduled Task/Job: Scheduled Task | Two tasks created at 13:41:13 and 13:41:15; one repeats every 15 minutes, last seen at 09:26 UTC on 6 November | Queries 3a (EventID 4698), 3b, 3c (launches); `schtasks` output on WKS-L57 |

## 4. Impact and containment

**What was taken.** A customer file, `customers.csv`, staged in a folder on the public desktop of WKS-L57. It holds customer identifiers, names, email addresses, subscription plans and monthly revenue. Staging is confirmed. Exfiltration is not confirmed, because the logs do not cover outbound transfers from this host.

**What the account could do.** `svc-app57` is a member of the local Administrators group on WKS-L57. `net localgroup administrators` on WKS-L57, run on 9 November 2026, lists it with `Administrator`, `becode`, `HAMILTON\Domain Admins`, `HAMILTON\madumathi`, and `svc_deploy`. Disabling and resetting the account doesn't remove this membership, so the account would have been a local administrator again if it were re-enabled. The membership was removed on 9 November 2026 (see Remaining). The discovery commands in Stage 2 ran the same listing command, but its output is not in the logs. Part 2 separately showed that the account could open a file it had been given access to. That shows file access, not group membership, and the group listing is the verification.

**Still inside?** Yes, until containment. Batch logons by `svc-app57` continued until 09:26 UTC on 6 November (query 1a), when the tasks were removed. The account was disabled at 10:33:29 UTC that day, so the intruder's access ended then.

A password change does not stop the tasks. It breaks their logon, and the tasks stay registered. Anyone with local admin can store a new password in a task and restart it. Containment must therefore remove the tasks, not only reset the account.

**Containment, completed.**

1. **Host (analyst, WKS-L57).** Evidence was saved first: copies of the task output, the staged folder and the log, with file hashes. Both tasks, `\M4-SvcApp57-Persistence` and `\M4-SvcApp57-Session`, were then removed. The last `svc-app57` logon before removal was at 09:26 UTC on 6 November 2026.
2. **Account (identity team, escalated).** The analyst's account was denied the rights to change domain accounts, so the identity team carried out the account step. `svc-app57` was disabled at 10:33:29 UTC and its password was reset at 10:33:41 UTC on 6 November 2026. The new password was not shared with the analyst. After the change the account showed Enabled = False, and its password-last-set time matched the reset.

**Evidence preserved (originals kept until review).** Copies were made in `C:\ProgramData\m4-evidence\` on WKS-L57, and their SHA-256 hashes were written to `C:\ProgramData\m4-hashes.txt`. The originals remain in place until this report is reviewed.

| Artifact (original path) | Last written (UTC) | Preserved copy | SHA-256 |
|---|---|---|---|
| `C:\Users\Public\Desktop\staging\customers.csv` | 2 Nov 2026, 13:41:14 | `C:\ProgramData\m4-evidence\staging\customers.csv` | copy and original match: `1BC81102C1C0DF832C14128816DB6EA37516F7AE6295382779D962ED4B7A0892` |
| `C:\Users\Public\Desktop\staging\staging-proof.txt` | 2 Nov 2026, 13:41:14 | `C:\ProgramData\m4-evidence\staging\staging-proof.txt` | copy and original match: `1464D07E319754B4617047D456D68A6ABF81B024EA911BE947F5EC0741AE6BD1` |
| `C:\ProgramData\m4-persistence-log.txt` | 6 Nov 2026, 09:26:14 (matches the last persistence run) | `C:\ProgramData\m4-evidence\m4-persistence-log.txt` | copy and original match: `A09EC57727FF429265330033F433FBC14581A46A2ED1650FFB4470AE1CFDBF08`. The first copy (4 Nov, `03E3AB3C…`) predates the later runs and is kept as part of the record. The final copy was taken on 6 Nov, after the tasks were removed |
| Scheduled task definitions (`schtasks` output) | 4 Nov 2026, 10:28 UTC (state at copy time) | `C:\ProgramData\m4-evidence\task-persistence.txt`, `task-session.txt` | copies: `5510DB5BFDAED049422EB87CFEB49B22D53328CD95F87DA2C0FEC06F769F6EDF` and `00F7A99628E305E6EAF85E11D8EEBF4CB2EC8B1344965B0CE78F08577B4200F1`; originals: not applicable (generated by `schtasks`) |

**Eradication (completed 9 November 2026).** Before deletion, the hashes of the staged files and the proof log were checked against the preserved copies, and all four matched. The removals are recorded in `C:\ProgramData\m4-removal-log.txt`: the staging folder `C:\Users\Public\Desktop\staging\` at 09:07:24 UTC, and the proof log `C:\ProgramData\m4-persistence-log.txt` at 09:07:25 UTC. The preserved copies remain in `C:\ProgramData\m4-evidence\`.

**Remaining.**

- **Removed.** `svc-app57` was removed from the local Administrators group on WKS-L57 on 9 November 2026, after 09:07:25 UTC (exact time not captured; group-change auditing is not enabled on this host, so Sentinel holds no record). A check afterwards lists `Administrator`, `becode`, `HAMILTON\Domain Admins`, `HAMILTON\madumathi`, and `svc_deploy`.
- Confirmed in Sentinel: there were **no successful `svc-app57` logons** after the account was disabled at 10:33:29 UTC on 6 November (query 5a returned 0). Query 5b, for failed logons after the reset at 10:33:41 UTC, returned no results. That is expected, because the tasks were removed before the reset, so nothing was left to attempt a logon.
- **Other hosts (checked).** In the workspace, the two task-creation events (4698) for `M4-SvcApp57` appear only on WKS-L57. `svc-app57` logged on to no other computer in the workspace since 1 November.
- **Network (not available).** The workspace holds no network-traffic logs for this host. A search for the customer file name and the workstation's address matched only heartbeat records, so the report cannot show whether the file left the network. This is a limit of the evidence.

## 5. Remediation — stop it happening again

| Weakness | Why it worked | Missing control and fix |
|---|---|---|
| Service account with an SPN and a password that could be cracked offline | Any domain user could request the ticket for `svc-app57` and crack it offline without an alarm | Move service accounts to group managed service accounts (gMSA), which rotate their own long passwords. Enforce AES-only Kerberos for service accounts and monitor for unusual ticket requests (EventID 4769) |
| No alert on new scheduled tasks created by SYSTEM for user accounts | Two tasks were created and ran for days with no alert | Alert on EventID 4698 where the task runs as a non-system account, and on new tasks that repeat every few minutes |
| Public desktop readable by every user | The staged file was readable by any account on the machine | Restrict the Public folder's permissions and block write access for non-admin accounts. Alert on new folders created under `C:\Users\Public` |
| Domain-side events not reaching the SOC | The Kerberos ticket request (4769) is logged on DC01, which is not forwarded to this workspace | Forward DC01 Security logs to Sentinel, and alert on 4769 requests for service accounts |

---

## 6. Part 2 — the attack reproduced from my own laptop

I reproduced the attack path against my own seat's service account, `svc-app57`, from my laptop, and only against that account and WKS-L57. The steps below show what each one looks like to a defender in our workspace.

| Step | What I did | MITRE ATT&CK | What the workspace could see | What it could not see |
|---|---|---|---|---|
| 1 | Obtained a Kerberos ticket-granting ticket for my own domain account from the laptop | T1078.002 — Valid Accounts: Domain Accounts | Nothing on WKS-L57. The authentication happened on DC01, which is not forwarded | The laptop, the source address, and the request itself |
| 2 | Listed accounts with SPNs and requested a service ticket for `svc-app57` | T1087.002 — Account Discovery: Domain Account; T1558.003 — Kerberoasting | A 4769 on DC01, with RC4 encryption (etype 0x17), if DC01 were forwarded. Not visible here | Everything. The request never touched WKS-L57 |
| 3 | Cracked the ticket offline on the laptop | T1110.002 — Password Cracking | Nothing. No logs are created on any machine during offline cracking | All of it |
| 4 | Signed on to WKS-L57 over RDP as `HAMILTON\svc-app57` | T1078.002; T1021.001 — Remote Desktop Protocol | 4624 on WKS-L57, with logon types 3 and 10. The source address is what the workstation sees, not the laptop | Which machine the password came from |
| 5 | Retrieved the flag from a resource the account can open | T1005 — Data from Local System | Nothing. Object access is not audited on WKS-L57 (audit.csv has no file-share or object-access settings) | The file access itself |

**Step 9 (own footprints in Sentinel).** My sign-ons as `svc-app57` differ from the intruder's activity in Part 1 (query 1a) in four ways:

- **Logon type.** The intruder's logons were type 4 (batch), run by the scheduler. Mine were type 3 (network) and type 10 (RDP), first seen on 4 November at 13:59 UTC.
- **Source.** The intruder's batch logons have no source address. Mine show `10.50.0.1`, the address the workstation saw. That is not my laptop, so the workstation cannot show which machine connected. The coach confirmed that this address is the lab gateway between the laptop and the lab. This is a limit of the evidence: the workstation cannot show which machine connected.
- **Pattern.** The intruder's logons repeated every 15 minutes, 373 times, until 09:26 UTC on 6 November. My sign-ons were individual sessions.
- **Ticket request.** No 4769 for `svc-app57` appears in the workspace (query 7), because DC01 is not forwarded. My ticket request left no trace here.

On 5 November at 15:58:57 UTC, I signed on to WKS-L57 as `svc-app57` over the network (type 3). The session was then unlocked twice (type 7, at 15:58:59 and 15:59:00 UTC). This was during my Step 8 check of the account's rights. These entries are my own activity, not the intruder's.

**Remediation for this path.**
- Move `svc-app57` to a group managed service account, so its password is long and rotated automatically, and no one can request an offline-crackable ticket for a password a person chose.
- Enforce AES-only Kerberos for service accounts, so RC4 tickets are refused.
- Forward DC01 Security logs to Sentinel, and alert on 4769 requests with RC4 encryption for service accounts.
- Turn on object-access auditing for the public share and the staging folder, so file access on the workstation is visible.

---

## Lab notes (not part of the incident)

- The staged customer records carry an exercise tag and use example addresses, so the file is small. The incident is treated as a real exposure of personal data.
- The payload generated the customer records itself. That is why the source of the data is not established from these logs.
- `employees.csv` in the staging folder was last written on 26 October 2026, before this intrusion. It is a Mission 03 file left in the same folder and is not part of this incident.
- A deletion (4699) and a creation (4698) at 14:56:02 UTC on 2 November were the analyst's own OneDrive update task (`\OneDrive Standalone Update Task-…`). They are not related to the intrusion, and they are not counted in the persistence timeline above.
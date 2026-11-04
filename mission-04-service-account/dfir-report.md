# Mission 04 — A service account goes rogue: DFIR report

**Analyst:** Madumathi S
**Date of report:** 2026-11-02
**Environment:** hamilton.corp — WKS-L57 (10.50.0.57), Microsoft Sentinel workspace `log-sentinel-lab`
**Times:** all times are UTC unless stated

---

## 1. Executive summary — for a manager

A service account used to run a SQL Server service, `svc-app57`, was taken over and used on our workstation WKS-L57. The intruder checked the account's privileges, copied a set of customer records into a folder on the machine's public desktop, and set up two scheduled tasks to keep access alive. The first task ran once to collect the data. The second runs every 15 minutes and is still active at the last confirmed time, 16:56 UTC on 2 November 2026, so the intruder is still inside.

The data taken is a customer file of names, email addresses, subscription plans and monthly revenue. It was left in a folder readable by every user of the machine, so anyone with a sign-in to WKS-L57 could read it. There is no evidence in the logs that the file left the network, but the logs do not cover outbound transfer, so that remains unknown.

Containment comes first: remove the two scheduled tasks, lock the service account, and review every host that the account can sign in to. The root cause happened on the domain and is not visible from this workstation.

## 2. Technical narrative — for a technician

**Stage 0 — how the account was stolen (reasoned, not in Sentinel).** `svc-app57` carries the service principal name `MSSQLSvc/app57.hamilton.corp`, which `setspn -Q` returned from a domain session. Any authenticated domain user can request a Kerberos service ticket for an account with an SPN, and the ticket is encrypted with that account's password. The ticket can be carried away and the password cracked offline, which leaves no failed logons and no alarm. The ticket request (EventID 4769) is logged on the domain controller, which is outside this workstation's monitoring. I therefore reason that the password was obtained by Kerberoasting before 13:41 UTC on 2 November. This is my reasoning, not something the logs show.

**Stage 1 — the logon that should not exist.** At 13:41:13 UTC, `svc-app57` signed on to WKS-L57 with logon type 4 (Batch). This is how a scheduled task runs, not how a person signs in. The same account then logged on again every 15 minutes (batch logons, EventID 4624), so the logon pattern is regular and automated.

**Stage 2 — what the account did.** Seven discovery commands ran as `svc-app57` within about 0.6 seconds, from 13:41:14.825 to 13:41:15.409:

- `whoami` and `whoami /all`, to read the account's identity and privileges
- `net user svc-app57`, to read the account's own details
- `net localgroup administrators`, to list who holds administrator rights
- `ipconfig /all`, to read the network configuration

The run speed points to a script rather than a person typing. The same time window contains the payload's single run, `powershell.exe -File C:\ProgramData\m4_session_payload.ps1`, launched by the machine account at 13:41:14. The payload is the source of these commands.

**Stage 3 — the data it gathered and staged.** The payload ran once, at 13:41:14. It created `C:\Users\Public\Desktop\staging\`, wrote `customers.csv` into it (created 13:41:14, last written 13:41:14, unchanged since), and wrote a second file, `staging-proof.txt`. The payload generates the customer records itself and does not copy them from another system, so the source of the data is not established by the script. The file's timestamps match the payload's run, and no later write has been recorded. `customers.csv` and `staging-proof.txt` were last written at 13:41:14 UTC (14:41:14 local time) on 2 November. The staging folder also holds `employees.csv`, last written on 26 October 2026, before this intrusion, so the payload did not create it. It is a Mission 03 file left in the same folder and is recorded separately.

**Stage 4 — how it kept a way back in.** At 13:41:13 and 13:41:15 UTC, the machine account created two scheduled tasks (EventID 4698):

- `\M4-SvcApp57-Session`: runs the payload on demand, as `HAMILTON\svc-app57`. It last ran at 13:41:14 and has not run again.
- `\M4-SvcApp57-Persistence`: runs as `HAMILTON\svc-app57` and repeats every 15 minutes with no end date. Each run appends a line to `C:\ProgramData\m4-persistence-log.txt`. The first launch was at 13:56 UTC, and the task was still firing at 16:56 UTC. Both tasks report Status `Ready`, Last Result `0`, and Run As `svc-app57`.

No later changes were recorded (no EventID 4702 for either task). A 4699 deletion and a 4698 creation at 14:56:02 UTC on 2 November relate to the analyst's own OneDrive update task (`\OneDrive Standalone Update Task-…`), not to either M4 task. On 4 November both M4 tasks were still registered with State Ready, so neither had been removed. The task was created by SYSTEM, not by `svc-app57` directly, so something with SYSTEM rights created it on the account's behalf. I cannot yet show how SYSTEM was reached. That is a question for the root-cause analysis.

## 3. MITRE ATT&CK mapping

| Stage | Tactic | Technique (ID + name) | What I observed | Where I can prove it |
|---|---|---|---|---|
| 0 — root cause | Credential Access | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting | `svc-app57` has an SPN (`MSSQLSvc/app57`), so any domain user can request its ticket | Reasoned, happened off my workstation. SPN from `setspn -Q` output |
| 1 — initial access | Initial Access / Persistence | T1078.002 — Valid Accounts: Domain Accounts | Batch logons (type 4) as `svc-app57` from 13:41 UTC, every 15 minutes | Sentinel, EventID 4624, `svc-app57`, WKS-L57 |
| 2 — discovery | Discovery | T1033 — System Owner/User Discovery; T1087.001 — Account Discovery (Local); T1069.001 — Permission Groups Discovery (Local); T1016 — System Network Configuration Discovery | `whoami`, `net user`, `net localgroup administrators`, `ipconfig /all` within 0.6 s | Sentinel, EventID 4688, `svc-app57` |
| 3 — collection / staging | Collection | T1074.001 — Data Staged: Local Data Staging | `customers.csv` and `staging-proof.txt` written to `C:\Users\Public\Desktop\staging\` by the payload at 13:41:14 | Sentinel, EventID 4688 (payload launch); file timestamps on the seat |
| 4 — persistence | Persistence | T1053.005 — Scheduled Task/Job: Scheduled Task | Two tasks created at 13:41:13 and 13:41:15; one repeats every 15 minutes, still firing at 16:56 UTC | Sentinel, EventID 4698 ×2 and 4688 launches; `schtasks /query` output on the seat |

## 4. Impact and containment

**What was taken.** A customer file, `customers.csv`, staged in a folder on the public desktop of WKS-L57. The file holds customer identifiers, names, email addresses, subscription plans, and monthly revenue. The lab data contains three records, all marked with an exercise tag and using example addresses, so its size is small. For the assessment it is treated as personal data. Staging is confirmed. Exfiltration is not confirmed, because the logs don't cover outbound transfers from this host.

**Still inside?** Yes. The persistence task fired at 16:56 UTC and was still `Ready` with a next run at 17:11 UTC, on the 15-minute schedule. Without action it will keep running indefinitely, and it gives the intruder a way back in even after the service account's password is changed, because the task runs under that account's credentials.

**Containment now.**

1. Record the final task status and last launch time, then remove `\M4-SvcApp57-Persistence` and `\M4-SvcApp57-Session`.
2. Disable `svc-app57` in Active Directory and reset its password. Check first that no legitimate SQL service depends on it, and move it to a managed service account if one is needed.
3. Preserve and then remove the staged folder `C:\Users\Public\Desktop\staging\`, and the proof log `C:\ProgramData\m4-persistence-log.txt`, after the evidence is saved.
4. Review every host where `svc-app57` has logged on, and check for the same two task names elsewhere.
5. Confirm whether the customer file left the workstation, using network logs from the perimeter if available.

## 5. Remediation — stop it happening again

| Weakness | Why it worked | Missing control + fix |
|---|---|---|
| Service account with an SPN and a password that could be cracked offline | Any domain user could request the ticket for `svc-app57` and crack it offline without an alarm | Move service accounts to group managed service accounts (gMSA), which rotate their own long passwords. Enforce AES-only Kerberos for service accounts and monitor for unusual ticket requests (EventID 4769) |
| No alert on new scheduled tasks created by SYSTEM for user accounts | Two tasks were created and ran for days with no alert | Alert on EventID 4698 where the task runs as a non-system account, and on new tasks that repeat every few minutes |
| Public desktop readable by every user | The staged file was readable by any account on the machine | Restrict the Public folder's permissions and block write access for non-admin accounts. Alert on new folders created under `C:\Users\Public` |
| Domain-side events not reaching the SOC | The Kerberos ticket request (4769) is logged on DC01, which is not forwarded to this workspace | Forward DC01 Security logs to Sentinel, and alert on 4769 requests for service accounts |

# Mission 3 — Case file: Locked Out
**Author:** Madumathi S · singaraju.madumathi@gmail.com
**Date:** 2026-10-26
**Environment:** hamilton.corp — DC01 (10.50.0.10) · WKS-L57 (10.50.0.57)

---

## 1. Executive summary — for a manager

An intruder gained access to the hamilton.corp domain environment and used it to lock the primary analyst out of both their workstation (WKS-L57) and the Sentinel monitoring platform. Recovery was achieved by using a lower-privileged account that remained accessible, enumerating the domain's Group Policy infrastructure, and locating a stored credential the intruder had left embedded in a Group Policy Preferences file — a years-old, publicly documented Windows misconfiguration (MS14-025) that encrypts passwords with a key Microsoft published in 2014, making them trivially recoverable by anyone with read access to the domain's SYSVOL share. The credential gave local administrator rights on the workstation and enabled re-entry. Separately, the intruder had staged a set of internal account credentials in a publicly readable network share on the workstation, apparently ready to exfiltrate them. The most important risk this incident exposed is that a single, low-privilege domain account is sufficient to recover any password stored via Group Policy Preferences — a control that should not be used to distribute credentials under any circumstances.

---

## 2. Technical narrative — for a technician

**Stage 1 — Seeing what was still exposed**

With the primary account locked out, investigation began using the `training01` domain account, which retained access to the network. SMB share enumeration against DC01 confirmed that the SYSVOL and NETLOGON shares were readable with standard domain-user authentication. Recursive enumeration of SYSVOL revealed 62 files across 112 folders and 16 Group Policy Object directories. SYSVOL holds one GPP `Groups.xml` per seat, each in its own GPO under the Machine Preferences path. Each file's `cpassword` belongs to the seat named in its comment. In parallel, enumeration of WKS-L57's SMB shares revealed a readable `Public` share containing a plaintext credential file — `account-access.txt` — which held the `training01` username and password and a proof marker, indicating the intruder had already harvested and staged these credentials for exfiltration.

**Stage 2 — Getting a first foothold**

The analyst's foothold used the `training01` account, which remained valid after the lockout. It read the `Public` share and authenticated to the domain, and its network logons to WKS-L57 are recorded in Sentinel (7 logons, LogonType 3, 18:34–20:23 UTC on 26 October). No exploitation was required.

Sentinel also shows 22 ANONYMOUS LOGON and 10 Guest network logons to WKS-L57 from 10.50.0.1 on the same day (LogonType 3, 14:50–20:23 UTC). The analyst did not perform these, and the logs do not establish who did. They are recorded as unattributed activity to review with the coach, not as the analyst's foothold.

**Stage 3 — Finding the real key**

Inside the `Groups.xml` for WKS-L57 (GPO `{BAFE699E-352A-44C0-86AA-36A7C6DC0D51}`, tagged for seat 57), the `Properties` element for the account `svc_deploy` contained a `cpassword` attribute — the Group Policy Preferences encrypted password field — along with `subAuthority="RID_ADMIN"`, meaning the policy had been used to add `svc_deploy` to the local Administrators group on domain workstations. The `cpassword` value was decrypted using the AES-256 key that Microsoft published when patching MS14-025 in 2014; this key is hardcoded into the GPP encryption scheme and cannot be changed. The decrypted value yielded the password for a local `svc_deploy` account on WKS-L57. An earlier attempt used the credential from another seat's item (`{58348A21}`), which the coach confirmed belongs to a different machine; the seat-57 item is the correct one.

**Stage 4 — Walking back in**

The seat-57 `svc_deploy` credential was used to RDP to WKS-L57 (10.50.0.57) as a local account (`.\svc_deploy`). It logged in directly, with no password change, because the GPP item sets `changeLogon="0"` and `noChange="1"`. Earlier attempts with the seat-50 credential returned "password certainly expired" (`ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED`). That error came from using a credential that belongs to another machine, not from a password that needed changing. Local administrator rights were confirmed on the desktop with `whoami /groups`.

Sentinel independently corroborates this stage. Querying WKS-L57's Log Analytics workspace for EventID 4625 (failed logon) reveals **six failed RDP attempts by `svc_deploy`** (SubStatus `%%2313` — STATUS_PASSWORD_EXPIRED) originating from `10.50.0.1` between 19:37 and 20:14 UTC on 26 October 2026, all with LogonType 10 (RemoteInteractive). The substatus needs careful reading. Sub-status `0xC0000071` (password expired) is returned only after the password has been checked and found correct; a wrong password returns `0xC000006A` instead. Six `svc_deploy` failures coded as "expired" therefore mean the password presented was accepted and the account was flagged as expired at that time. That does not fit the explanation that the seat-50 credential was simply the wrong one. The cause is not settled from the workstation logs: the account's expiry state is a domain-side attribute, which is recorded on DC01 and is unverified. The successful logon with the seat-57 credential on 27 October is recorded in Sentinel as EventID 4624, LogonType 10. Additionally, the **primary analyst account (`madumathi`) appears in two EventID 4625 entries with SubStatus `%%2310`** (STATUS_ACCOUNT_DISABLED), both from `10.50.0.1`, confirming that the intruder's lockout of the analyst account was effective and that these login attempts hit the disabled-account barrier rather than a wrong-password barrier.

**Domain-side changes (observed, not verified from telemetry).** The domain account `madumathi` was disabled during the lockout. The workstation shows this only indirectly, through the `%%2310` 4625 entries and the Windows sign-in message "Your account has been disabled" when the correct password was entered. The DC-side events (account disable, EventID 4725, and any `svc_deploy` change, EventID 4738 or `pwdLastSet`) were recorded on DC01. They are outside this workstation's monitoring scope by design, so they could not be verified from telemetry. These changes are documented from observed behaviour and from my own actions, not from log evidence.

Confirmed after RDP: landed on WKS-L57 as `.\svc_deploy`. `whoami /groups` lists `BUILTIN\Administrators` at High integrity. No password change was needed.

**Stage 5 — Taking the proof and seeing what they were after**

Three desktop items were collected: the proof file (submitted to CTFd as "Proof on the desktop"), the Sentinel credentials file (password rotated), and `employees.csv` in a `staging` folder, which is the staged dataset described in Section 5.

The `Public` SMB share on WKS-L57 was independently accessible during the investigation using `training01` credentials and yielded `account-access.txt`, a plaintext file containing the `training01` username and password. This represents the intruder's staged collection, ready for exfiltration, and is treated as a data breach in Section 5 regardless of whether the RDP stage is completed.

---

## 3. MITRE ATT&CK mapping

| Stage | Tactic | Technique (ID + name) | What I did | Where I can prove it |
|---|---|---|---|---|
| 1 — exposure | Discovery | T1135 — Network Share Discovery | Enumerated SMB shares on DC01 and WKS-L57 using `training01`; identified SYSVOL and a readable Public share | Reconstructed from my own actions (off-workstation); Sentinel shows `training01` SMB logons from 10.50.0.1; the anonymous and guest logons are unattributed |
| 2 — foothold | Initial Access / Persistence | T1078 — Valid Accounts (Domain Account) | Authenticated to the domain using the `training01` low-privilege account that survived the lockout | Reconstructed from my own actions |
| 3 — the key | Credential Access | T1552.006 — Unsecured Credentials: Group Policy Preferences | Located `Groups.xml` in SYSVOL GPO; decrypted `cpassword` field using the publicly known MS14-025 AES key | Reconstructed from my own actions (SYSVOL access is off-workstation) |
| 4 — reprise | Lateral Movement | T1021.001 — Remote Services: Remote Desktop Protocol | Used the seat-57 `svc_deploy` GPP credential (local account) to RDP into WKS-L57 with local administrator rights; no password change needed | Sentinel — EventID 4625 SubStatus %%2313 (password expired), `svc_deploy`, 6 failed attempts LogonType 10 from 10.50.0.1, 26 Oct 2026; EventID 4625 SubStatus %%2310 (account disabled), `madumathi`, 2 entries confirming lockout |
| 5 — proof + staged data | Collection | T1074.001 — Data Staged: Local Data Staging | Staged `training01` credentials in `\\WKS-L57\Public`, on WKS-L57's own disk, prior to exfiltration | Direct SMB enumeration via `spider_plus` (`account-access.txt`, ctime 2026-10-26). Share-access events (5140/5145) are absent because file-share auditing is not enabled: the `audit.csv` policy in GPO `{73815AA3}` covers only Logon, Logoff, Special Logon and Process Creation. |

---

## 4. Control gaps & remediation

| Weakness exploited | Why it worked | Missing control + fix | ISO 27001 Annex A | NIS2 / CyFun |
|---|---|---|---|---|
| GPP cpassword storage (MS14-025) | Microsoft published the AES-256 encryption key in 2014 when patching the vulnerability; any domain user with SYSVOL read access can decrypt any `cpassword` field. The GPO had never been cleaned up. | **Remove all GPP password fields from SYSVOL immediately.** Use Microsoft LAPS (Local Administrator Password Solution) to manage local admin passwords per machine with unique, rotated secrets. Never use GPP to distribute credentials. | A.9.2.3 Management of privileged access rights; A.9.4.3 Password management system | NIS2 Art. 21(2)(i) — access control policies; CyFun PR.AC-1 Identity management |
| Readable Public SMB share exposing credentials | The `Public` share on WKS-L57 required no authentication and contained a plaintext credential file. Any host on the network could read it without logging in. | **Remove unauthenticated shares.** If a drop-zone share is operationally required, restrict it to write-only with no read permission for unprivileged accounts. Audit all share ACLs quarterly. Credentials must never be stored in plaintext on a file share. | A.9.4.1 Information access restriction; A.8.3.1 Management of removable media | NIS2 Art. 21(2)(e) — supply chain security / access control; CyFun PR.AC-3 |
| No domain-side logging reaching the SOC | The domain account `madumathi` was disabled and `svc_deploy` was changed on DC01, but DC01's Security log does not reach the workspace. Monitoring covers only WKS-L57 by design, so these changes could not be detected or verified from the SOC. | **Extend log collection to domain controllers** (Windows Security Events via AMA on DC01), and alert on EventIDs 4725 and 4738 for primary and privileged accounts. Confirm account-management auditing is enabled on DC01. | A.12.4.1 Event logging; A.16.1.2 Reporting information security events | NIS2 Art. 21(2)(b) — incident handling; CyFun DE.CM-1 Monitoring of networks and systems |
| Shared local admin account name with a per-seat GPP password | Each seat's GPP item stored the password for a local `svc_deploy` admin account in a form any domain user can decrypt. Anyone holding one seat's credential could try the others, and every seat's item was readable from any machine. | **Replace GPP-stored local admin passwords with LAPS**, which gives each machine a unique, rotated password stored in AD with restricted read rights. Review local Administrators membership on every workstation. | A.9.2.3 Management of privileged access rights; A.9.4.3 Password management system | NIS2 Art. 21(2)(i); CyFun PR.AC-1 Identity management |
| SYSVOL readable by all domain users | The GPO containing the credential was deployed to the domain and readable by any authenticated user, not restricted to specific OUs or admin accounts. | **Audit SYSVOL for legacy GPP password entries** (use Microsoft's own `Get-GPPPassword` or equivalent). Restrict SYSVOL ACLs to the minimum required. Apply Group Policy security filtering to limit who can read sensitive policy objects. | A.9.1.2 Access to networks and network services | NIS2 Art. 21(2)(i); CyFun PR.AC-4 Access permissions managed |

---

## 5. Data breach assessment

**What was exposed**

The intruder staged two sets of data for exfiltration.

The first is the `training01` domain account credentials (username and plaintext password) in `account-access.txt` on the `Public` SMB share of WKS-L57. The file contained one set of authentication credentials for a domain account with network-wide read access to SYSVOL and other internal shares. The data was accessible without authentication to any host on the internal network segment and had been staged there as of 2026-10-26 (confirmed via file creation timestamp).

The second is `employees.csv`, found in a `staging` folder on the `svc_deploy` desktop of WKS-L57. It holds four employee records with the fields `employee_id`, `full_name`, `email`, `department`, and `salary`, and every row carries the marker `EXFIL-TEST-MARKER-M3`. The email addresses use the `example.com` domain, so the records appear synthetic and the marker indicates they were placed for this exercise. For the assessment they are treated as personal data. The coach confirmed the file is part of the mission and is to be used for this GRC assessment.

**Severity**

The exposure of a valid domain account credential gives any party who reads the file the ability to authenticate to the domain, enumerate internal file shares, and potentially escalate further — as demonstrated by this investigation itself, which used `training01` to locate and decrypt a higher-privileged credential. If the `training01` account is used in any system that processes personal data (HR directories, monitoring platforms, ticketing systems), the credential breach becomes a gateway to a secondary personal-data breach. The severity is elevated by the fact that the staged file was publicly readable without authentication.

**Notification duty under NIS2**

Under NIS2 Article 23, significant incidents affecting network and information systems must be reported in stages: an **early warning within 24 hours** of becoming aware of a significant incident, followed by a **full incident notification within 72 hours**, and a final report within one month. The incident must be reported to the competent national authority (CERT/NCA) and, where applicable, to affected recipients of the service. The threshold for "significant" includes incidents with substantial impact on service continuity or data integrity; a credential breach enabling lateral movement in a corporate domain meets this threshold.

**Obligations under GDPR**

The `employees.csv` file contains personal data as defined by GDPR Article 4: full names, email addresses, and salaries, linked to employee identifiers. Its staging on the `svc_deploy` desktop, alongside the credential file on the Public share, means the intruder was collecting personal data and not only credentials. The breach must be assessed under GDPR Article 33, which requires notifying the supervisory authority **within 72 hours** where the breach is likely to result in a risk to individuals' rights and freedoms. Salary data combined with names and identifiers is likely to meet that threshold, and Article 34 notification to the affected employees may also apply. The four records in this file are the known extent of the staged personal data. A Data Protection Impact Assessment of systems accessible via `training01` and `svc_deploy` is still required to determine whether more personal data was reachable.

**Missing control**

The data should never have been reachable from a network share. The control that failed was **data classification and share access governance**: sensitive authentication credentials were placed in an unauthenticated, world-readable share with no DLP monitoring. The fix is threefold: (1) remove the Public share or enforce authentication and read-restriction; (2) implement a DLP rule that alerts when credential-pattern content (username/password pairs) is written to file shares; (3) rotate `training01` and all credentials visible to or from that account immediately. Reference: ISO 27001 A.8.2 Information classification, A.13.2 Information transfer; NIS2 Art. 21(2)(e); GDPR Art. 25 Data protection by design and by default.

---

## 6. Stretch — alternative route (optional)

No second independent entry path was identified. The `Public` share exposed credentials but offered only read access and no code execution, so it did not provide a privileged re-entry path. Access to WKS-L57 depended on the GPP-stored credential for the seat-57 local account.
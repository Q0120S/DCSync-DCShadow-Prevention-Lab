# DCSync Prevention — Complete Guide

Combines the step-by-step build, the rationale behind every decision, safety caveats, the code we wrote on top of the open-source RPC Firewall, and the proof-of-concept results that validated each step.

Read top-to-bottom for a complete picture. Every command is copy-paste and every result was observed in the lab.

---

## Table of contents

1. Executive summary
2. Attack context — what DCSync does at the wire
3. Research methodology — how we built the evidence base
4. Defense layer 1 — Identity ACLs (Phase 1)
5. Defense layer 2 — Tier-0 silo + Kerberos armoring (Phases 3, 2)
6. Defense layer 3 — Coercion RPC filters (Phase 4)
7. Defense layer 4 — DC firewall + static ports (Phase 5)
8. Defense layer 5 — Base RPC Firewall SID rule (Phase 6)
9. Defense layer 6 — DRS Request-Inspection module we wrote (Phase 7)
10. Custom code — what we built on top of the upstream project
11. Behavioural fingerprinting — the buffer-capture study
12. The SYSTEM-privilege investigation
13. Optional advanced — local-SYSTEM ncalrpc SDDL filter
14. Attack matrix — validated PoC results
15. What remains open — Phase 8 (WDAC)
16. Recovery playbook

---

## 1. Executive summary

DCSync abuses the legitimate MS-DRSR replication protocol. An attacker holding any Domain Admin-equivalent identity can dump every credential in AD by making one RPC call to a DC. Standard AD ACLs cannot help — the caller *is* legitimately authorized.

We built a layered defense that intercepts DCSync at every layer between the network and the real replication server, using the smallest possible discriminator at each layer:

- IP filtering at Windows Firewall
- Interface + protocol filtering at the WFP RPC filter layer
- SID + shape filtering at a Detours hook inside `lsass.exe`
- AD ACL evaluation inside NTDS

We then modified an open-source RPC Firewall to add payload-layer inspection, using empirical buffer captures to identify wire-level discriminators between legitimate KCC replication and attacker tooling. We discovered a genuine improvement over the "SYSTEM-on-DC is unaddressable" ceiling by isolating the local-vs-cross-DC transport split and adding a targeted SDDL-conditioned block for local SYSTEM.

The one attack shape we cannot close at the RPC layer is cross-DC SYSTEM DCSync, where mimikatz on one DC authenticates outbound as its own machine account against a peer DC. The wire is byte-identical to legitimate KCC replication. That case needs WDAC (kernel code-integrity), which is the recommended Phase 8.

---

## 2. Attack context — what DCSync does at the wire

DCSync is not an exploit. It is the legitimate DRSUAPI protocol used adversarially.

- **Protocol:** MS-DRSR (Directory Replication Service Remote Protocol)
- **Interface UUID:** `e3514235-4b06-11d1-ab04-00c04fc2dcd2`
- **Endpoint:** `lsass.exe` on every DC listens for DRSUAPI RPC calls (NTDS is loaded into lsass)
- **Attack opnums:**
  - `IDL_DRSGetNCChanges` (opnum 3) — pull replication changes, including credential attributes. mimikatz `lsadump::dcsync` calls this.
  - `IDL_DRSReplicaAdd` (opnum 5) — register a new replication partner. mimikatz `lsadump::dcshadow` calls this.
- **Authorization:** at the AD access-check layer, holding the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights lets the call succeed. Members of Domain Admins, Enterprise Admins, and the built-in Administrators group inherit these. So does anyone AD is convinced to grant them to.

A `GetNCChanges` request from mimikatz is structurally similar to one from a real DC doing scheduled replication: same interface UUID, same opnum, same DRSUAPI protocol version. Distinguishing them requires looking at signals AD's default check does not consider — caller SID category, authentication service, source IP, transport, and — for the truly hard cases — the wire content of the request buffer.

---

## 3. Research methodology

We didn't guess which controls would work. The approach was:

1. **Build the base defense** (Phases 1 through 6) using published guidance from the identity/AD-security community.
2. **Instrument the RPC layer** by hooking `rpcrt4.dll` NDR dispatch functions inside `lsass.exe` and writing every DRSUAPI opnum 3 (later also opnum 0) request buffer to disk as a labeled corpus.
3. **Run attacks** — mimikatz, secretsdump, both from off-DC and from on-DC as various principals — with markers written into the corpus manifest so we could correlate captured buffers with the tool run that produced them.
4. **Compare buffers byte-by-byte** to identify discriminators between legitimate KCC replication and each attacker shape.
5. **Encode the discriminators as classification rules** in our modified RPC Firewall DLL and validate that DETECT mode blocks the attacker without breaking legitimate replication.
6. **Push against the ceiling** — the "SYSTEM on DC" case memory §6 described as unaddressable. We split it into local ncalrpc and cross-DC network variants, closed the local one with a targeted RPC filter, and confirmed the cross-DC one is the true wire-indistinguishable ceiling.

Every attack test was reproducible in the lab, and every finding is backed by an actual buffer capture, event-log entry, or command output.

---

## 4. Defense layer 1 — Identity ACLs (Phase 1)

### What it does

Restricts *who* holds the AD replication extended rights, adds audit visibility when they are used, and plants a honeytoken account whose access instantly produces an alert.

### Why this exists

The DCSync attack requires the `Get-Changes` and `Get-Changes-All` extended rights on the domain naming context. The defaults on a fresh domain are correct. What's needed is:

- Baseline verification (nothing added a rogue principal to the ACL)
- OWNER RIGHTS restriction, so an object's owner cannot silently regain access
- SACL 4662 auditing so any attempt to invoke replication rights produces a security event
- A honeytoken user whose access is always suspicious

### Commands

Baseline audit (Phase 0):

```powershell
$nc = (Get-ADDomain).DistinguishedName; $replRights = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c'); (Get-Acl "AD:$nc").Access | Where-Object { $_.ObjectType -in $replRights } | Format-Table IdentityReference, ActiveDirectoryRights, ObjectType
```

OWNER RIGHTS restriction:

```powershell
$nc = (Get-ADDomain).DistinguishedName; $acl = Get-Acl "AD:$nc"; $ownerRights = New-Object System.Security.Principal.SecurityIdentifier('S-1-3-4'); $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($ownerRights, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead, [System.Security.AccessControl.AccessControlType]::Allow); $acl.AddAccessRule($rule); Set-Acl -Path "AD:$nc" -AclObject $acl
```

SACL for 4662:

```powershell
$rights = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c'); $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0'); $sacl = Get-Acl "AD:$nc" -Audit; foreach ($g in $rights) { $auditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($everyone, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, [System.Security.AccessControl.AuditFlags]'Success,Failure', [Guid]$g); $sacl.AddAuditRule($auditRule) }; Set-Acl -Path "AD:$nc" -AclObject $sacl
```

```cmd
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

### Safety and caution

- The OWNER RIGHTS SID (S-1-3-4) does not exist as a real principal; you're setting an ACE that redirects the implicit owner-full-control to `GenericRead`. It doesn't lock anyone out.
- Event volume from 4662 auditing can be high during normal DC-to-DC replication. Forward the log off-box and set a rate-limited alert on the honeytoken specifically.
- The honeytoken should never have real credentials in use. Use a 32+ character random password and never log in with it.

### PoC result

Phase 0 baseline on `lab.local` returned exactly the expected default principals:

- `NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS` — Get-Changes, Get-Changes-In-Filtered-Set
- `BUILTIN\Administrators` — all three
- `Enterprise Read-only Domain Controllers` — Get-Changes
- `Domain Controllers` — Get-Changes-All

No rogue principals. Clean baseline snapshot taken as `phase0-baseline`.

---

## 5. Defense layer 2 — Tier-0 silo + Kerberos armoring (Phases 3, 2)

### What it does

Constrains where Tier-0 identities (`t0-admin`, `DC$`, `DC2$`) can log in from. Enforced via Kerberos claims that require FAST armoring to be evaluated.

### Why this exists

DCSync doesn't need to run *on* a DC — the attacker just needs an identity with replication rights, from anywhere reachable. If we can prevent that identity from authenticating outside of Tier-0 (i.e. from anywhere other than the DCs themselves), the network attack surface for DA credentials shrinks dramatically. Silo enforcement won't stop an attacker who already lives on a DC, but it does close the lateral path from Tier-1 to Tier-0.

Kerberos armoring is a prerequisite because the silo policy is expressed as a conditional-ACE SDDL that requires FAST claims in the ticket.

### Ordering caveat

Armoring MUST be enabled before silo enforcement. If you enforce first, the DC's own Kerberos tickets don't carry the required claim yet, and the silo denies its own membership check — locking out `t0-admin` under all conditions.

### Commands (Phase 3, armoring, both DCs)

The registry key path is easy to get wrong. Both values live under `\Parameters`, not at the root of `\KDC` or `\Kerberos`:

```powershell
$kdc = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'; $cli = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; foreach ($p in @($kdc, $cli)) { if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }; New-ItemProperty -Path $p -Name EnableCbacAndArmor -Value 1 -PropertyType DWord -Force | Out-Null }
```

Reboot each DC, then verify with `Get-ItemProperty` on both paths.

### Commands (Phase 2, silo, on DC only)

```powershell
New-ADAuthenticationPolicy -Name 'Tier0-Auth' -UserAllowedToAuthenticateFrom "O:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(ED)}))"
```

The SDDL says: the calling device's token must contain the Enterprise Domain Controllers group (`S-1-5-9`). Practically, this means `t0-admin` can only authenticate when logging in from a DC.

```powershell
$siloParams = @{ Name='Tier0Silo'; UserAuthenticationPolicy='Tier0-Auth'; ComputerAuthenticationPolicy='Tier0-Auth'; ServiceAuthenticationPolicy='Tier0-Auth'; Enforce=$false }; New-ADAuthenticationPolicySilo @siloParams
```

Assign members and grant access, then verify.

### Safety and caution

- Start in audit mode (`Enforce=$false`). Watch for silo-denial events 4820/4821/4823/4824 during a soak. Enforce only after zero surprise denials.
- Built-in `Administrator` (RID-500) is exempt from silo enforcement — it's your escape hatch. Do not disable it.
- If you enforce and the silo locks you out (typically because armoring wasn't actually working), log in as `Administrator` via the hypervisor console and disable enforcement.

### PoC result

Silo created in audit mode. All three members' `msDS-AssignedAuthNPolicySilo` attribute confirmed to point at the silo DN. Ready for a 24-hour+ soak followed by enforce+reboot.

---

## 6. Defense layer 3 — Coercion RPC filters (Phase 4)

### What it does

Blocks the RPC interfaces used to *coerce* a DC into authenticating to an attacker-controlled machine, which is a common prelude to unconstrained-delegation or RBCD attacks that end in DCSync.

### Blocked UUIDs

| UUID | Protocol | Attack it enables |
|---|---|---|
| `c681d488-d850-11d0-8c52-00c04fd90f7e` | MS-EFSR (EfsRpcOpenFileRaw) | PetitPotam |
| `df1941c5-fe89-4e79-bf10-463657acf44d` | MS-EFSR (secondary) | PetitPotam variant |
| `4fc742e0-4a10-11cf-8273-00aa004ae673` | MS-DFSNM | DFSCoerce |
| `12345678-1234-abcd-ef00-0123456789ab` | MS-RPRN | PrinterBug |

Plus Print Spooler service disabled entirely on DCs.

### Commands

Save the four filter rules to a `.rsp` file and load with `netsh -f`. Filters persist across reboot via Windows Filtering Platform.

### Safety and caution

- These interfaces are also used for legitimate features (Encrypted File System, DFS Namespaces, network printing). On a DC these are unusual to need. Verify no operational tool depends on them.
- `netsh rpc filter` filters live at the WFP RPC layer, one hop earlier than our Detours hook. They persist across reboot via WFP configuration. However, if you later install our modified `rpcFwManager`, its `/start` and `/update` commands do `delete filter filterkey=all` before installing what's in `RpcFw.conf` — so put the coercion UUIDs *inside* `RpcFw.conf` as `flt:` lines, not just via `netsh`. This is a real gotcha we hit and fixed.

### PoC result

PetitPotam from Kali:

- Connection to `\\PIPE\lsarpc` succeeded.
- `EfsRpcOpenFileRaw` returned `RPC_ACCESS_DENIED`. Tool tried fallback `EfsRpcEncryptFileSrv`, got `STATUS_PIPE_DISCONNECTED`.
- No NTLM authentication callback arrived at Kali. Coercion blocked.

---

## 7. Defense layer 4 — DC firewall + static ports (Phase 5)

### What it does

Constrains which endpoints reach the DCs at all and pins RPC-based services to known ports so firewall rules can be tight. Deployed via a GPO built by the DCFWTool.

### Why this exists

Restricts lateral reachability and management-plane exposure. LDAP, Kerberos, GC, and SMB stay open to the client subnet; NTDS, Netlogon, WMI, RDP, and WinRM are restricted to management addresses (in this lab, only the DCs themselves).

### Static ports pinned

| Service | Port |
|---|---|
| NTDS RPC | 38901 |
| Netlogon RPC | 38902 |
| FRS (legacy, pinned anyway) | 38903 |
| DFSR | 5722 |
| WMI (via `WmiStaticPort: true`) | Windows-managed |

### Commands (summary)

Set static ports on each DC via registry (NTDS, Netlogon) and `dfsrdiag StaticRPC` (DFSR). Reboot. Then clone the DCFWTool, create a lab-specific `Set-ADDSFirewallPolicy.json`, run the deploy script on one DC, and gpupdate on both.

### Known issue — GPO not always linked

In our lab the DCFWTool created the GPO but did not link it to the `Domain Controllers` OU on first run. We added an explicit link step:

```powershell
Import-Module GroupPolicy; $dcOU = "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"; $links = Get-GPInheritance -Target $dcOU | Select-Object -ExpandProperty GpoLinks; if ($links.DisplayName -notcontains 'Domain Controller Firewall') { New-GPLink -Name 'Domain Controller Firewall' -Target $dcOU -LinkEnabled Yes -Enforced Yes }
```

Always verify the link before proceeding.

### Safety and caution

- `EnableRpcFilters: true` in the JSON config makes DCFWTool wipe and reinstall the RPC filter set. This is a superset of the Phase 4 coercion UUIDs, so it's a strict improvement — but you'll see all your netsh-loaded filters go away and be replaced.
- Kali is in the same `192.168.20.0/24` client subnet as legit workstations. LDAP, Kerberos, and GC ports will still be open to Kali. That's intentional — DCSync blocking is at the SID + payload layers, not the network layer. Kali reaching port 88 doesn't hurt if it can't dump anything through it.

### PoC result

Nmap from Kali against DC after GPO applied:

- Open: 88 (Kerberos), 389 (LDAP), 464 (kpasswd), 636 (LDAPS), 3268/3269 (GC), 135 (RPC EPM), 445 (SMB), 38901 (NTDS static), 38902 (Netlogon static)
- Filtered: 3389 (RDP), 5722 (DFSR), 5985 (WinRM)

Legit tools (`Get-ADDomainController`, `repadmin`, `dcdiag`) work from `t0-admin`. Domain client authentication from the SQL member box unaffected.

---

## 8. Defense layer 5 — Base RPC Firewall SID rule (Phase 6)

### What it does

Runs an open-source Detours DLL (Zero Networks' RPC Firewall, upstream: `zeronetworks/rpcfirewall` on GitHub) inside `lsass.exe`, hooking every RPC server-side dispatch. Applies allow/block rules based on interface UUID, opnum, and caller SID. Our rules allow DRSUAPI opnums 3 and 5 only when the caller has the `S-1-5-9` (Enterprise Domain Controllers) group in their token, and block everything else on those opnums.

### Why the SID rule works

Legitimate DC-to-DC replication is Kerberos-authenticated as the DC's own machine account (`DC1$`, `DC2$`, etc.). Every DC machine account inherits `S-1-5-9`. Any user identity — including Domain Admins — does *not* inherit `S-1-5-9`. That single group check cleanly separates "DC talking to DC" from "user (or Kali, or attacker) invoking DCSync."

### RPC Firewall config

The `RpcFw.conf` file has to be named exactly that (not `RpcFirewall.txt` as I initially suggested in an earlier draft — this is a real bug we hit and fixed). It lives in the same directory as `rpcFwManager.exe`. Content for this stack:

```
flt:action:block audit:true uuid:c681d488-d850-11d0-8c52-00c04fd90f7e
flt:action:block audit:true uuid:df1941c5-fe89-4e79-bf10-463657acf44d
flt:action:block audit:true uuid:4fc742e0-4a10-11cf-8273-00aa004ae673
flt:action:block audit:true uuid:12345678-1234-abcd-ef00-0123456789ab
fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 sid:S-1-5-9 opnum:3 action:allow audit:true
fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 sid:S-1-5-9 opnum:5 action:allow audit:true
fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 opnum:3 action:block audit:true
fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 opnum:5 action:block audit:true
```

The `flt:` lines re-declare the Phase 4 coercion UUIDs because `rpcFwManager /start` and `/update` do `delete filter filterkey=all` before installing what's in this file — anything only loaded via `netsh` gets wiped. Putting them here makes them survive service restarts.

### Install sequence

1. Build the DLL from source (Visual Studio, Release | x64).
2. Copy `rpcFireWall.dll`, `rpcFwManager.exe`, `rpcMessages.dll`, and the `RpcFw.conf` config to `C:\Program Files\RpcFirewall\` on each DC.
3. Also copy `rpcFireWall.dll` to `C:\Windows\System32\` — lsass loads it from there.
4. Run `rpcFwManager.exe /install` then `/start`.
5. Reboot each DC.
6. Verify the DLL is loaded in lsass with `Get-Process lsass -Module`.

### Safety and caution

- `/install` alone does not attach the hook. `/start` + reboot is required.
- Every DC must be running the base. One unprotected DC is a full bypass because attackers can select the target with `-dc-ip` or `/dc:`.
- The DLL is loaded from `C:\Windows\System32\rpcFireWall.dll` regardless of where `rpcFwManager` lives. When you replace the DLL, replace it in *both* locations, and reboot.
- Replacing `C:\Windows\System32\rpcFireWall.dll` while lsass has it loaded is an in-use error. Rename the current one and copy the new file in its place, or use `MoveFileEx MOVEFILE_DELAY_UNTIL_REBOOT`.

### PoC results

Kali `impacket-secretsdump` against both DCs (as any identity, including Domain Admin `t0-admin`):

```
[-] RemoteOperations failed: rpc_s_access_denied
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] rpc_s_access_denied
```

mimikatz DCSync run as `t0-admin` on the DC console:

```
mimikatz # lsadump::dcsync /domain:lab.local /user:krbtgt
[DC] 'krbtgt' will be the user account
ERROR kuhl_m_lsadump_dcsync ; RPC Exception 0x00000005 (5)
```

mimikatz DCShadow run as `t0-admin`:

- Server-side mimikatz starts and prints "Fake Server (already registered)".
- Push-side mimikatz produces no attribute change. Confirmed with `Get-ADUser t0-admin -Properties Description` returning empty.
- opnum-5 SID rule fires; RPCFW Event 3 records the block.

RPCFW/Operational event 3 (`Auth: KERBEROS`, `SID: LAB\DC2$` for legit replication; `Auth: WINNT`, `SID: lab\t0-admin` or Kali's identity for attempts).

---

## 9. Defense layer 6 — DRS Request-Inspection module (Phase 7)

### What it does

A new module we wrote on top of the RPC Firewall DLL. Sits above the base SID rule. Extracts features from the marshalled `DRS_MSG_GETCHGREQ` request buffer, consults a topology oracle (list of known partner DCs), applies a decision engine, and either logs (AUDIT mode) or blocks (DETECT mode) the call.

### Why we added it

The base SID rule catches Kali and user-invoked DCSync. It does not catch attackers who impersonate a DC machine account, nor does it distinguish targeted single-object DCSync from bulk pull. Payload-layer inspection closes some of these gaps and produces a detection signal for the ones it can't close.

### Signals extracted

- `target_is_security_principal` — the request's target DSNAME parses as a security principal (DN starts with `CN=`) versus a partition NC head (`DC=…`, `CN=Configuration,…`, `CN=Schema,…`).
- `is_single_object_exop` — the request carries an extended-operation code indicating single-object replication (EXOP_REPL_OBJ=6 or EXOP_REPL_SECRETS=7). Combined with the DN heuristic for high confidence.
- `source_is_established_partner` — the source IP is in `partners.txt`, auto-populated from `Get-ADDomainController -Filter *` by a scheduled task.
- `caller_is_local_system` — primary SID is `S-1-5-18`.
- `source_is_loopback` — source IP starts with `fe80::`, `::1`, or `127.`.
- `allowlisted` — the (SID, IP) pair matches an entry in `allowlist.txt`. Used to allow-list known-benign SYSTEM/loopback traffic.

### Decision engine

```
if allowlisted -> ALLOW
if !caller_is_dc_identity -> BLOCK
if targetedShape && !source_is_established_partner -> BLOCK (targeted DCSync)
if caller_is_local_system -> BLOCK (opt-in via drsi_enforce_sys_loopback)
if source_is_loopback -> BLOCK (opt-in via drsi_enforce_sys_loopback)
if !parse_ok -> ALERT (fail-open)
if source_is_established_partner && targetedShape -> ALERT (indistinguishable case)
if source_is_established_partner -> ALLOW (normal replication)
if !source_is_established_partner && !targetedShape -> ALERT
```

### Deployment

`Deploy-DrsHarden.ps1` (companion script we wrote) creates the data directory `C:\Hardening\capture\`, populates `partners.txt`, seeds `allowlist.txt` with the DC's own loopback addresses (SYSTEM+fe80:: is a known Windows-internal producer of this shape), and registers a 15-minute scheduled task to refresh partners.

Sentinel files control the mode:

| File | Effect |
|---|---|
| `drsi_enabled` | Module runs; logs every decision to `decisions.log`. |
| `drsi_enforce_shape` | BLOCK verdicts on the shape rule are enforced. |
| `drsi_enforce_sys_loopback` | BLOCK verdicts on the SYSTEM/loopback rule are enforced. |
| `drsi_alert_blocks` | ALERT verdicts also block (very aggressive). |
| `enabled` | Phase 1 capture shim writes `.bin` files for corpus building. |

### Safety and caution

- Default is AUDIT — the module logs but blocks nothing. Every enforcement dimension is a separate opt-in sentinel. This is deliberate; the original engagement was wedged by enforcing STRICT (SYSTEM/loopback) before allowlisting known-benign Windows-internal traffic.
- Never enable `drsi_enforce_sys_loopback` without a soak period first. Grep `decisions.log` for recurring SYSTEM/loopback shapes and add them to `allowlist.txt` if they turn out to be legit Windows internals.
- The DLL parses request buffers with heuristics, not a full NDR unmarshaller. Any parse failure produces an ALERT verdict, never a BLOCK. Fail-open is the design.
- The kill switch is a single `Remove-Item "$dir\drsi_enforce_shape"` — effect within 1 second.

### PoC result — AUDIT

First legit KCC replication event captured:

```
decision=ALLOW enforced=0 src=192.168.20.2 sid=S-1-5-21-...-2601 buflen=480 partner=1 partners_loaded=2 parse_ok=1 dn="DC=lab,DC=local" reason="established partner - normal replication"
```

First Kali attack event captured:

```
decision=BLOCK enforced=0 src=192.168.20.50 sid=S-1-5-21-...-2602 partner=0 single_obj=1 principal=1 reason="single-object secret pull from a non-partner source (targeted DCSync)"
```

`enforced=0` because AUDIT — Phase 6 still blocks it at the SID gate; DRSI is recording what it would decide.

### PoC result — DETECT

After creating `drsi_enforce_shape`, same Kali attack:

```
decision=BLOCK enforced=1 ...
```

Legit replication remained ALLOW throughout. `repadmin /replsummary` stayed at 0/5 fails. Snapshot taken as `phase7-detect`.

---

## 10. Custom code — what we built on top of the upstream project

We started from `zeronetworks/rpcfirewall` (open source) and added new code. Here is precisely what.

### Files unchanged from upstream

- `rpcFwManager/*` — the manager EXE and its build. Untouched.
- `rpcMessages/*` — event log resource DLL. Untouched.
- `rpcFirewall/pch.h`, `framework.h`, `config.hpp`, `rpcWrappers.hpp` — untouched.
- Most of `rpcFirewall/dllmain.cpp` — the base hook logic (Detours attach/detach, `processRPCCallInternal`, event log formatting) is unchanged.

### Files we added

- `rpcFirewall/drsCapture.hpp`, `drsCapture.cpp` — Phase 1 capture shim. New code. Bounded, SEH-safe copy of DRSUAPI opnum 0 and opnum 3 request buffers to disk via an async writer thread. Manifest-CSV output including opnum, source IP, caller SID, byte length. Sentinel-file kill switch (`enabled`).
- `rpcFirewall/drsInspect.hpp`, `drsInspect.cpp` — Phase 2-4 inspector. New code. Feature extraction from request buffer, partner topology lookup, decision engine, per-decision structured log to `decisions.log`, three separate enforce sentinels, allowlist file. Data directory configurable via HKLM registry.
- `scripts/Deploy-DrsHarden.ps1` — new companion script. Auto-populates `partners.txt` from AD, seeds `allowlist.txt`, registers a 15-minute refresh scheduled task, locks the data directory ACL. Idempotent.

### File we modified — `rpcFirewall/dllmain.cpp`

Four surgical additions (all guarded by our own module's kill-switch sentinel; zero effect when disabled):

1. Two `#include` lines for `drsCapture.hpp` and `drsInspect.hpp`.
2. Two lines inside `processRPCCallInternal` after `populateEventParameters`: check if this is DRSUAPI opnum 0 or 3, capture the buffer; if it's opnum 3 and policy already allowed, also invoke the inspector and let it override `policy.allow` if it decides BLOCK.
3. One call `drscap::startCaptureThread()` at DLL attach, after Detours succeeds.
4. One call `drscap::stopCaptureThread()` at DLL detach, before Detours teardown.

All other existing code paths run identically to upstream.

### Files we modified — build system

- `rpcFirewall/rpcFirewall.vcxproj` — registered the four new `.hpp/.cpp` files.
- `rpcFirewall/rpcFirewall.vcxproj.filters` — same, for VS solution explorer.

### Design constraints in our own code (non-negotiable)

- **Read-only.** Never modify `pRpcMsg` or its buffer.
- **Fail-open.** Every error, parse failure, SEH exception → no-op or ALERT. Never BLOCK on uncertainty.
- **Bounded.** Copy at most 64 KB per call. Queue at most 256 items. Scan at most 8 KB during feature extraction.
- **SEH-wrapped.** The raw-buffer copy of attacker-controlled memory runs inside `__try/__except` in a standalone `noexcept` function so C++ unwinding doesn't collide.
- **Async I/O.** RPC thread never touches disk. Owned struct pushed to a queue; a background writer thread drains it.
- **Kill switch.** Sentinel files polled once per second (cached), so `Remove-Item` takes effect within 1 s.
- **Config-driven.** All paths configurable via HKLM registry. Nothing hardcoded except a default (`C:\Hardening\capture`).

---

## 11. Behavioural fingerprinting — the buffer-capture study

This section documents the research that produced the discriminators encoded in `drsInspect.cpp`, and one important finding that led to the SYSTEM-privilege chapter below.

### Method

With capture enabled, we ran controlled test cycles:

- Legit replication: `repadmin /syncall DC.lab.local /Aed /q`
- Attack as t0-admin: mimikatz `lsadump::dcsync /user:krbtgt`
- Attack as SYSTEM: same via scheduled task with `-UserId 'SYSTEM'`
- Kali secretsdump

Each cycle was bounded by manifest markers (`# --- LABEL START ---`) so we could correlate captured `.bin` files to the tool run.

### Signal 1 — caller SID class

The base RPCFW rule already uses this: legit callers carry `S-1-5-9` (Enterprise DCs group); user identities and remote callers don't. In our lab captures, every legit KCC entry showed a machine account SID (RID matching DC2$); every Kali entry showed the user's SID under WINNT auth service.

### Signal 2 — DN shape in the request buffer

We scanned buffers for the wide-string `DC=` marker (used as a landmark since it's guaranteed in any target DSNAME) and walked back to identify the start of the DN. Findings:

- Legit KCC single-partition pulls: DN starts with `DC=lab,DC=local` (domain NC), `DC=ForestDnsZones,…`, `DC=DomainDnsZones,…`.
- Legit KCC partition-head pulls for Config/Schema: DN starts with `CN=Configuration,…`, `CN=Schema,…`.
- mimikatz `/user:X`: DN starts with `CN=X,CN=Users,DC=lab,DC=local`.

Our heuristic (`target_is_security_principal = DN startsWith 'CN='`) fires false-positive on Configuration/Schema NC heads. The classifier compensates by requiring `partner=1` (which those legit calls always have) before treating the DN as a real principal target.

### Signal 3 — Extended-op DWORD

We searched for the DWORD values 6 and 7 (EXOP_REPL_OBJ, EXOP_REPL_SECRETS) at 4-byte-aligned positions with small flanking values. Result: this signal alone hits on almost every buffer (the byte pattern is too common). We use it only as a corroborating signal in combination with the DN heuristic.

### Signal 4 — Established partner

`Deploy-DrsHarden.ps1` populates `partners.txt` from `Get-ADDomainController -Filter *`. The DLL polls that file every 5 seconds and looks up incoming source IPs. Very reliable when the file is current, which the 15-minute scheduled task ensures.

### Signal 5 — DsBind client PID (biggest single finding)

We compared two 148-byte DsBind (opnum 0) captures — one from legit KCC (`192.168.20.2` / `DC2$`) and one suspected mimikatz (`192.168.20.1` / `t0-admin`). Every byte was identical except one DWORD at **offset `0x40`**:

- Legit: `74 02 00 00` = **0x0274 = 628** — lsass PID on the source DC
- Suspect: `28 08 00 00` = **0x0828 = 2088** — the calling user-mode tool's PID

This field is `DRS_EXTENSIONS_INT.Pid`, filled by the *client*, not the OS. Legit DC-to-DC replication runs inside lsass on the source DC, so the reported PID is lsass's. Mimikatz runs as a separate process (or a scheduled-task-launched process under SYSTEM) with its own PID.

This is a real, robust discriminator against default mimikatz. It would still work against attackers who don't specifically patch mimikatz to spoof the PID field.

### Failed hypothesis — secret attribute detection

We hypothesized mimikatz `/user:X` would request specific secret attribute IDs (`unicodePwd` = 0x9005A, `dBCSPwd` = 0x90037, etc.) in the `PARTIAL_ATTR_VECTOR_V1_EXT`, and legit KCC would not. Testing showed:

- Zero secret-attribute DWORD hits in any of ~50 captured legit buffers.
- Zero hits in the suspected mimikatz buffers either.

Reason: the attribute vector is NDR-referenced through a pointer chain that our bounded byte-scan doesn't follow. To read those bytes properly, we would need a full NDR unmarshaller with the DRSUAPI type descriptor. That is out of scope for a lab prototype.

### Result summary

Signals we implemented and rely on: 1 (SID), 2 (DN shape), 3 (EXOP DWORD as corroboration only), 4 (partner list).

Signal 5 (DsBind PID) is a validated finding but not yet coded into the classifier. A future refinement would hook opnum 0 in the *inspector* (not just the capture shim) and cache a "known-good PID per partner" over time, blocking new PIDs from the same source.

---

## 12. The SYSTEM-privilege investigation

The design spec §0/§6 originally claimed DCSync-as-SYSTEM-on-DC was un-catchable at the wire because SYSTEM's token contains `S-1-5-9`. Our investigation split this case in two.

### Test setup — Test-DcsyncTransports.ps1

Purpose-written script that runs mimikatz twice via scheduled tasks with `-UserId 'SYSTEM'`:

- **Test A** — `lsadump::dcsync /user:krbtgt` (default target resolution)
- **Test B** — same command with `/dc:<peer FQDN>` (force network TCP)

Each test writes markers into the DRSI manifest and parses mimikatz output to classify SUCCEEDED / BLOCKED / UNCLEAR.

### Test A observation — the ncalrpc bypass

Before any additional mitigation: Test A **SUCCEEDED**, dumping the full krbtgt hash. The manifest showed **zero captured entries** in the window when mimikatz ran.

Root cause: mimikatz on the DC, targeting local DRSUAPI, used **`ncalrpc`** (local RPC). The base RPCFW code early-returns from `processRPCCallInternal` when the binding is ncalrpc ([dllmain.cpp:1425](rpcfirewall/rpcFirewall/dllmain.cpp:1425)):

```cpp
if (_tcsstr(szStringBinding.str, _T("ncalrpc")) != nullptr) return true;
```

That path bypassed the SID rule, DRSI inspector, and Phase 1 capture entirely. This was not a limitation of memory §6's "wire ceiling" — it was a whole transport we weren't inspecting.

### Test B observation — the true wire ceiling

Test B **SUCCEEDED** every time, even after the ncalrpc gap was closed. Why:

- SYSTEM on DC1, making outbound network RPC to DC2, gets its auth from the machine account's Kerberos ticket.
- On DC2, the request arrives as `LAB\DC1$` via Kerberos over TCP port 38901.
- Byte-for-byte identical to legitimate KCC replication.

Our buffer captures for Test B on DC2's manifest matched the legit KCC patterns exactly. No wire-level signal distinguishes them.

**This is the true, remaining ceiling.** WDAC is the only mitigation.

### Closing Test A — SDDL-conditioned RPC filter

Since Test A is same-machine, we can filter at the WFP RPC layer with a condition on both `protocol=ncalrpc` and the caller's primary token. The netsh RPC filter language supports a `remote_user_token` field taking an SDDL descriptor.

```
add rule layer=um actiontype=block filterkey=e3514235-4b06-11d1-ab04-00c04fc2dc00
add condition field=protocol matchtype=equal data=ncalrpc
add condition field=if_uuid matchtype=equal data=e3514235-4b06-11d1-ab04-00c04fc2dcd2
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;SY)
add filter
```

The SDDL `D:(A;;CC;;;SY)` means the caller's token must contain SYSTEM. Legit admin tools (repadmin, dcdiag, Get-ADDomainController) run as `t0-admin`, so they don't satisfy the condition and continue to work. mimikatz-as-SYSTEM satisfies it and hits the block.

### PoC result

Before the filter:

- Test A: SUCCEEDED — full krbtgt dump.
- Test B: SUCCEEDED — full krbtgt dump.
- All legit tools work.

After the filter (per DC):

- Test A: **BLOCKED** — mimikatz outputs `ERROR kull_m_rpc_drsr_getDCBind ; RPC Exception 0x00000005 (5)` at the DsBind.
- Test B: SUCCEEDED — true wire ceiling.
- `Get-ADDomainController`: works (returns both DCs).
- `repadmin /showrepl`: healthy.
- `dcdiag /test:Replications /q`: silent (pass).

### Persistence problem

`rpcFwManager /start` and `/update` do `delete filter filterkey=all` before installing `RpcFw.conf`. Whenever the rpcFirewall service restarts (including at boot), our netsh-loaded filter disappears. Since `RpcFw.conf`'s `flt:` format doesn't support `protocol` or `remote_user_token` conditions, we couldn't move the filter into that file.

Solution: a scheduled task that reapplies the filter every 5 minutes, with a PowerShell wrapper that verifies the filter is present after netsh and exits 0 only when it is. Post-reboot verification (after ≥6 minutes) confirms the filter re-appears.

### Refined ceiling model

| Attack | Before this work | After this work |
|---|---|---|
| Local mimikatz-as-SYSTEM DCSync (ncalrpc) | Succeeded (ceiling) | **Blocked** (SDDL filter) |
| Cross-DC mimikatz-as-SYSTEM DCSync | Succeeded (ceiling) | Still succeeds (true wire-indistinguishable ceiling; WDAC required) |
| Legit tools | Green | Green |

This is a real improvement over memory §6's original position that SYSTEM-on-DC was entirely unaddressable at this layer.

---

## 13. Optional advanced — local-SYSTEM ncalrpc SDDL filter

Full step-by-step is in `DCSync-Hardening-Clean-StepByStep.md` under "Optional advanced." Summary of what to do:

1. Save the filter `.rsp` file (5 lines of netsh).
2. Apply it (`netsh -f`).
3. Register a scheduled task that reapplies it every 5 minutes.
4. Force-run the task once and confirm `LastTaskResult : 0`.
5. Validate: legit tools work, Test A blocks, Test B still succeeds.
6. Reboot; verify filter reappears within 6 minutes.

**When to do this:** you want the local-SYSTEM DCSync closed before Phase 8 (WDAC) lands, and you're willing to own the maintenance of a scheduled task.

**When to skip:** you plan to do Phase 8 soon; WDAC closes both the local *and* cross-DC SYSTEM cases without needing a task.

**Uninstall (if it ever breaks something):**

```powershell
Unregister-ScheduledTask -TaskName 'DrsuapiNcalrpcSysBlock' -Confirm:$false; netsh rpc filter delete filter filterkey=e3514235-4b06-11d1-ab04-00c04fc2dc00
```

---

## 14. Attack matrix — validated PoC results

Every row was tested end-to-end in the lab and the observed behaviour is recorded. `L1..L6` map to defense layers 1-6 as titled in this document.

| # | Attack | Result | Layer that catches it |
|---|---|---|---|
| 1 | Legit DC-to-DC replication | Green throughout | none — legitimate |
| 2 | Kali `secretsdump` → DC | `rpc_s_access_denied` | L5 (Phase 6 SID rule) |
| 3 | Kali `secretsdump` → DC2 | `rpc_s_access_denied` | L5 |
| 4 | mimikatz DCSync as `t0-admin` on DC | `RPC Exception 0x00000005 (5)` | L5 |
| 5 | mimikatz DCSync as `t0-admin` on DC2 | `RPC Exception 0x00000005 (5)` | L5 |
| 6 | mimikatz DCShadow as `t0-admin` on DC | Attribute unchanged; opnum-5 block | L5 |
| 7 | PetitPotam from Kali | `RPC_ACCESS_DENIED` then `STATUS_PIPE_DISCONNECTED` | L3 (RPC filters) |
| 8 | mimikatz-as-SYSTEM local DCSync (ncalrpc), no advanced mitigation | krbtgt dumped — bypass | *ncalrpc gap* |
| 9 | Same as #8, with optional advanced mitigation | `RPC Exception 5` at DsBind | Optional advanced (WFP RPC filter) |
| 10 | mimikatz-as-SYSTEM cross-DC DCSync (`/dc:<peer>`) | krbtgt dumped | **not blocked at RPC layer** — Phase 8 (WDAC) required |
| 11 | mimikatz-as-SYSTEM DCShadow (self-target) | Attribute unchanged (Windows self-replication refusal, not our control) | Windows built-in |
| 12 | Legit `Get-ADDomainController`, `repadmin`, `dcdiag` | All green | — |
| 13 | Legit interactive `t0-admin` logon on DC (post-silo-enforce) | Succeeds | — |
| 14 | Legit domain-client authentication (SQL member) | Succeeds | — |

Row 8 was our biggest discovery: the "unaddressable ceiling" in memory §6 was actually two cases, one of which (local) is closable at the RPC filter layer.

Row 10 is the honest remaining ceiling: cross-DC SYSTEM is wire-indistinguishable and needs WDAC.

---

## 15. What remains open — Phase 8 (WDAC)

WDAC (Windows Defender Application Control) is a kernel-mode code-integrity mechanism. It evaluates every executable at launch against a policy of allowed publishers and hashes, and terminates non-matching processes.

For our stack, WDAC closes the last remaining DCSync path:

- **Row 10 (cross-DC SYSTEM DCSync)** — WDAC on the DCs blocks `mimikatz.exe` (or any non-signed / non-hashed binary) from executing at all. Without a running mimikatz process, no DCSync request is ever made.
- **Row 8 (local SYSTEM DCSync)** — same. WDAC also closes this case, making the optional advanced ncalrpc filter redundant if Phase 8 is deployed.

### Rollout shape

1. Generate a base policy from what's currently running on the DC (`New-CIPolicy -Level Publisher -UserPEs -Fallback Hash`).
2. Enable in audit mode — event 3076 fires when a would-be-blocked binary runs, but the process still executes.
3. Soak ≥1 week. Every 3076 event names a binary and its signature status; legitimate ones get publisher or hash rules added to the policy.
4. Flip to enforce. Event 3077 fires and processes are terminated.

Not documented in step-by-step form in this repo yet — that's the next build.

---

## 16. Recovery playbook

| Symptom | Likely cause | Recovery |
|---|---|---|
| `t0-admin` locked out after silo enforce | Armoring wasn't fully working when silo enforced; DC's own ticket missing claim | Log in as `Administrator` via hypervisor console; `Set-ADAuthenticationPolicySilo -Identity Tier0Silo -Enforce:$false` |
| Replication broken (`rpc_s_access_denied`) | New DC added without allowlisting in DCFWTool `DomainControllerAddresses` and RPC firewall config | Add the new DC's IP to DCFWTool config; verify RpcFw.conf `sid:S-1-5-9` rule is in place (it auto-covers new DCs) |
| `repadmin` reports `1908 (Could not find the domain controller)` or `8524 (DNS lookup failure)` transiently | Stale artifact from a reboot window — `Get-ADReplicationPartnerMetadata` will show `LastReplicationResult=0` | `repadmin /syncall DC.lab.local /Aed /q` clears stale entries |
| DRSI DETECT blocks a legit replication call | False positive on the shape rule (very rare; requires `partner=0` + CN= target) | `Remove-Item "$dir\drsi_enforce_shape"` — effect in 1 s; inspect the log entry to understand which fingerprint triggered |
| DRSI STRICT (`drsi_enforce_sys_loopback`) breaks Windows internals | Not on the audit-first path — should never have been enabled without allowlist tuning | `Remove-Item "$dir\drsi_enforce_sys_loopback"` — effect in 1 s |
| Local admin tools (repadmin, dcdiag, Get-ADDomainController) return access-denied | Optional advanced ncalrpc filter is too broad (not using SDDL-scoped variant) | Verify filter includes `remote_user_token=D:(A;;CC;;;SY)` condition; if it doesn't, delete and reapply with the correct rule |
| Base rpcFirewall log shows `No configuration file found` | Config file named `RpcFirewall.txt` instead of `RpcFw.conf` | Rename to `RpcFw.conf`; run `rpcFwManager.exe /update` |
| RPC filters keep disappearing | `rpcFwManager /start` or service restart wiped them | Put UUIDs in `RpcFw.conf` as `flt:` lines (survives); for the SDDL-conditioned ncalrpc filter which can't be expressed in `flt:`, install the 5-minute repeater task |
| Everything wrong | Revert both DCs to the last named snapshot |

---

## Companion documents

- `DCSync-Hardening-Clean-StepByStep.md` — commands only, no rationale
- `DCSync-Hardening-Runbook.md` — full runbook with Fixes log and appendices
- `DCSync-Prevention-Explained.md` — short technical explainer of how it works
- `DCSync-DCShadow-Hardening-Memory.md` — as-built engagement memory for this lab
- `DCSync-Prevention-Complete-Guide.md` — this document

Each document targets a different reader. This one is the definitive combined reference — someone reading it start to finish should understand what to run, why to run it, what to watch for, and what evidence backed each decision.

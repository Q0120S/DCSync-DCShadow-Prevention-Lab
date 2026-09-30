# DCSync / DCShadow Hardening Runbook — lab.local

_A living document. Every time we hit an error and solve it, the fix is applied inline in the affected phase and recorded with a date in the [Fixes log](#fixes-log) at the bottom._

- **Environment:** `lab.local` (SID `S-1-5-21-512320763-4122718174-4040246643`, Site `Default-First-Site-Name`)
  - DC — hostname `DC`, IP `192.168.20.1`
  - DC2 — hostname `DC2`, IP `192.168.20.2` (added in Phase 0.5; skip that phase if you already have two DCs)
  - SQL member — `192.168.20.30`
  - Kali attacker — `192.168.20.50`
- **Privileged accounts today:** only built-in `Administrator` (RID-500). We create `t0-admin` in Phase 1.0.
- **Base tools:** DCFWTool (dsinternals), Zero Networks RPC Firewall (modified — this repo)
- **Working directory on each DC:** `C:\Hardening\` (created in Phase 0)
- **Working directory on the operator workstation:** `C:\Users\BigBoss\Desktop\Hardening\` (this runbook + build outputs; not the same as the DC's dir)

## Conventions

- **Snapshot each DC before every numbered phase.** Name snapshots by phase (e.g. `phase3-armoring-verified`).
- **Prefer splatting over backtick-continued lines.** PowerShell backtick continuation breaks when pasted into consoles that echo `>>` on empty lines; splatting hashtables paste cleanly.
- **Do not skip forward.** Each phase assumes the ones above it are in place; some (Kerberos armoring, RPCFW `/start` + reboot) have order-of-operations traps documented in the Fixes log.

## Order of operations (quick reference)

**Core path — do these in order:**

1. Phase 0 — Baseline & inventory
2. Phase 0.5 — Add second DC (skip if already two DCs; see also [Appendix A](#appendix-a--adding-a-new-dc-after-hardening) for the post-hardening variant)
3. Phase 1.0 — Create `t0-admin`
4. Phase 1 — Identity layer (ACL / OWNER RIGHTS / SACL / honeytoken)
5. Phase 3 — Kerberos armoring **before** silo enforcement
6. Phase 2 — Tier-0 silo (audit → enforce → reboot)
7. Phase 4 — Coercion filters + Print Spooler off
8. Phase 5 — DC firewall + static RPC ports (DCFWTool)
9. Phase 6 — RPC Firewall base rules
10. Phase 7 — DRS Request-Inspection AUDIT → DETECT → STRICT
11. Phase 8 — WDAC / RunAsPPL / EDR / krbtgt rotation
12. Phase 9 — Telemetry off-box
13. Phase 10 — Validation drills

**Optional advanced hardening — pick if you need it:**

- [Appendix B — Local-SYSTEM DCSync block (ncalrpc SDDL filter)](#appendix-b--advanced-local-system-dcsync-block-ncalrpc-sddl-filter). Closes the on-DC-SYSTEM local DCSync path (mimikatz-as-SYSTEM using ncalrpc). Sits alongside Phase 6/7; independent of the core path. Adds ~15 minutes of setup per DC and a small operational responsibility for a maintenance scheduled task. Recommended when you have Phase 6 stable and want a defense-in-depth win against the "SYSTEM on DC" case without waiting for Phase 8 (WDAC).

---

## Immediate cleanup — recover from a half-created `t0-admin`

If a previous run of Phase 1.0 created `t0-admin` in a disabled/no-password state (see [Fixes log 2026-09-28 #1](#2026-09-28--1--backtick-line-continuation-broke-phase-10)):

```powershell
Import-Module ActiveDirectory

# Verify current state
Get-ADUser t0-admin -Properties Enabled, PasswordLastSet, DistinguishedName |
    Format-List Name, Enabled, PasswordLastSet, DistinguishedName

# Reset the password
$pw = Read-Host -AsSecureString -Prompt 'New password for t0-admin'
Set-ADAccountPassword -Identity t0-admin -Reset -NewPassword $pw

# Enable and clear "must change at next logon"
Set-ADUser -Identity t0-admin -Enabled $true -ChangePasswordAtLogon $false

# If it's not already in OU=Tier-0, move it
$dn = (Get-ADDomain).DistinguishedName
$target = "OU=Tier-0,$dn"
if ((Get-ADUser t0-admin).DistinguishedName -notlike "*,$target") {
    Move-ADObject -Identity (Get-ADUser t0-admin).DistinguishedName -TargetPath $target
}

# Confirm group membership
Get-ADPrincipalGroupMembership t0-admin | Select-Object Name
```

If any of those fail because `t0-admin` doesn't exist at all, jump to Phase 1.0.

---

## Phase 0 — Baseline & inventory

Prove the starting state is clean and capture it for later comparison.

**Prerequisite:** the DC needs a local output directory. `C:\Users\BigBoss\Desktop\Hardening\` is on the workstation, not the DC. See [Fixes log — 2026-09-28 #3](#2026-09-28--3--phase-0-output-dir-and-broken-pipeline-paste).

```powershell
New-Item -ItemType Directory C:\Hardening -Force | Out-Null

Import-Module ActiveDirectory
dcdiag /q
dcdiag /test:Replications /v > C:\Hardening\baseline_repl.txt
repadmin /replsummary
Get-ADDomainController -Filter * | Select Name, HostName, IPv4Address, Site
Get-ADDomain | Select DNSRoot, DomainSID, DomainMode, ForestMode
```

Replication-rights principals — paste-safe single-statement form (multi-line pipelines can break on blank lines in the console):

```powershell
$nc = (Get-ADDomain).DistinguishedName
$replRights = @(
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',   # DS-Replication-Get-Changes
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',   # DS-Replication-Get-Changes-All
    '89e95b76-444d-4c62-991a-0facbeda640c'    # DS-Replication-Get-Changes-In-Filtered-Set
)
$acl = Get-Acl "AD:$nc"
$acl.Access | Where-Object { $_.ObjectType -in $replRights } | Format-Table IdentityReference, ActiveDirectoryRights, ObjectType
```

Allowed principals: `SYSTEM`, `Administrators`, `Domain Admins`, `Enterprise Admins`, `Enterprise Domain Controllers` (S-1-5-9), `Domain Controllers`, `Read-only Domain Controllers` if RODCs exist. Any other principal is a finding — remove before proceeding.

**Single-DC vs multi-DC:**
- If `Get-ADDomainController` returns one row, `repadmin /replsummary` will be empty (nothing to replicate with) — that's expected, not a bug.
- Phases 2 (silo membership), 6 (RPCFW per DC), 7 (partners.txt) assume all present DCs. Adapt member lists to actual DCs. When you later add DC2, first allowlist its IP in both DCFWTool `DomainControllerAddresses` and the DRSI `partners.txt`, then promote.

Snapshot: `phase0-baseline`.

---

## Phase 0.5 — Add DC2 (pre-hardening path)

Skip if you already have two DCs. If a DC is added AFTER hardening is in place, use [Appendix A](#appendix-a--adding-a-new-dc-after-hardening) instead — extra steps are required because promotion is itself a DRSUAPI opnum 3/5 flow.

### 0.5.1 Prep on the future DC2

Fresh Windows Server VM, local Administrator:

```powershell
Rename-Computer -NewName DC2 -Force
$if = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1).ifIndex
New-NetIPAddress -InterfaceIndex $if -IPAddress 192.168.20.2 -PrefixLength 24 -DefaultGateway 192.168.20.1
Set-DnsClientServerAddress -InterfaceIndex $if -ServerAddresses 192.168.20.1
Restart-Computer -Force
```

### 0.5.2 Install role and promote

After reboot:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Import-Module ADDSDeployment
$safeMode = Read-Host -AsSecureString -Prompt 'DSRM Administrator password (unique)'
# IMPORTANT: enter the credential as 'lab\Administrator' (DOMAIN\user) or
# 'Administrator@lab.local' (UPN). A bare 'Administrator' is interpreted as
# the LOCAL account on this machine and fails with:
#   "The user name or password is incorrect"
# during the promotion pre-flight, even if the domain password is right.
$cred     = Get-Credential -Message 'Enter as lab\Administrator (DOMAIN\user), NOT bare Administrator'
$promote  = @{
    DomainName                    = 'lab.local'
    SafeModeAdministratorPassword = $safeMode
    Credential                    = $cred
    SiteName                      = 'Default-First-Site-Name'
    InstallDns                    = $true
    NoRebootOnCompletion          = $false
    Force                         = $true
}
Install-ADDSDomainController @promote
# Machine reboots automatically
```

### 0.5.3 Verify on DC

```powershell
Import-Module ActiveDirectory
Get-ADDomainController -Filter * | Select Name, HostName, IPv4Address, Site
repadmin /replsummary
dcdiag /test:Replications /q
```

Expected: two rows in the DC list; `repadmin /replsummary` shows 0 fails in both directions; `dcdiag` clean.

Snapshot both DCs: `phase0.5-dc2-joined`.

---

## Phase 1.0 — Create the Tier-0 admin

Do this before any hardening. All later phases are logged in as `t0-admin`.

```powershell
Import-Module ActiveDirectory
$dn = (Get-ADDomain).DistinguishedName

# 1. OU
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Tier-0'" -SearchBase $dn -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name 'Tier-0' -Path $dn -ProtectedFromAccidentalDeletion $true
}

# 2. Create OR relocate t0-admin. If it already exists from an earlier
#    attempt, move it into OU=Tier-0 and reset its password instead of failing.
$pw = Read-Host -AsSecureString -Prompt 'Strong password for t0-admin'
$existing = Get-ADUser -Filter "SamAccountName -eq 't0-admin'" -ErrorAction SilentlyContinue
if ($existing) {
    Set-ADAccountPassword -Identity t0-admin -Reset -NewPassword $pw
    Set-ADUser -Identity t0-admin -Enabled $true -ChangePasswordAtLogon $false
    if ($existing.DistinguishedName -notlike "*OU=Tier-0,*") {
        Move-ADObject -Identity $existing.DistinguishedName -TargetPath "OU=Tier-0,$dn"
    }
} else {
    $userParams = @{
        Name                 = 't0-admin'
        SamAccountName       = 't0-admin'
        UserPrincipalName    = "t0-admin@$((Get-ADDomain).DNSRoot)"
        AccountPassword      = $pw
        Enabled              = $true
        Path                 = "OU=Tier-0,$dn"
        PasswordNeverExpires = $false
        CannotChangePassword = $false
    }
    New-ADUser @userParams
}

# 3. Group memberships (idempotent - safe to re-run)
Add-ADGroupMember 'Domain Admins'     -Members t0-admin -ErrorAction SilentlyContinue
Add-ADGroupMember 'Enterprise Admins' -Members t0-admin -ErrorAction SilentlyContinue
Add-ADGroupMember 'Schema Admins'     -Members t0-admin -ErrorAction SilentlyContinue

# 4. Mark built-in Administrator as break-glass. Do NOT disable it.
Set-ADUser Administrator -Description 'BREAK-GLASS ONLY. Use t0-admin for all normal admin.'

# 5. Rotate Administrator's password. Written as a ONE-LINER
#    Set-ADAccountPassword to avoid the backtick-continuation trap that
#    silently prompts for a password interactively and can leave the account
#    in an unknown state - see Fixes log 2026-09-28 #4.
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 32
$rng.GetBytes($bytes)
$adminPw = ([Convert]::ToBase64String($bytes)).Substring(0, 32)
Write-Host "==> COPY TO PASSWORD MANAGER NOW <==" -ForegroundColor Yellow
Write-Host $adminPw
Read-Host -Prompt 'Press Enter after saving the password'
Set-ADAccountPassword -Identity Administrator -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $adminPw -Force)
Get-ADUser Administrator -Properties PasswordLastSet | Select-Object Name, PasswordLastSet
Remove-Variable adminPw

# 6. Log out. Log back in as t0-admin on the DC console (or RDP), then launch
#    an ELEVATED PowerShell (Run as administrator). In a non-elevated shell,
#    'whoami /groups' shows DA/EA/SA as "Group used for deny only" because of
#    UAC token filtering - that is normal, not a failure. The elevated shell
#    has those groups active. See Fixes log 2026-09-28 #4.
```

Snapshot: `phase1.0-tier0-admin-created`.

---

## Phase 1 — Identity layer

### 1.1 OWNER RIGHTS restriction on the domain NC

```powershell
$nc = (Get-ADDomain).DistinguishedName
$acl = Get-Acl "AD:$nc"
$ownerRights = New-Object System.Security.Principal.SecurityIdentifier('S-1-3-4')
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $ownerRights,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($rule)
Set-Acl -Path "AD:$nc" -AclObject $acl
```

### 1.2 SACL 4662 auditing on replication rights

```powershell
$rights = @(
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
    '89e95b76-444d-4c62-991a-0facbeda640c'
)
$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$sacl = Get-Acl "AD:$nc" -Audit
foreach ($g in $rights) {
    $auditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
        $everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AuditFlags]'Success,Failure',
        [Guid]$g
    )
    $sacl.AddAuditRule($auditRule)
}
Set-Acl -Path "AD:$nc" -AclObject $sacl
```

Enable the DS Access audit subcategory:

```cmd
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

### 1.3 Honeytoken account

```powershell
$dn = (Get-ADDomain).DistinguishedName
$honeyPw = Read-Host -AsSecureString -Prompt 'Random password for honeytoken (>=32 chars, discard)'
$honeyParams = @{
    Name              = 'svc_replreader'
    SamAccountName    = 'svc_replreader'
    Description       = 'DO NOT USE - Honeytoken (DCSync detection)'
    Enabled           = $false
    Path              = "CN=Users,$dn"
    AccountPassword   = $honeyPw
}
New-ADUser @honeyParams
Add-ADGroupMember 'Backup Operators' svc_replreader

# SACL: log every access
$user = Get-ADUser svc_replreader
$path = "AD:$($user.DistinguishedName)"
$sacl = Get-Acl $path -Audit
$rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    (New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0'),
    'GenericAll',
    'Success,Failure'
)
$sacl.AddAuditRule($rule)
Set-Acl $path $sacl
```

Snapshot: `phase1-identity-done`.

---

## Phase 3 — Kerberos armoring (do this BEFORE the silo)

Registry paths matter. See [Fixes log — 2026-09-27 #A](#armor-key-must-be-under-parameters-subkey) for the trap that hard-locks `t0-admin`.

```powershell
$kdc = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
$cli = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
foreach ($p in @($kdc, $cli)) {
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    New-ItemProperty -Path $p -Name EnableCbacAndArmor -Value 1 -PropertyType DWord -Force | Out-Null
}
Restart-Computer -Force
```

Verify post-reboot:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters' EnableCbacAndArmor
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' EnableCbacAndArmor
```

Snapshot: `phase3-armoring-verified`.

---

## Phase 2 — Tier-0 Authentication Policy Silo

### 2.1 Create the silo objects

```powershell
$policyName = 'Tier0-Auth'
$siloName   = 'Tier0Silo'

New-ADAuthenticationPolicy -Name $policyName `
    -UserAllowedToAuthenticateFrom "O:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(ED)}))"

$siloParams = @{
    Name                          = $siloName
    UserAuthenticationPolicy      = $policyName
    ComputerAuthenticationPolicy  = $policyName
    ServiceAuthenticationPolicy   = $policyName
    Enforce                       = $false   # audit first
}
New-ADAuthenticationPolicySilo @siloParams
```

### 2.2 Members

```powershell
$members = @(
    (Get-ADUser 't0-admin'),
    (Get-ADComputer 'DC$'),
    (Get-ADComputer 'DC2$')
)
foreach ($m in $members) {
    Set-ADAccountAuthenticationPolicySilo -Identity $m.DistinguishedName -AuthenticationPolicySilo $siloName
    Grant-ADAuthenticationPolicySiloAccess -Identity $siloName -Account $m
}
```

### 2.3 Soak in audit for ≥24 h

Watch for 4820/4821/4823/4824 and events under `Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController`.

### 2.4 Enforce THEN reboot each DC

Order matters — see [Fixes log — 2026-09-27 #B](#silo-must-be-enforced-before-reboot-not-after).

```powershell
Set-ADAuthenticationPolicySilo -Identity $siloName -Enforce:$true
Restart-Computer -Force
```

### 2.5 Verify (post-audit-setup AND post-enforce)

`Get-ADAccountAuthenticationPolicySilo` does NOT exist as a cmdlet, and `MembersAndAccess` is not a valid property on `Get-ADAuthenticationPolicySilo`. Use the correct verification calls — see [Fixes log 2026-09-28 #5](#2026-09-28--5--phase-2-verification-cmdlets-corrected).

```powershell
# From the silo side - membership
Get-ADAuthenticationPolicySilo Tier0Silo | Format-List Name, Enforce, UserAuthenticationPolicy, Members

# From the account side - read msDS-AssignedAuthNPolicySilo directly
Get-ADUser     t0-admin -Properties msDS-AssignedAuthNPolicySilo | Select-Object Name, msDS-AssignedAuthNPolicySilo
Get-ADComputer DC       -Properties msDS-AssignedAuthNPolicySilo | Select-Object Name, msDS-AssignedAuthNPolicySilo
Get-ADComputer DC2      -Properties msDS-AssignedAuthNPolicySilo | Select-Object Name, msDS-AssignedAuthNPolicySilo

# Note: there is NO Get-ADAuthenticationPolicySiloAccess cmdlet in Server
# 2019's AD module (see Fixes log 2026-09-28 #5). The Grant-* verb writes to
# an internal msDS-* attribute that does NOT show up as per-account ACEs on
# the silo object in Get-Acl, so an ACL query on the silo is inconclusive.
# The audit soak below is the definitive test - if grants were missing, you
# would see 4820/4821 denials when t0-admin logs on under enforce.

# After ENFORCE + reboot: the DC's SYSTEM tickets should carry the silo claim
klist -li 0x3e7 | Select-String -Pattern 'Cache Flags|PRIMARY|krbtgt/'
```

Expected after 2.1-2.2:
- `Enforce : False` (audit)
- Silo `Members`: three DNs (t0-admin, DC$, DC2$)
- Each account's `msDS-AssignedAuthNPolicySilo` = the silo's DN
- ACL query shows t0-admin, DC$, DC2$ with ExtendedRight Allow

Expected after 2.4 (enforce + reboot):
- `Enforce : True`
- `whoami` as t0-admin still works
- Replication still 0 fails

Snapshot: `phase2-silo-audit` after 2.3; `phase2-tier0-enforced` after 2.6.

### 2.6 Recovery if enforce locks you out

If `t0-admin` cannot log in after enforce (silo/armoring mismatch): log in as built-in `Administrator` via the hypervisor console — RID-500 is exempt from silo enforcement (memory §4 gotcha #6) — then revert:

```powershell
Set-ADAuthenticationPolicySilo -Identity Tier0Silo -Enforce:$false
```

---

## Phase 4 — Coercion filters + Print Spooler

Save `dc-rpc-filters.rsp`:

```
rpc filter
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
add filter

add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add filter

add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=4fc742e0-4a10-11cf-8273-00aa004ae673
add filter

add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=12345678-1234-abcd-ef00-0123456789ab
add filter
```

Load and disable Spooler:

```powershell
netsh -f .\dc-rpc-filters.rsp
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
netsh rpc filter show filter
```

Snapshot: `phase4-coercion-blocked`.

---

## Phase 5 — DC network firewall + static RPC ports

**Where each sub-phase runs:**

| Sub-phase | Run on | Why |
|---|---|---|
| 5.1 Static ports | Both DCs (one at a time, reboot between) | Registry values are per-machine |
| 5.2 Post-reboot verify | Both DCs | Verify each machine's port state |
| 5.3 DCFWTool deploy | **ONE DC only** | Creates a domain-wide GPO |
| 5.4 `gpupdate /force` + verify | Both DCs | Each DC pulls and applies the GPO from AD |
| 5.5 Kali surface check | Kali | Attack path verification |

### 5.1 Static ports (on each DC, one at a time)

Paste-safe one-liners — no backtick continuation.

```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'TCP/IP Port' -Value 38901 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DCTcpipPort' -Value 38902 -PropertyType DWord -Force | Out-Null
dfsrdiag StaticRPC /Port:5722 /Member:$env:COMPUTERNAME
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'TCP/IP Port'
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'DCTcpipPort'
Restart-Computer -Force
```

### 5.2 Post-reboot verification (each DC)

```powershell
netstat -ano -p tcp | Select-String ':38901|:38902|:5722'
whoami
repadmin /replsummary
nltest /dsgetdc:lab.local
Test-NetConnection DC.lab.local  -Port 38901
Test-NetConnection DC2.lab.local -Port 38901
```

Expected: LISTENING on 38901/38902 (5722 only when replicating). Cross-DC `Test-NetConnection` returns `TcpTestSucceeded : True`. Self-tests may resolve to `fe80::…` — that's normal loopback.

If `/replsummary` shows stale `1908 (Could not find the domain controller for this domain)` errors after both reboots, force replication to clear them:

```powershell
repadmin /syncall DC.lab.local  /Aed /q
repadmin /syncall DC2.lab.local /Aed /q
Start-Sleep -Seconds 10
Get-ADReplicationPartnerMetadata -Target lab.local -Scope Domain | Format-Table Partner, LastReplicationResult, ConsecutiveReplicationFailures -AutoSize
```

### 5.3 Deploy DCFWTool GPO (ONE DC only)

Config file at `C:\Hardening\DCFWTool\Set-ADDSFirewallPolicy.json` — see the reference config committed in this repo. Key values for `lab.local`:

- `TargetDomain` = `"lab.local"`
- `ClientAddresses` = `[ "192.168.20.0/24" ]`
- `ManagementAddresses` = `[ "192.168.20.1", "192.168.20.2" ]` (DCs only, no jump host)
- `DomainControllerAddresses` = `[ "192.168.20.1", "192.168.20.2" ]`
- `RadiusClientAddresses` = `[]`
- `NtdsStaticPort` = `38901`, `NetlogonStaticPort` = `38902`, `DfsrStaticPort` = `5722`
- `EnableRpcFilters` = `true` (wipes Phase 4 `netsh` filters and installs a superset — verify UUIDs still present after)
- `EnablePrintSpooler` = `false` (matches Phase 4)
- `EnableRemoteDesktop` = `true`
- `BlockWmiCommandExecution` = `true`, `WmiStaticPort` = `true`

Deploy:

```powershell
cd C:\Hardening\DCFWTool
Get-Content .\Set-ADDSFirewallPolicy.json | Out-String  # sanity check
.\Set-ADDSFirewallPolicy.ps1
```

**Verify the link happened** — the tool sometimes creates the GPO but does not link it. See [Fixes log 2026-09-29 #6](#2026-09-29--6--phase-5-3-dcfwtool-created-the-gpo-but-did-not-link-it).

```powershell
Import-Module GroupPolicy
$dcOU = "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"
$links = Get-GPInheritance -Target $dcOU | Select-Object -ExpandProperty GpoLinks
if ($links.DisplayName -notcontains 'Domain Controller Firewall') {
    New-GPLink -Name 'Domain Controller Firewall' -Target $dcOU -LinkEnabled Yes -Enforced Yes
}
Get-GPInheritance -Target $dcOU | Select-Object -ExpandProperty GpoLinks | Format-Table DisplayName, Enabled, Enforced, Order -AutoSize
```

Must show two rows: `Default Domain Controllers Policy` and `Domain Controller Firewall`, both `Enabled : True`.

Force replication so DC2 sees the GPO link:

```powershell
repadmin /syncall DC.lab.local /Aed /q
Start-Sleep -Seconds 10
```

### 5.4 Apply on both DCs

Both DCs, sequentially:

```powershell
gpupdate /force
gpresult /r /scope:computer | Out-String
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction
netsh rpc filter show filter | Select-String -Pattern 'c681d488|df1941c5|4fc742e0|12345678 abcd1234' -Context 2
```

Expected:
- `gpresult` lists "Domain Controller Firewall" under **Applied Group Policy Objects**.
- `Get-NetFirewallProfile`: `DefaultInboundAction : Block` on Domain (typically also Private and Public).
- All four coercion UUIDs still blocked by the DCFWTool RPC filter set (supersets Phase 4).

Reboot each DC once, one at a time (DC first, wait for it to come back and replication clean, then DC2). Not simultaneously.

### 5.5 Attack surface check from Kali

```bash
nmap -Pn -sT -p 88,135,389,445,464,636,3268,3269,3389,5985,38901,38902,5722 192.168.20.1
```

Expected from Kali (in client subnet, NOT in Management/DomainController):
- **Open:** 88, 389, 464, 636, 3268, 3269 (Kerberos + LDAP + GC — client access allowed)
- **Filtered/closed:** 135 (RPC EPM restricted to Management), 445 (SMB), 3389 (RDP), 5985 (WinRM), 5722 (DFSR), 38901 (NTDS static), 38902 (Netlogon static)

If any "filtered/closed" port shows `open`, the GPO didn't apply — go back to 5.4.

### 5.6 Snapshot

After all four DCs (2 machines × before/after reboot) pass verification and Kali's `nmap` shows the expected open-vs-blocked split, snapshot both as `phase5-dcfw-live`.

---

## Phase 6 — RPC Firewall base rules

### 6.1 Config

File is `C:\Program Files\RpcFirewall\RpcFw.conf` — that exact filename, in the same directory as `rpcFwManager.exe`. See [Fixes log 2026-09-29 #7](#2026-09-29--7--phase-6-config-filename--rpc-filter-takeover) for why the filename and the `flt:` lines both matter.

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

Line meanings:
- `flt:` = RPC filter (interface-level block, wire-layer). The four UUIDs are MS-EFSR primary + secondary, MS-DFSNM, MS-RPRN — the four coercion primitives.
- `fw:` = RPC Firewall rule (interface + opnum + SID + action). Allows DRSUAPI opnum 3/5 for Enterprise Domain Controllers (S-1-5-9), blocks everything else.
- `audit:true` on every line = each decision produces an event in `RPCFW/Operational`.

**Why `flt:` lines belong here:** `rpcFwManager /start` and `/update` wipe **all** existing RPC filters before installing what's in the config. If you leave `flt:` out, every restart destroys the coercion filters DCFWTool installed in Phase 5. Placing the coercion UUIDs in `RpcFw.conf` makes rpcFwManager the single source of truth and keeps them alive across restarts.

Save via PowerShell here-string (paste-safe):

```powershell
cd 'C:\Program Files\RpcFirewall'
$conf = @'
flt:action:block audit:true uuid:c681d488-d850-11d0-8c52-00c04fd90f7e
flt:action:block audit:true uuid:df1941c5-fe89-4e79-bf10-463657acf44d
flt:action:block audit:true uuid:4fc742e0-4a10-11cf-8273-00aa004ae673
flt:action:block audit:true uuid:12345678-1234-abcd-ef00-0123456789ab
fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 sid:S-1-5-9 opnum:3 action:allow audit:true
fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 sid:S-1-5-9 opnum:5 action:allow audit:true
fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 opnum:3 action:block audit:true
fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 opnum:5 action:block audit:true
'@
Set-Content -Path .\RpcFw.conf -Value $conf -Encoding ASCII
```

### 6.2 Install, start, reboot — on every DC

```powershell
& '<install>\rpcFwManager.exe' /install
& '<install>\rpcFwManager.exe' /start
Restart-Computer -Force
```

`/install` alone does not attach — see [Fixes log — 2026-09-27 #C](#rpcfw-hook-only-loads-after-start--reboot).

### 6.3 Verify hook is in lsass

```powershell
Get-Process lsass -Module | Where-Object ModuleName -like "*RpcF*"
```

### 6.4 Validate

```bash
# From Kali
impacket-secretsdump lab.local/kali@192.168.20.1 -just-dc-user krbtgt
# Expect: rpc_s_access_denied
```

```powershell
Get-WinEvent -LogName 'RPCFW/Operational' -MaxEvents 20 |
    Where-Object Id -eq 3 | Format-List TimeCreated, Message
```

Snapshot: `phase6-rpcfw-live`.

---

## Phase 7 — DRS Request-Inspection module

Payload-layer detection sitting on top of Phase 6. Full module details in [rpcfirewall/rpcFirewall/drsInspect.cpp](rpcfirewall/rpcFirewall/drsInspect.cpp).

### 7.1 Deploy on each DC

```powershell
# Overlay the built rpcFireWall.dll at the rpcFwManager install path, then reboot.
# Then:
cd C:\Users\BigBoss\Desktop\Hardening\rpcfirewall\scripts
.\Deploy-DrsHarden.ps1 -SeedAllowlist
```

The seed allowlist covers Windows-internal DRSUAPI opnum 3 traffic from SYSTEM over loopback that would otherwise BLOCK in STRICT mode. See [Fixes log — 2026-09-27 #D](#strict-mode-blocks-legit-windows-internal-loopback-traffic).

### 7.2 AUDIT → DETECT → STRICT

| Level | Sentinels to touch | What blocks |
|---|---|---|
| AUDIT  | `drsi_enabled` | Nothing — decisions logged to `decisions.log`. |
| DETECT | + `drsi_enforce_shape` | Non-partner + single-object CN= target (Kali-style off-DC DCSync). |
| STRICT | + `drsi_enforce_sys_loopback` | Also SYSTEM (S-1-5-18) and loopback/link-local. |

Progress one level per week; grep `decisions.log` for recurring `enforced=0 decision=BLOCK` fingerprints and either allowlist them or accept them before escalating.

Snapshots: `phase7-audit`, `phase7-detect`, `phase7-strict`.

---

## Phase 8 — Host controls on the DCs

### 8.1 WDAC (the hard control for SYSTEM-on-DC)

```powershell
$policy = "$env:TEMP\dc-wdac.xml"
New-CIPolicy -FilePath $policy -Level Publisher -UserPEs -Fallback Hash
Set-RuleOption -FilePath $policy -Option 3    # Audit Mode ON first
$bin = "$env:TEMP\SiPolicy.p7b"
ConvertFrom-CIPolicy -XmlFilePath $policy -BinaryFilePath $bin
Copy-Item $bin C:\Windows\System32\CodeIntegrity\SiPolicy.p7b -Force
Restart-Computer -Force
```

Soak WDAC in audit for ≥ 1 week. Every 3076/3077 in `Microsoft-Windows-CodeIntegrity/Operational` = something that will break under enforce. Add publisher rules for the legitimate ones. Then remove `-Option 3` and redeploy.

### 8.2 RunAsPPL

```powershell
New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name RunAsPPL -Value 2 -PropertyType DWord -Force
```

Reboot.

### 8.3 EDR

Enable at minimum: lsass memory read alerts; Kerberos ticket export; machine-account credential extraction; suspicious mimikatz/impacket command lines.

### 8.4 krbtgt double-rotation

Use the community `Reset-KrbTgt-Password.ps1` script. Rotate twice with a ≥ 10 h gap.

```powershell
# Illustrative — script API varies by version
Reset-KrbTgt-Password -mode 1    # dry run
Reset-KrbTgt-Password -mode 4    # first reset
# wait > 10 hours
Reset-KrbTgt-Password -mode 4    # second reset
repadmin /replsummary
```

Snapshot: `phase8-host-controls-done`.

---

## Phase 9 — Telemetry off-box

Forward to a hardened collector via Windows Event Forwarding:

| Log | Event ID | Meaning |
|---|---|---|
| Security | 4662 | Replication rights invoked |
| Security | 4768 / 4769 | TGT / TGS request |
| Security | 4820 / 4821 / 4823 / 4824 | Silo / auth-policy denials |
| Microsoft-Windows-CodeIntegrity/Operational | 3076 / 3077 | WDAC audit / block |
| Windows Firewall/Firewall | 5157 | Firewall block |
| RPCFW/Operational | 3 | RPCFW audit-failure (DCSync/DCShadow attempt) |
| Sysmon | 1 | Process create — flag mimikatz / secretsdump / impacket-* |

Additionally, ship file logs from `$DataDir`:

- `decisions.log`
- `manifest.csv` and `.bin` files
- `partners.log`

Snapshot: `phase9-telemetry-live`.

---

## Phase 10 — Validation drills

### 10.1 Green-path (must stay working)

```powershell
repadmin /replsummary
repadmin /syncall /Aed /q
dcdiag /test:Replications /v
```

### 10.2 DCSync test matrix

| # | Attack | Where run from | Expected verdict | Catcher |
|---|---|---|---|---|
| 1 | `secretsdump lab.local/kali@dc -just-dc-user krbtgt` | Kali | rpc_s_access_denied | Phase 6 (SID rule) |
| 2 | Same as 1 with a DA account | Kali | rpc_s_access_denied | Phase 6 |
| 3 | Rogue-ACL DCSync from a user | Kali | rpc_s_access_denied | Phase 6 |
| 4 | `mimikatz lsadump::dcsync /all` as SYSTEM on DC | DC console | Blocked | Phase 7 STRICT |
| 5 | `$MACHINE.ACC` PTT, dcsync from same DC | DC console | Blocked | Phase 7 STRICT (loopback) |
| 6 | Stolen `DC$` key, dcsync from off-box | Kali | Blocked | Phase 7 DETECT (shape) |
| 7 | Same as 6 with Kali IP added to `partners.txt` | Kali | Alert only | Phase 8 (WDAC / EDR) |
| 8 | Compromise DC2, dcsync from DC2 → DC | DC2 console | Alert only | Phase 8 (WDAC blocks mimikatz on DC2) |

Record actual outcomes per snapshot.

### 10.3 Recovery drill (quarterly)

- Revert one DC to a "compromise" snapshot.
- Rotate krbtgt twice.
- Force full-domain replication.
- Confirm no pre-rotation forged ticket still authenticates.

### 10.4 Break-glass drill (quarterly)

- Deliberately break `t0-admin`.
- Log in as `Administrator` via hypervisor console.
- Repair `t0-admin`.

---

## Recovery cheat sheet

| Problem | Command |
|---|---|
| Locked out of `t0-admin` | Hypervisor console → login as `Administrator` (RID-500 is silo-exempt) |
| Replication broken | See [Fixes log — 2026-09-28 #2](#2026-09-28--2--replication-broken-by-strict-mode) |
| RPC Firewall wedged something | Delete relevant sentinel file under `$DataDir`; effect within 1 s |
| Full stack off | Stop `rpcFirewall` service, remove `$DataDir\*_enabled`, reboot |
| Everything on fire | Revert DC to the last known-good snapshot; then re-run phases from there |

---

## Fixes log

Newest first. Every entry names the phase it affects and the inline fix applied.

### 2026-09-29 · #10 · Surgical ncalrpc DRSUAPI block — closes local-SYSTEM DCSync bypass
<a id="2026-09-29--10--ncalrpc-drsuapi-surgical-block"></a>

- **Phase affected:** new sub-phase between Phase 4 and Phase 6 (RPC coercion filters + DRSUAPI ncalrpc gate).
- **Discovery:** while comparing DsBind captures for the SYSTEM-on-DC ceiling case, the transport-isolation test proved that mimikatz-as-SYSTEM running on a DC (targeting local DRSUAPI) uses `ncalrpc`, which our DLL early-returns on ([dllmain.cpp:1425](rpcfirewall/rpcFirewall/dllmain.cpp:1425)). That path bypassed the entire Phase 6 SID rule, DRSI, and Phase 1 capture. Test B (cross-DC via TCP) still succeeds — that is the genuine wire-level ceiling.
- **Fix applied:** persistent netsh RPC filter on both DCs blocking DRSUAPI over ncalrpc, gated by `remote_user_token` SDDL so it only fires when the caller's token is SYSTEM. Legit operator tools (Get-ADDomainController, repadmin /showrepl, dcdiag /test:Replications) continue to work because they run as t0-admin, not SYSTEM.
- **Filter definition** (save as `C:\Hardening\drs-ncalrpc-sys-block.rsp`, then `netsh -f <path>`):
  ```
  rpc filter
  add rule layer=um actiontype=block filterkey=e3514235-4b06-11d1-ab04-00c04fc2dc00
  add condition field=protocol matchtype=equal data=ncalrpc
  add condition field=if_uuid matchtype=equal data=e3514235-4b06-11d1-ab04-00c04fc2dcd2
  add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;SY)
  add filter
  ```
- **Effect measured:** mimikatz `lsadump::dcsync /user:krbtgt` run as SYSTEM on the local DC now returns `RPC Exception 0x00000005 (5)` at the DsBind. Cross-DC variant `/dc:<peer>` still succeeds — that path authenticates outbound as the DC machine account via Kerberos, and DC2 sees it as legit KCC replication (documented ceiling; WDAC required).
- **Persistence caveat:** netsh RPC filters survive reboots via WFP. However `rpcFwManager /start` and `/update` call `delete filter filterkey=all` before installing what's in `RpcFw.conf` (see Fixes log 2026-09-29 #7). If `RpcFw.conf` does not carry this rule (its `flt:` line format may not support `protocol` and `remote_user_token` conditions), you must reapply the netsh script after any rpcFirewall service restart. A boot-time scheduled task running `netsh -f C:\Hardening\drs-ncalrpc-sys-block.rsp` is the simplest guard.
- **What remains open:** cross-DC SYSTEM DCSync (attacker on DC1 → DC2 authenticating as DC1$). Wire is byte-identical to legit KCC. WDAC on the DCs is the mitigation. Memory §6 stands for this case; memory should be updated so §6 no longer applies to the local ncalrpc case.

### 2026-09-29 · #9 · Deploy-DrsHarden.ps1 — Scheduled task registration + false success
<a id="2026-09-29--9--deploy-drsharden-ps1-scheduled-task-registration"></a>

- **Phase affected:** Phase 7.1 (DRSI module deploy — scheduled task step)
- **Symptoms:**
  1. `Register-ScheduledTask` errored with `The task XML contains a value which is incorrectly formatted or out of range. (8,42):Duration:P99999999DT23H59M59S`.
  2. The script printed `task : scheduled '...' every 15 minutes` immediately after the error, giving a false positive.
  3. `Get-ScheduledTask` confirmed no task was actually registered.
- **Root causes:**
  1. The trigger set `-RepetitionDuration ([TimeSpan]::MaxValue)`. PowerShell serialises `MaxValue` to the ISO 8601 duration `P99999999DT23H59M59S`, which the Windows Task Scheduler XML schema rejects as out of range.
  2. `Register-ScheduledTask` was piped to `Out-Null` without a `try/catch`, so the failure bubbled to the pipeline error stream but the following `Write-Host` still executed unconditionally.
- **Fix applied:**
  1. Trigger no longer sets `-RepetitionDuration`. Omitting it makes the task repeat indefinitely, which is the desired behaviour.
  2. `Register-ScheduledTask` is now wrapped in `try/catch`. Success prints the confirmation; failure prints a warning with the exception message and a note that `partners.txt` won't auto-refresh.
- **Recovery for anyone who hit this state:** the rest of the script's work landed (DataDir, ACL, partners.txt, allowlist.txt, registry). Just pick up the patched script and re-run — it's idempotent and will register the task on the second pass.

### 2026-09-29 · #8 · Deploy-DrsHarden.ps1 — ACL clear bug
<a id="2026-09-29--8--deploy-drsharden-ps1-acl-clear-bug"></a>

- **Phase affected:** Phase 7.1 (DRSI module deploy)
- **Symptom:** `Deploy-DrsHarden.ps1 -SeedAllowlist` printed `DataDir : C:\Hardening\capture` and then errored:
  ```
  A positional parameter cannot be found that accepts argument
  'System.Security.AccessControl.FileSystemAccessRule'.
  ```
- **Root cause:** the script cleared existing ACEs with:
  ```powershell
  $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
  ```
  Some PowerShell 5.1 versions parse the pipeline inside `ForEach-Object` in a way that turns `$acl.RemoveAccessRule($_)` into a cmdlet-style positional call rather than a .NET method call, and reject the `FileSystemAccessRule` object as an unexpected positional parameter.
- **Fix applied:** rewritten to use the `foreach` statement and `[void]`, materialising the ACL collection first so we can iterate safely while removing:
  ```powershell
  $existingRules = @($acl.Access)
  foreach ($rule in $existingRules) { [void]$acl.RemoveAccessRule($rule) }
  ```
- **Recovery for anyone who hit this state:** the DataDir was created but the ACL lock and subsequent steps did not run. After picking up the fixed script, just re-run it — it's idempotent (checks for existing OU, existing t0-admin, existing sentinel files, etc., and only creates what's missing).

### 2026-09-29 · #7 · Phase 6 config filename + RPC filter takeover
<a id="2026-09-29--7--phase-6-config-filename--rpc-filter-takeover"></a>

- **Phase affected:** Phase 6 (RPC Firewall base rules)
- **Symptoms on `rpcFwManager.exe /start`:**
  1. `No configuration file found 636524360.` printed — the manager could not read the expected config file. Result: no firewall rules loaded.
  2. `Removing RPC Filters...` then `Creating RPC Filters...` — the manager wiped every existing RPC filter (including DCFWTool's Phase 5 set) and, because the config wasn't found, installed zero replacements. Coercion protection gone.
- **Root causes:**
  1. The runbook told the operator to save the config as `RpcFirewall.txt`. The manager actually looks for `RpcFw.conf` at the exe's own directory (`stdafx.h:8 #define CONF_FILE_NAME TEXT("RpcFw.conf")`, resolved in `common.cpp:120` relative to `rpcFwManager.exe`).
  2. `rpcFwManager /start` and `/update` do a wholesale `delete filter filterkey=all` before reinstalling from config. Anything installed by DCFWTool or `netsh -f` outside the manager's config file is destroyed on every service start.
- **Fix applied:**
  1. Runbook Phase 6.1 now specifies the filename as **`RpcFw.conf`** and shows the full config content saved via a here-string.
  2. The config now includes `flt:action:block audit:true uuid:<coercion UUID>` lines for the four coercion UUIDs (MS-EFSR ×2, MS-DFSNM, MS-RPRN) in addition to the four `fw:` DCSync rules. This makes rpcFwManager the single source of truth for RPC filters and ensures they survive every service restart.
- **Trade-off accepted:** DCFWTool's fuller RPC filter set (MS-EVEN, MS-SCMR, and others over named pipes) is lost until we replicate those `flt:` lines into `RpcFw.conf`. Not DCSync-critical; can be added later if the broader lateral-movement coverage matters.
- **Recovery for anyone who hit this state:**
  ```powershell
  cd 'C:\Program Files\RpcFirewall'
  if (Test-Path .\RpcFirewall.txt) { Remove-Item .\RpcFirewall.txt }
  # Save RpcFw.conf per Phase 6.1
  .\rpcFwManager.exe /update
  netsh rpc filter show filter | Select-String -Pattern 'c681d488|df1941c5|4fc742e0|12345678 abcd1234'
  # If /update doesn't reload, Stop-Service / Start-Service rpcFirewall
  ```

### 2026-09-29 · #6 · Phase 5.3 DCFWTool created the GPO but did not link it
<a id="2026-09-29--6--phase-5-3-dcfwtool-created-the-gpo-but-did-not-link-it"></a>

- **Phase affected:** Phase 5.3 (DCFWTool deploy)
- **Symptoms:**
  - `Set-ADDSFirewallPolicy.ps1` completed with only non-fatal warnings.
  - `Get-GPO -Name 'Domain Controller Firewall'` showed the GPO existed with `ComputerVersion : AD Version 18, SysVol Version 18` (settings written).
  - `Get-GPInheritance -Target "OU=Domain Controllers,..."` showed `GpoLinks : {Default Domain Controllers Policy}` — the new GPO was NOT linked.
  - `gpresult /r /scope:computer | Select-String 'Domain Controller Firewall'` returned nothing.
  - `Get-NetFirewallProfile` on both DCs showed `DefaultInboundAction : NotConfigured` after `gpupdate /force`.
  - `nmap` from Kali confirmed nothing was blocked: 88, 135, 389, 445, 464, 636, 3268, 3269, 5722, 5985, 38901, 38902 all `open`.
- **Root cause:** the tool created the GPO object but did not perform the link step on the Domain Controllers OU. Observed in v2.1 of DCFWTool — cause is not consistent (may relate to first-run permissions or an unsurfaced error).
- **Fix applied:** Phase 5.3 in the runbook now includes an explicit link step immediately after `Set-ADDSFirewallPolicy.ps1` succeeds, plus a verification that the GPO appears in `Get-GPInheritance`'s `GpoLinks` before proceeding to `gpupdate /force`.
- **Recovery command:**
  ```powershell
  Import-Module GroupPolicy
  $dcOU = "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"
  New-GPLink -Name 'Domain Controller Firewall' -Target $dcOU -LinkEnabled Yes -Enforced Yes
  Get-GPInheritance -Target $dcOU | Select-Object -ExpandProperty GpoLinks |
      Format-Table DisplayName, Enabled, Enforced, Order -AutoSize
  ```
  Then `gpupdate /force` on both DCs.
- **Tool warnings that were non-fatal in this run:** firewall log-size baseline mismatch (cosmetic — larger log = longer soak); SCCM incompatibility (no SCCM in lab); NPS+RADIUS warning (false positive from `RadiusClientAddresses: []`); ADMX Central Store missing (GPMC display cosmetic — settings still apply).

### 2026-09-28 · #5 · Phase 2 verification cmdlets corrected
<a id="2026-09-28--5--phase-2-verification-cmdlets-corrected"></a>

- **Phase affected:** Phase 2 (Tier-0 silo verification)
- **Symptoms:**
  1. `Get-ADAuthenticationPolicySilo Tier0Silo | Format-List Name, Enforce, UserAuthenticationPolicy, MembersAndAccess` returned `MembersAndAccess : {}` — looked like the silo had no members even though `Set-ADAccountAuthenticationPolicySilo` and `Grant-ADAuthenticationPolicySiloAccess` had all succeeded silently.
  2. `Get-ADAccountAuthenticationPolicySilo -Identity 't0-admin'` errored with `The term 'Get-ADAccountAuthenticationPolicySilo' is not recognized as the name of a cmdlet`.
  3. `Get-ADAuthenticationPolicySiloAccess -Identity Tier0Silo` errored the same way.
- **Root causes:**
  1. `MembersAndAccess` is not a valid property on `Get-ADAuthenticationPolicySilo`. The property that lists accounts assigned to the silo is `Members`. `Format-List` silently drops property names it doesn't find, hence the misleading `{}`.
  2. `Get-ADAccountAuthenticationPolicySilo` does not exist in the ActiveDirectory module. The `Set-` verb exists on the account side; there is no `Get-` counterpart. To check what silo an account is assigned to, read the LDAP attribute `msDS-AssignedAuthNPolicySilo` directly via `Get-ADUser` / `Get-ADComputer` with `-Properties`.
  3. `Get-ADAuthenticationPolicySiloAccess` also does not exist on Server 2019's ActiveDirectory module. The `Grant-` and `Revoke-` verbs exist for setting/removing the ExtendedRight ACE on the silo object, but no `Get-` verb. To inspect the grants, query the silo object's ACL with `Get-Acl "AD:<silo DN>"` and filter for the ExtendedRight ACEs.
- **Fix applied:** Phase 2.5 in the runbook now uses:
  - `Get-ADAuthenticationPolicySilo Tier0Silo | Format-List ... Members` (correct property)
  - `Get-ADUser` / `Get-ADComputer` with `-Properties msDS-AssignedAuthNPolicySilo` (account-side)
  - `Get-Acl "AD:<silo DN>"` and filter for non-BUILTIN ExtendedRight ACEs (grantee inspection, optional)

### 2026-09-28 · #4 · Phase 1.0 password-rotation backtick + t0-admin outside Tier-0 OU + UAC deny-only groups
<a id="2026-09-28--4--phase-10-password-rotation-backtick--t0-admin-outside-tier-0-ou--uac-deny-only-groups"></a>

- **Phase affected:** Phase 1.0
- **Symptoms:**
  1. `Set-ADAccountPassword -Identity Administrator -Reset \` (backtick continuation) broke on the blank line the console echoed. PowerShell executed `Set-ADAccountPassword ... -Reset` with no `-NewPassword`, which fell back to an interactive `Password:` prompt. What was typed there is unknown; then `-NewPassword (ConvertTo-SecureString ...)` on the next line was parsed as a bad standalone command. Net effect: Administrator's password ended up in an uncertain state until a one-liner retry set it explicitly.
  2. `New-ADUser @userParams` failed with `The specified account already exists` because a prior half-created `t0-admin` had survived (in `CN=Users`, not the intended `OU=Tier-0`). Group memberships and password reset then applied to the wrong-location account.
  3. `whoami /groups` in the fresh `t0-admin` session showed `Domain Admins`, `Enterprise Admins`, `Schema Admins` as `Group used for deny only`, which looked broken but was actually normal UAC token filtering in a non-elevated shell.
- **Fixes applied to the runbook:**
  1. Phase 1.0 step 5 is now a **one-liner** `Set-ADAccountPassword ... -Reset -NewPassword (ConvertTo-SecureString ...)`. No backtick continuation anywhere in Phase 1.0. General rule reinforced from the earlier fix.
  2. Phase 1.0 step 2 is now **idempotent**: if `t0-admin` already exists it is reset, re-enabled, and moved into `OU=Tier-0`; if not, it is created fresh. Step 3 `Add-ADGroupMember` calls are wrapped in `-ErrorAction SilentlyContinue` so re-runs don't fail on "already a member".
  3. Phase 1.0 step 6 explicitly tells the operator to launch **elevated** PowerShell as `t0-admin` and states that "Group used for deny only" in a non-elevated shell is expected UAC behavior, not a failure. In an elevated shell the groups appear as enabled.
- **Recovery for anyone who hit this session's state (Administrator pw unclear, t0-admin in `CN=Users`):**
  ```powershell
  Import-Module ActiveDirectory
  $dn = (Get-ADDomain).DistinguishedName
  # Move t0-admin
  $u = Get-ADUser t0-admin
  if ($u.DistinguishedName -notlike "*OU=Tier-0,*") {
      Move-ADObject -Identity $u.DistinguishedName -TargetPath "OU=Tier-0,$dn"
  }
  # Re-rotate Administrator password authoritatively as a one-liner
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $b = New-Object byte[] 32; $rng.GetBytes($b)
  $pw = ([Convert]::ToBase64String($b)).Substring(0, 32)
  Write-Host "==> RECORD: $pw" -ForegroundColor Yellow
  Set-ADAccountPassword -Identity Administrator -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $pw -Force)
  Get-ADUser Administrator -Properties PasswordLastSet | Select-Object Name, PasswordLastSet
  Remove-Variable pw
  ```

### 2026-09-28 · #3 · Phase 0 output dir and broken pipeline paste
<a id="2026-09-28--3--phase-0-output-dir-and-broken-pipeline-paste"></a>

- **Phase affected:** Phase 0
- **Symptoms:**
  1. `dcdiag /test:Replications /v > C:\Users\BigBoss\Desktop\Hardening\baseline_repl.txt` failed with `Could not find a part of the path` because that directory only exists on the workstation, not on the DC.
  2. Multi-line pipeline `(Get-Acl "AD:$nc").Access | Where-Object ... | Format-Table ...` pasted across blank lines errored with `An empty pipe element is not allowed`. Same class of issue as the earlier backtick continuation problem — the console terminated the statement on an empty line.
- **Fixes applied:**
  1. Runbook now creates `C:\Hardening` on the DC as a first step of Phase 0 and writes baseline output there.
  2. The ACL enumeration is now a single-statement three-liner: hoist the ACL to `$acl`, hoist the GUIDs to `$replRights`, then one flat pipeline on one line. No blank lines mid-pipeline.
- **General rule reinforced:** in this runbook, no command uses backtick continuation and no multi-line pipeline crosses a blank line. Use splatting, hoist to intermediate variables, or write on one line.
- **Environmental observation logged:** after the snapshot revert, only `DC` exists (no `DC2`). Runbook now calls out that single-DC state is expected during a fresh rebuild and that `repadmin /replsummary` being empty in that case is not a bug. Phases that assume two DCs are noted.

### 2026-09-28 · #2 · Replication broken by STRICT mode

- **Phase affected:** Phase 7 (STRICT enforce)
- **Symptom:** `repadmin /replicate` returned `LDAP Error 82 (Local Error)` on one direction and `0x80090334 — server requires user-to-user but didn't send a TGT reply` on the other, ~24 h after enabling `drsi_enforce`.
- **Root cause:** The single `drsi_enforce` sentinel enforced both the shape rule and the SYSTEM/loopback rule. A Windows-internal producer of DRSUAPI opnum 3 from SYSTEM over link-local IPv6 (source `fe80::…`) was silently blocked for ~24 h, cascading into stale Kerberos state.
- **Fix applied:** Split enforce into two independent sentinels — `drsi_enforce_shape` and `drsi_enforce_sys_loopback` — plus an `allowlist.txt` and a deploy script that seeds the allowlist with the DC's own loopback/link-local addresses. Runbook Phase 7 now walks AUDIT → DETECT → STRICT and requires a full audit soak before STRICT.
- **Recovery steps that worked:**
  1. `Remove-Item C:\Hardening\capture\drsi_enforce` on both DCs
  2. `klist purge` and `klist -li 0x3e7 purge` on both DCs
  3. `nltest /sc_reset:lab.local` on both DCs
  4. `Restart-Service NETLOGON -Force` on both DCs
  5. If Kerberos still wedged: `netdom resetpwd /server:<peer DC> /userd:<recovery> /passwordd:*`
  6. `repadmin /syncall /Aed /q`

### 2026-09-28 · #1 · Backtick line continuation broke Phase 1.0

- **Phase affected:** Phase 1.0 — Create Tier-0 admin
- **Symptom:** Pasting the multi-line `New-ADUser` with trailing backticks into the PowerShell console produced errors like `-AccountPassword : The term '-AccountPassword' is not recognized`. Later, the same command as a one-liner failed with `The specified account already exists` because the earlier partial paste had already created `t0-admin` in a disabled/no-password state.
- **Root cause:** PowerShell backtick continuation is fragile when pasted into a shell that echoes `>>` continuation prompts — the shell can terminate the statement on the empty line, executing only the first fragment. The partial `New-ADUser -Name 't0-admin' -SamAccountName 't0-admin'` succeeded (defaults: disabled, no password), and the remaining `-Enabled`, `-Path`, etc. were parsed as unknown standalone commands.
- **Fix applied:** All multi-line commands in this runbook now use **splatting** (a `@params` hashtable) instead of backtick continuation. Splatting is fully paste-safe and unambiguous.
- **Also fixed in the same session:** `Set-ADAccountPassword` for Administrator used `[System.Web.Security.Membership]::GeneratePassword(32,6)`, which fails with `Unable to find type [System.Web.Security.Membership]` because `System.Web` is not loaded by default in Windows PowerShell 5.1 on Server 2019. Replaced with a dependency-free RNG via `System.Security.Cryptography.RandomNumberGenerator` + `Convert.ToBase64String`.
- **Cleanup for anyone who hit this:** see the [Immediate cleanup section](#immediate-cleanup--recover-from-a-half-created-t0-admin) — resets password, enables the account, moves it into `OU=Tier-0` if needed.

### 2026-09-27 · #D · STRICT mode blocks legit Windows-internal loopback traffic
<a id="strict-mode-blocks-legit-windows-internal-loopback-traffic"></a>

- **Phase affected:** Phase 7 STRICT
- **Symptom:** Even with `partners.txt` populated correctly and `drsi_enforce` set, some Windows-internal component periodically made DRSUAPI opnum 3 calls from SYSTEM (S-1-5-18) over link-local IPv6 (`fe80::…`). These got `decision=BLOCK enforced=1` and eventually broke replication.
- **Fix applied:** Deploy script now seeds `allowlist.txt` with `ip-prefix:fe80::`, `ip-prefix:127.`, `ip:::1`, and `sid+ip:S-1-5-18@<own fe80 addresses>`. Allowlist is consulted before any BLOCK rule.

### 2026-09-27 · #C · RPCFW hook only loads after /start + reboot
<a id="rpcfw-hook-only-loads-after-start--reboot"></a>

- **Phase affected:** Phase 6
- **Symptom:** DCSync from Kali still succeeded after running only `rpcFwManager.exe /install`.
- **Root cause:** `/install` writes the service and registers config; the DLL is only injected into lsass after `/start` and (reliably) a reboot.
- **Fix applied:** Phase 6.2 explicitly lists `/install` → `/start` → `Restart-Computer` as three separate steps and adds a `Get-Process lsass -Module` verification step.

### 2026-09-27 · #B · Silo must be enforced BEFORE reboot, not after
<a id="silo-must-be-enforced-before-reboot-not-after"></a>

- **Phase affected:** Phase 2
- **Symptom:** After turning on silo enforcement and rebooting a DC, the DC's own machine-account tickets lacked the `Tier0Silo` claim and its own membership checks failed closed. `t0-admin` was denied under all conditions.
- **Root cause:** The DC only picks up the silo claim on its next TGT fetch under enforcement. Reboot before enforce → TGT is claim-less; enforce → membership check fails.
- **Fix applied:** Phase 2.4 sets `Enforce:$true` first, then reboots.

### 2026-09-27 · #A · Kerberos armor key must be under \Parameters subkey
<a id="armor-key-must-be-under-parameters-subkey"></a>

- **Phase affected:** Phase 3
- **Symptom:** Registry value `EnableCbacAndArmor` set at `…\KDC\EnableCbacAndArmor` read back as `1`, but the KDC ignored it. Silo lockouts under enforce.
- **Root cause:** The KDC only honors the value under the `\Parameters` subkey, i.e. `…\KDC\Parameters\EnableCbacAndArmor` and `…\Kerberos\Parameters\EnableCbacAndArmor`.
- **Fix applied:** Phase 3 commands explicitly create the `\Parameters` path if absent and set the value there.

---

## Appendix A — Adding a new DC after hardening

The full stack is in place and you want to promote a new DC (say `DC3`). Promotion itself is a DRSUAPI opnum 3/5 flow, so it will be caught by every layer that filters DCSync unless you allowlist first. Memory §4 gotcha #5.

**Pre-promotion allowlisting on every existing DC**, in this order:

1. **DCFWTool `DomainControllerAddresses`.** Add the new DC's IP and re-apply the GPO. Without this, the new DC can't reach the DCs on the static NTDS port.
   ```powershell
   # Update the DCFWTool config and re-run its script per its own docs
   ```
2. **RPC Firewall config.** If you use IP-based rules (`addr:` form), add the new DC's IP to the allow lines. If you use the identity rule (`sid:S-1-5-9`), it self-maintains — the promoted DC will join Enterprise DCs automatically. Verify your config:
   ```powershell
   Get-Content '<install>\RpcFirewall.txt'
   ```
3. **DRSI `partners.txt`.** If you're running the Deploy-DrsHarden scheduled task, it auto-refreshes from `Get-ADDomainController` — but only *after* promotion. For the promotion phase itself, either add the new DC IP manually as a `static:` line, or temporarily remove `drsi_enforce_shape` on the existing DCs.

**Then promote** as in Phase 0.5.

**Post-promotion**:
- The scheduled task on each existing DC picks up the new DC on its next 15-minute refresh.
- Verify `partners.log` on each DC shows the count increased.
- Re-enable `drsi_enforce_shape` if you removed it.

**Verify replication is green on all pairs**:
```powershell
repadmin /replsummary
Get-ADReplicationFailure -Target lab.local
```

If any pair fails with `rpc_s_access_denied` or `The target principal name is incorrect`, one of the three allowlisting steps above was missed.

---

## Appendix B — Advanced: local-SYSTEM DCSync block (ncalrpc SDDL filter)

### What this closes

mimikatz DCSync run as SYSTEM directly on a DC (`psexec -s mimikatz.exe "lsadump::dcsync /user:krbtgt"` or the same via Task Scheduler as SYSTEM) uses the local RPC endpoint (`ncalrpc`) to reach DRSUAPI. That path bypasses the entire network-layer stack:

- Phase 6 SID rule never evaluates (the DLL early-returns on ncalrpc bindings).
- Phase 7 DRSI never sees the request.
- Phase 1 capture doesn't record it.

Empirically verified in this lab (2026-09-29 transport-isolation test). See [Fixes log 2026-09-29 #10](#2026-09-29--10--ncalrpc-drsuapi-surgical-block).

This appendix installs a targeted `netsh rpc filter` that blocks DRSUAPI over ncalrpc **only when the caller's primary token is SYSTEM (S-1-5-18)**. Legit operator tools (`repadmin`, `dcdiag`, `Get-ADDomainController`) continue to work because they run as t0-admin.

### What this does NOT close

Cross-DC mimikatz-as-SYSTEM (`lsadump::dcsync /dc:<peer>`) authenticates outbound as the DC's machine account via Kerberos over TCP. The request arriving at the peer DC is byte-identical to legitimate KCC replication. This is the true wire-level ceiling. **Phase 8 (WDAC)** is the mitigation for that case.

Combined coverage after this appendix + Phase 6 + Phase 7:

| Attack shape | Result |
|---|---|
| Off-DC DCSync as any non-DC identity (Kali, DA user, etc.) | Blocked (Phase 6 SID rule) |
| DCShadow (opnum 5) from non-DC identity | Blocked (Phase 6) |
| **Local mimikatz-as-SYSTEM on DC** | **Blocked (this appendix)** |
| Cross-DC mimikatz-as-SYSTEM using machine-account Kerberos | Still succeeds → Phase 8 |

### Prerequisites

- Phase 6 (RPC Firewall base rules) live and healthy on both DCs.
- Elevated PowerShell as `t0-admin` on each DC.
- `C:\Hardening\` directory exists.
- Have the transport-isolation test script (`Test-DcsyncTransports.ps1`) available so you can verify the effect.

### One-shot install (per DC)

Run all four blocks in order on **each** DC. All are paste-safe (no backtick continuation, no blank-line pipeline breaks).

**B.1 — Save the filter definition:**

```powershell
$rsp = @'
rpc filter
delete filter filterkey=e3514235-4b06-11d1-ab04-00c04fc2dc00
add rule layer=um actiontype=block filterkey=e3514235-4b06-11d1-ab04-00c04fc2dc00
add condition field=protocol matchtype=equal data=ncalrpc
add condition field=if_uuid matchtype=equal data=e3514235-4b06-11d1-ab04-00c04fc2dcd2
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;SY)
add filter
'@
Set-Content -Path C:\Hardening\drs-ncalrpc-sys-block.rsp -Value $rsp -Encoding ASCII
```

The `delete filter` step at the top makes the script idempotent — safe to re-run. First-run warning `RpcpFwpmFilterDeleteByKey failed -- 2150760451 (0x80320003)` means "filter didn't exist yet" and is benign; the subsequent `add` succeeds.

**B.2 — Apply immediately and verify:**

```powershell
netsh -f C:\Hardening\drs-ncalrpc-sys-block.rsp
$fk='e3514235-4b06-11d1-ab04-00c04fc2dc00'; if (netsh rpc filter show filter | Select-String -Quiet $fk) { Write-Host 'OK filter present' -ForegroundColor Green } else { Write-Host 'MISSING' -ForegroundColor Red }
```

**B.3 — Install the 5-minute repeater task.** The rpcFirewall service's `/start` and `/update` code paths call `delete filter filterkey=all` before reinstalling from `RpcFw.conf` — see [Fixes log 2026-09-29 #7](#2026-09-29--7--phase-6-config-filename--rpc-filter-takeover). That wipes our netsh filter on any service restart, including at boot. The 5-minute repeater restores the filter within that window regardless of when the service cycles.

```powershell
Unregister-ScheduledTask -TaskName 'DrsuapiNcalrpcSysBlock' -Confirm:$false -ErrorAction SilentlyContinue
$rspPath='C:\Hardening\drs-ncalrpc-sys-block.rsp'; $filterKey='e3514235-4b06-11d1-ab04-00c04fc2dc00'; $psCmd="& { netsh -f '$rspPath' | Out-Null; if ((netsh rpc filter show filter | Select-String -Quiet '$filterKey')) { exit 0 } else { exit 2 } }"; $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -Command `"$psCmd`""; $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5); $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName 'DrsuapiNcalrpcSysBlock' -Description 'Reapply DRSUAPI ncalrpc SYSTEM-token block every 5 min - defeats rpcFirewall filter wipe on service restart.' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
```

**B.4 — Force-run once and confirm the task returns 0:**

```powershell
Start-ScheduledTask -TaskName 'DrsuapiNcalrpcSysBlock'; Start-Sleep -Seconds 3; Get-ScheduledTaskInfo -TaskName 'DrsuapiNcalrpcSysBlock' | Format-List LastRunTime, LastTaskResult
```

Expected `LastTaskResult : 0`. The wrapper exits 0 only when the filter is confirmed present after `netsh -f`, so anything other than 0 is a real failure to diagnose.

### Validation (per DC)

**Legit tools must still work:**

```powershell
Get-ADDomainController -Filter *
repadmin /showrepl | Select-String 'was successful|failed'
dcdiag /test:Replications /q
```

`Get-ADDomainController` returns both DCs; `repadmin /showrepl` shows successful entries; `dcdiag` returns silent (no errors).

**Local SYSTEM DCSync must block:**

```powershell
cd C:\Hardening; .\Test-DcsyncTransports.ps1 -PeerDcFqdn '<the OTHER DC FQDN>'
```

Expected on this DC:
- Test A (local, default target): **BLOCKED** — `ERROR kull_m_rpc_drsr_getDCBind ; RPC Exception 0x00000005 (5)`.
- Test B (cross-DC, forced peer): **SUCCEEDED** — this is the remaining ceiling; Phase 8 closes it.

**Reboot survival:**

Reboot the DC, wait 6 minutes (past the first 5-min repeater firing after service start), then:

```powershell
$fk='e3514235-4b06-11d1-ab04-00c04fc2dc00'; if (netsh rpc filter show filter | Select-String -Quiet $fk) { Write-Host 'OK filter present after reboot' -ForegroundColor Green } else { Write-Host 'BAD - still missing' -ForegroundColor Red }
```

Must show OK.

### Snapshot

After both DCs pass validation + reboot survival, snapshot both as `phase-appendix-b-live` (or your naming preference).

### Uninstall

If Appendix B ever breaks a legitimate use case that appears later:

```powershell
Unregister-ScheduledTask -TaskName 'DrsuapiNcalrpcSysBlock' -Confirm:$false
netsh rpc filter delete filter filterkey=e3514235-4b06-11d1-ab04-00c04fc2dc00
```

The local-SYSTEM ncalrpc bypass returns immediately. No other state changes.

### Why this isn't in the core path

Three reasons the core path stops at Phase 7 and treats this as optional:

1. **Operational responsibility.** The 5-min repeater is a scheduled task that has to keep running. If someone disables it and the filter gets wiped by an rpcFirewall service restart, protection quietly disappears. That maintenance burden is a real cost.
2. **Case coverage.** Cross-DC SYSTEM DCSync (Test B) is still un-blocked and is the harder-to-execute-but-more-realistic attack path. WDAC (Phase 8) closes both cases. If you're going to do Phase 8 anyway, Appendix B is redundant for the enforcement side and only useful for the audit signal it produces.
3. **Portability.** The SDDL `remote_user_token` condition works on Server 2019 and later, but behavior on older builds is untested here.

Do this appendix when: you want the local-SYSTEM case closed today, Phase 8 is weeks away, and you're willing to own the maintenance task.

---

_End of runbook._

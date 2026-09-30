# DCSync Hardening — Clean Step-by-Step

Distilled build guide. Every command below is copy-paste as-is; every step has been verified end-to-end in the lab.

Read once, then run top-to-bottom.

## Environment

- Domain: `lab.local`
- DC: `DC.lab.local` (`192.168.20.1`)
- DC2: `DC2.lab.local` (`192.168.20.2`)
- Client subnet: `192.168.20.0/24`
- Working dir on each DC: `C:\Hardening\`
- Privileged account you'll create in Phase 1.0: `t0-admin`

## Conventions

- Commands are one line each unless annotated otherwise. No backtick line continuations. No multi-line pipelines across blank lines.
- Snapshot both DCs before each numbered phase.
- Every phase runs as `t0-admin` (elevated) except Phase 1.0 which runs as the built-in `Administrator`.

---

## Phase 0 — Baseline

**On DC (elevated Administrator, since t0-admin doesn't exist yet):**

```powershell
New-Item -ItemType Directory C:\Hardening -Force | Out-Null
```

```powershell
Import-Module ActiveDirectory
```

```powershell
dcdiag /q
```

```powershell
dcdiag /test:Replications /v > C:\Hardening\baseline_repl.txt
```

```powershell
repadmin /replsummary
```

```powershell
Get-ADDomainController -Filter * | Select Name, HostName, IPv4Address, Site
```

```powershell
Get-ADDomain | Select DNSRoot, DomainSID, DomainMode, ForestMode
```

Verify no rogue principals hold replication rights:

```powershell
$nc = (Get-ADDomain).DistinguishedName; $replRights = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c'); (Get-Acl "AD:$nc").Access | Where-Object { $_.ObjectType -in $replRights } | Format-Table IdentityReference, ActiveDirectoryRights, ObjectType
```

Expected principals only: `SYSTEM`, `BUILTIN\Administrators`, `ENTERPRISE DOMAIN CONTROLLERS`, `Domain Controllers`, `Enterprise Read-only Domain Controllers`. Anything else is a finding — remove it before proceeding.

Snapshot: `phase0-baseline`.

---

## Phase 0.5 — Add DC2 (skip if you already have two DCs)

**On the future DC2** (fresh Windows Server VM, local Administrator):

```powershell
Rename-Computer -NewName DC2 -Force
```

```powershell
$if = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1).ifIndex; New-NetIPAddress -InterfaceIndex $if -IPAddress 192.168.20.2 -PrefixLength 24 -DefaultGateway 192.168.20.1; Set-DnsClientServerAddress -InterfaceIndex $if -ServerAddresses 192.168.20.1
```

```powershell
Restart-Computer -Force
```

After DC2 comes back:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
```

```powershell
Import-Module ADDSDeployment
```

```powershell
$safeMode = Read-Host -AsSecureString -Prompt 'DSRM Administrator password'
```

```powershell
$cred = Get-Credential -Message 'Enter as lab\Administrator (DOMAIN\user), NOT bare Administrator'
```

```powershell
$promote = @{ DomainName='lab.local'; SafeModeAdministratorPassword=$safeMode; Credential=$cred; SiteName='Default-First-Site-Name'; InstallDns=$true; NoRebootOnCompletion=$false; Force=$true }; Install-ADDSDomainController @promote
```

DC2 reboots automatically. After it comes back, verify on DC:

```powershell
Get-ADDomainController -Filter * | Select Name, HostName, IPv4Address, Site
```

```powershell
repadmin /replsummary
```

```powershell
dcdiag /test:Replications /q
```

Snapshot both DCs: `phase0.5-dc2-joined`.

---

## Phase 1.0 — Create the Tier-0 admin

**On DC as built-in Administrator (elevated):**

```powershell
Import-Module ActiveDirectory; $dn = (Get-ADDomain).DistinguishedName
```

```powershell
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Tier-0'" -SearchBase $dn -ErrorAction SilentlyContinue)) { New-ADOrganizationalUnit -Name 'Tier-0' -Path $dn -ProtectedFromAccidentalDeletion $true }
```

Create t0-admin (splatting, paste-safe):

```powershell
$pw = Read-Host -AsSecureString -Prompt 'Strong password for t0-admin'
```

```powershell
$existing = Get-ADUser -Filter "SamAccountName -eq 't0-admin'" -ErrorAction SilentlyContinue; if ($existing) { Set-ADAccountPassword -Identity t0-admin -Reset -NewPassword $pw; Set-ADUser -Identity t0-admin -Enabled $true -ChangePasswordAtLogon $false; if ($existing.DistinguishedName -notlike "*OU=Tier-0,*") { Move-ADObject -Identity $existing.DistinguishedName -TargetPath "OU=Tier-0,$dn" } } else { $userParams = @{ Name='t0-admin'; SamAccountName='t0-admin'; UserPrincipalName="t0-admin@$((Get-ADDomain).DNSRoot)"; AccountPassword=$pw; Enabled=$true; Path="OU=Tier-0,$dn"; PasswordNeverExpires=$false; CannotChangePassword=$false }; New-ADUser @userParams }
```

```powershell
Add-ADGroupMember 'Domain Admins' -Members t0-admin -ErrorAction SilentlyContinue; Add-ADGroupMember 'Enterprise Admins' -Members t0-admin -ErrorAction SilentlyContinue; Add-ADGroupMember 'Schema Admins' -Members t0-admin -ErrorAction SilentlyContinue
```

Mark built-in Administrator as break-glass (do NOT disable):

```powershell
Set-ADUser Administrator -Description 'BREAK-GLASS ONLY. Use t0-admin for all normal admin.'
```

Rotate Administrator password to a random value (record the output in your password manager):

```powershell
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $bytes = New-Object byte[] 32; $rng.GetBytes($bytes); $adminPw = ([Convert]::ToBase64String($bytes)).Substring(0,32); Write-Host "==> COPY TO PASSWORD MANAGER NOW <==" -ForegroundColor Yellow; Write-Host $adminPw; Read-Host -Prompt 'Press Enter after saving'; Set-ADAccountPassword -Identity Administrator -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $adminPw -Force); Get-ADUser Administrator -Properties PasswordLastSet | Select-Object Name, PasswordLastSet; Remove-Variable adminPw
```

**Log out. Log back in as `t0-admin` on the DC console. Launch elevated PowerShell.** In an elevated shell, `whoami /groups | Select-String 'Domain Admins'` shows `Enabled group` — that confirms UAC token elevation is active. Do all further work from this session (or the same on DC2 as needed).

Verify:

```powershell
Get-ADUser t0-admin -Properties Enabled, MemberOf | Format-List Name, Enabled, DistinguishedName, MemberOf
```

Snapshot both DCs: `phase1.0-tier0-admin-created`.

---

## Phase 1 — Identity layer

**On DC as t0-admin (elevated):**

OWNER RIGHTS restriction on the domain NC:

```powershell
$nc = (Get-ADDomain).DistinguishedName; $acl = Get-Acl "AD:$nc"; $ownerRights = New-Object System.Security.Principal.SecurityIdentifier('S-1-3-4'); $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($ownerRights, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead, [System.Security.AccessControl.AccessControlType]::Allow); $acl.AddAccessRule($rule); Set-Acl -Path "AD:$nc" -AclObject $acl
```

SACL 4662 auditing on replication rights:

```powershell
$rights = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c'); $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0'); $sacl = Get-Acl "AD:$nc" -Audit; foreach ($g in $rights) { $auditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($everyone, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, [System.Security.AccessControl.AuditFlags]'Success,Failure', [Guid]$g); $sacl.AddAuditRule($auditRule) }; Set-Acl -Path "AD:$nc" -AclObject $sacl
```

Enable the DS Access audit subcategory:

```cmd
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

Honeytoken account:

```powershell
$dn = (Get-ADDomain).DistinguishedName; $honeyPw = Read-Host -AsSecureString -Prompt 'Random password for honeytoken (>=32 chars, discard)'
```

```powershell
$honeyParams = @{ Name='svc_replreader'; SamAccountName='svc_replreader'; Description='DO NOT USE - Honeytoken (DCSync detection)'; Enabled=$false; Path="CN=Users,$dn"; AccountPassword=$honeyPw }; New-ADUser @honeyParams; Add-ADGroupMember 'Backup Operators' svc_replreader
```

```powershell
$user = Get-ADUser svc_replreader; $path = "AD:$($user.DistinguishedName)"; $sacl = Get-Acl $path -Audit; $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule((New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0'), 'GenericAll', 'Success,Failure'); $sacl.AddAuditRule($rule); Set-Acl $path $sacl
```

Snapshot: `phase1-identity-done`.

---

## Phase 3 — Kerberos armoring (BEFORE Phase 2)

**On each DC (elevated as t0-admin):**

```powershell
$kdc = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'; $cli = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; foreach ($p in @($kdc, $cli)) { if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }; New-ItemProperty -Path $p -Name EnableCbacAndArmor -Value 1 -PropertyType DWord -Force | Out-Null }
```

```powershell
Get-ItemProperty $kdc EnableCbacAndArmor
```

```powershell
Get-ItemProperty $cli EnableCbacAndArmor
```

```powershell
Restart-Computer -Force
```

Post-reboot verification on each DC:

```powershell
whoami
```

```powershell
repadmin /replsummary
```

```powershell
klist -li 0x3e7 | Select-String -Pattern 'Cache Flags|PRIMARY|krbtgt/'
```

Snapshot: `phase3-armoring-verified`.

---

## Phase 2 — Tier-0 silo

**On DC as t0-admin (elevated):**

```powershell
Import-Module ActiveDirectory; $policyName = 'Tier0-Auth'; $siloName = 'Tier0Silo'
```

```powershell
New-ADAuthenticationPolicy -Name $policyName -UserAllowedToAuthenticateFrom "O:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(ED)}))"
```

```powershell
$siloParams = @{ Name=$siloName; UserAuthenticationPolicy=$policyName; ComputerAuthenticationPolicy=$policyName; ServiceAuthenticationPolicy=$policyName; Enforce=$false }; New-ADAuthenticationPolicySilo @siloParams
```

Assign members:

```powershell
$members = @((Get-ADUser -Identity 't0-admin'), (Get-ADComputer -Identity 'DC$'), (Get-ADComputer -Identity 'DC2$')); foreach ($m in $members) { Set-ADAccountAuthenticationPolicySilo -Identity $m.DistinguishedName -AuthenticationPolicySilo $siloName; Grant-ADAuthenticationPolicySiloAccess -Identity $siloName -Account $m }
```

Verify:

```powershell
Get-ADAuthenticationPolicySilo Tier0Silo | Format-List Name, Enforce, UserAuthenticationPolicy, Members
```

```powershell
Get-ADUser t0-admin -Properties msDS-AssignedAuthNPolicySilo | Select-Object Name, msDS-AssignedAuthNPolicySilo
```

```powershell
Get-ADComputer DC -Properties msDS-AssignedAuthNPolicySilo | Select-Object Name, msDS-AssignedAuthNPolicySilo
```

```powershell
Get-ADComputer DC2 -Properties msDS-AssignedAuthNPolicySilo | Select-Object Name, msDS-AssignedAuthNPolicySilo
```

Snapshot: `phase2-silo-audit`. Soak in audit for at least 24 h + one reboot cycle. Watch 4820/4821 events on both DCs.

**When ready to enforce (after clean soak):**

```powershell
Set-ADAuthenticationPolicySilo -Identity Tier0Silo -Enforce:$true
```

```powershell
repadmin /syncall DC.lab.local /Aed /q
```

Reboot each DC one at a time (DC first, wait for it to be back and clean, then DC2).

Snapshot: `phase2-tier0-enforced`.

**Recovery if enforce locks out t0-admin:** log in as built-in `Administrator` via hypervisor console (RID-500 is silo-exempt), then `Set-ADAuthenticationPolicySilo -Identity Tier0Silo -Enforce:$false`.

---

## Phase 4 — Coercion filters + Print Spooler off

**On each DC:**

```powershell
$rsp = @'
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
'@; if (-not (Test-Path C:\Hardening)) { New-Item -ItemType Directory C:\Hardening -Force | Out-Null }; Set-Content -Path C:\Hardening\dc-rpc-filters.rsp -Value $rsp -Encoding ASCII
```

```powershell
netsh -f C:\Hardening\dc-rpc-filters.rsp
```

```powershell
Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled
```

Verify:

```powershell
netsh rpc filter show filter
```

```powershell
Get-Service Spooler | Select-Object Name, Status, StartType
```

Snapshot: `phase4-coercion-blocked`.

---

## Phase 5 — DC network firewall + static RPC ports

### 5.1 Static ports (each DC, one at a time)

```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'TCP/IP Port' -Value 38901 -PropertyType DWord -Force | Out-Null
```

```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DCTcpipPort' -Value 38902 -PropertyType DWord -Force | Out-Null
```

```powershell
dfsrdiag StaticRPC /Port:5722 /Member:$env:COMPUTERNAME
```

```powershell
Restart-Computer -Force
```

Post-reboot on each DC:

```powershell
netstat -ano -p tcp | Select-String ':38901|:38902|:5722'
```

```powershell
repadmin /replsummary
```

### 5.2 DCFWTool GPO (run on ONE DC only)

Clone the tool:

```powershell
cd C:\Hardening
```

```powershell
git clone https://github.com/MichaelGrafnetter/active-directory-firewall.git DCFWTool
```

Create the config file `C:\Hardening\DCFWTool\Set-ADDSFirewallPolicy.json` with these values for lab.local:

```json
{
    "$schema": "Set-ADDSFirewallPolicy.schema.json",
    "GroupPolicyObjectName": "Domain Controller Firewall",
    "TargetDomain": "lab.local",
    "LogDroppedPackets": true,
    "LogAllowedPackets": false,
    "LogMaxSizeKilobytes": 32767,
    "ClientAddresses": [ "192.168.20.0/24" ],
    "ManagementAddresses": [ "192.168.20.1", "192.168.20.2" ],
    "DomainControllerAddresses": [ "192.168.20.1", "192.168.20.2" ],
    "RadiusClientAddresses": [],
    "NtdsStaticPort": 38901,
    "NetlogonStaticPort": 38902,
    "FrsStaticPort": 38903,
    "DfsrStaticPort": 5722,
    "WmiStaticPort": true,
    "RestrictADWS": true,
    "DisableNetbiosBroadcasts": true,
    "DisableLLMNR": true,
    "DisableMDNS": true,
    "BlockManagementFromDomainControllers": false,
    "EnableRemoteDesktop": true,
    "EnableWindowsRemoteManagement": true,
    "EnableNetworkProtection": true,
    "BlockWmiCommandExecution": true,
    "EnableRpcFilters": true,
    "EnableLocalIPsecRules": false,
    "EnablePrintSpooler": false
}
```

Deploy:

```powershell
cd C:\Hardening\DCFWTool; .\Set-ADDSFirewallPolicy.ps1
```

Verify the GPO was created AND linked:

```powershell
Import-Module GroupPolicy; $dcOU = "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"; $links = Get-GPInheritance -Target $dcOU | Select-Object -ExpandProperty GpoLinks; if ($links.DisplayName -notcontains 'Domain Controller Firewall') { New-GPLink -Name 'Domain Controller Firewall' -Target $dcOU -LinkEnabled Yes -Enforced Yes }
```

```powershell
Get-GPInheritance -Target $dcOU | Select-Object -ExpandProperty GpoLinks | Format-Table DisplayName, Enabled, Enforced, Order -AutoSize
```

Force replication:

```powershell
repadmin /syncall DC.lab.local /Aed /q
```

### 5.3 Apply on both DCs

On each DC:

```powershell
gpupdate /force
```

```powershell
gpresult /r /scope:computer | Select-String -Pattern 'Applied Group Policy Objects' -Context 0,3
```

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction
```

Reboot each DC one at a time.

Snapshot: `phase5-dcfw-live`.

---

## Phase 6 — RPC Firewall base rules

Build `rpcFireWall.dll`, `rpcFwManager.exe`, `rpcMessages.dll` from your rpcfirewall project on the workstation (Visual Studio, Release | x64).

Copy the four files to each DC at `C:\Program Files\RpcFirewall\` (create the dir first). Also copy to `C:\Windows\System32\rpcFireWall.dll` so lsass finds it there:

```powershell
New-Item -ItemType Directory 'C:\Program Files\RpcFirewall' -Force | Out-Null
```

Copy `rpcFireWall.dll`, `rpcFwManager.exe`, `rpcMessages.dll` into `C:\Program Files\RpcFirewall\`, and `rpcFireWall.dll` into `C:\Windows\System32\`.

Then save the config as `C:\Program Files\RpcFirewall\RpcFw.conf`:

```powershell
cd 'C:\Program Files\RpcFirewall'
```

```powershell
$conf = @'
flt:action:block audit:true uuid:c681d488-d850-11d0-8c52-00c04fd90f7e
flt:action:block audit:true uuid:df1941c5-fe89-4e79-bf10-463657acf44d
flt:action:block audit:true uuid:4fc742e0-4a10-11cf-8273-00aa004ae673
flt:action:block audit:true uuid:12345678-1234-abcd-ef00-0123456789ab
fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 sid:S-1-5-9 opnum:3 action:allow audit:true
fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 sid:S-1-5-9 opnum:5 action:allow audit:true
fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 opnum:3 action:block audit:true
fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 opnum:5 action:block audit:true
'@; Set-Content -Path .\RpcFw.conf -Value $conf -Encoding ASCII
```

Install and start on each DC (in order):

```powershell
.\rpcFwManager.exe /install
```

```powershell
.\rpcFwManager.exe /start
```

```powershell
Restart-Computer -Force
```

Post-reboot verification on each DC:

```powershell
Get-Process lsass -Module | Where-Object ModuleName -like "*RpcF*" | Format-Table Size, ModuleName, FileName -AutoSize
```

Attack test from Kali (`192.168.20.50`):

```bash
impacket-secretsdump 'lab.local/t0-admin:<pw>@192.168.20.1' -just-dc-user krbtgt
impacket-secretsdump 'lab.local/t0-admin:<pw>@192.168.20.2' -just-dc-user krbtgt
```

Both must return `rpc_s_access_denied`. On each DC, confirm the block was logged:

```powershell
Get-WinEvent -FilterHashtable @{LogName='RPCFW'; Id=3} -MaxEvents 5 | Format-List TimeCreated, Message
```

Snapshot: `phase6-rpcfw-live`.

---

## Phase 7 — DRS Request-Inspection module

Copy `Deploy-DrsHarden.ps1` from your project's `rpcfirewall/scripts/` to `C:\Hardening\` on each DC.

**On each DC:**

```powershell
cd C:\Hardening; .\Deploy-DrsHarden.ps1 -SeedAllowlist
```

Verify:

```powershell
$dir = (Get-ItemProperty 'HKLM:\SOFTWARE\Hardening\DrsInspect').DataDir; Get-Content "$dir\partners.txt"
```

```powershell
Get-ScheduledTask -TaskName HardeningDrsInspectPartnersRefresh | Format-Table TaskName, State -AutoSize
```

**Turn on AUDIT:**

```powershell
$dir = (Get-ItemProperty 'HKLM:\SOFTWARE\Hardening\DrsInspect').DataDir; New-Item -ItemType File "$dir\drsi_enabled" | Out-Null
```

Generate one legit and one attack cycle:

```powershell
repadmin /syncall DC.lab.local /Aed /q
```

From Kali:

```bash
impacket-secretsdump 'lab.local/t0-admin:<pw>@192.168.20.1' -just-dc-user krbtgt
```

Read decisions.log:

```powershell
$dir = (Get-ItemProperty 'HKLM:\SOFTWARE\Hardening\DrsInspect').DataDir; Get-Content "$dir\decisions.log" -Tail 10
```

Expected: legit replication logs `decision=ALLOW partner=1`; Kali attack logs `decision=BLOCK enforced=0`.

Snapshot: `phase7-audit`.

**When ready to promote to DETECT (after 24 h soak with zero surprise BLOCK verdicts):**

```powershell
$dir = (Get-ItemProperty 'HKLM:\SOFTWARE\Hardening\DrsInspect').DataDir; New-Item -ItemType File "$dir\drsi_enforce_shape" | Out-Null
```

Re-attack from Kali — should still block; decisions.log line now shows `enforced=1`.

Snapshot: `phase7-detect`.

---

## Phase 8 — WDAC (recommended next; not covered in detail here)

Build a WDAC policy in audit mode from what's already on the DC. Soak at least a week watching `Microsoft-Windows-CodeIntegrity/Operational` events 3076/3077. Add publisher/hash rules for anything flagged as legitimate. Then enforce.

Phase 8 is the mitigation for the one remaining DCSync path: cross-DC mimikatz-as-SYSTEM, where the attacker uses the DC's Kerberos machine-account context to authenticate outbound to a peer DC. That path is byte-identical to legitimate KCC replication at the wire; WDAC blocks by preventing mimikatz from executing at all.

---

## Optional advanced: local-SYSTEM DCSync block

The steps below close the on-DC local-SYSTEM DCSync path (mimikatz-as-SYSTEM using ncalrpc). Do this if you want that case blocked before Phase 8 WDAC lands.

**On each DC (elevated as t0-admin):**

Save the filter definition:

```powershell
$rsp = @'
rpc filter
delete filter filterkey=e3514235-4b06-11d1-ab04-00c04fc2dc00
add rule layer=um actiontype=block filterkey=e3514235-4b06-11d1-ab04-00c04fc2dc00
add condition field=protocol matchtype=equal data=ncalrpc
add condition field=if_uuid matchtype=equal data=e3514235-4b06-11d1-ab04-00c04fc2dcd2
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;SY)
add filter
'@; Set-Content -Path C:\Hardening\drs-ncalrpc-sys-block.rsp -Value $rsp -Encoding ASCII
```

Apply and verify:

```powershell
netsh -f C:\Hardening\drs-ncalrpc-sys-block.rsp
```

```powershell
$fk='e3514235-4b06-11d1-ab04-00c04fc2dc00'; if (netsh rpc filter show filter | Select-String -Quiet $fk) { Write-Host 'OK filter present' -ForegroundColor Green } else { Write-Host 'MISSING' -ForegroundColor Red }
```

Install the 5-minute reapply task (rpcFwManager's service restart wipes all RPC filters, so we reapply on a schedule):

```powershell
Unregister-ScheduledTask -TaskName 'DrsuapiNcalrpcSysBlock' -Confirm:$false -ErrorAction SilentlyContinue
```

```powershell
$rspPath='C:\Hardening\drs-ncalrpc-sys-block.rsp'; $filterKey='e3514235-4b06-11d1-ab04-00c04fc2dc00'; $psCmd="& { netsh -f '$rspPath' | Out-Null; if ((netsh rpc filter show filter | Select-String -Quiet '$filterKey')) { exit 0 } else { exit 2 } }"; $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -Command `"$psCmd`""; $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5); $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName 'DrsuapiNcalrpcSysBlock' -Description 'Reapply DRSUAPI ncalrpc SYSTEM-token block every 5 min.' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
```

Force-run once:

```powershell
Start-ScheduledTask -TaskName 'DrsuapiNcalrpcSysBlock'; Start-Sleep -Seconds 3; Get-ScheduledTaskInfo -TaskName 'DrsuapiNcalrpcSysBlock' | Format-List LastRunTime, LastTaskResult
```

Must show `LastTaskResult : 0`.

Validate legit tools:

```powershell
Get-ADDomainController -Filter *
```

```powershell
repadmin /showrepl | Select-String 'was successful|failed'
```

```powershell
dcdiag /test:Replications /q
```

All must work (no RPC access-denied).

Reboot test: after reboot, wait ~6 minutes then run:

```powershell
$fk='e3514235-4b06-11d1-ab04-00c04fc2dc00'; if (netsh rpc filter show filter | Select-String -Quiet $fk) { Write-Host 'OK filter present after reboot' -ForegroundColor Green } else { Write-Host 'BAD - still missing' -ForegroundColor Red }
```

Snapshot: `phase-optional-ncalrpc-block-live`.

**Uninstall (if it ever breaks something later):**

```powershell
Unregister-ScheduledTask -TaskName 'DrsuapiNcalrpcSysBlock' -Confirm:$false; netsh rpc filter delete filter filterkey=e3514235-4b06-11d1-ab04-00c04fc2dc00
```

---

## Attack-matrix validation

After completing the core phases (and optionally the advanced ncalrpc block), the state of each attack path:

| Attack | Result |
|---|---|
| Kali `secretsdump` (any non-DC identity) | Blocked (Phase 6 SID rule) |
| mimikatz DCSync as `t0-admin` (Domain Admin) on either DC | Blocked (Phase 6 — DA doesn't inherit S-1-5-9) |
| mimikatz DCShadow as `t0-admin` | Blocked (Phase 6 opnum-5 rule) |
| PetitPotam / DFSCoerce / PrinterBug | Blocked (Phase 4 RPC filters) |
| mimikatz-as-SYSTEM local DCSync (ncalrpc) | Blocked if optional appendix is deployed; otherwise open (Phase 8 also closes) |
| mimikatz-as-SYSTEM cross-DC DCSync | Open — Phase 8 (WDAC) required |
| Legit DC-to-DC replication | Green throughout |

---

## Recovery quick reference

| Problem | Action |
|---|---|
| Locked out of `t0-admin` after silo enforce | Log in as built-in `Administrator` via hypervisor console; `Set-ADAuthenticationPolicySilo -Identity Tier0Silo -Enforce:$false` |
| Replication broken | `klist purge`; `nltest /sc_reset:lab.local`; `Restart-Service NETLOGON -Force`; `repadmin /syncall DC.lab.local /Aed /q` |
| RPCFW wedged something | Remove sentinel under `C:\Hardening\capture\` (`drsi_enforce_shape`, `drsi_enforce`, `drsi_enabled`); effect within 1 s |
| ncalrpc filter breaks a legit tool | Uninstall commands under Optional advanced |
| Everything wrong | Revert both DCs to the last named snapshot |

---

_End of build._

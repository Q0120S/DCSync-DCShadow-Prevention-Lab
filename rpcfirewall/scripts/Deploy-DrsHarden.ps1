<#
.SYNOPSIS
    Deploy and maintain the DRS Request-Inspection module on a domain
    controller. Works in any AD environment (no hardcoded domain/DC names).

.DESCRIPTION
    Run once on each DC as an elevated administrator. Actions:

      1. Determine the data directory (registry override or default).
      2. Create the data directory with restrictive ACLs.
      3. Populate partners.txt from Get-ADDomainController.
      4. Register a scheduled task that refreshes partners.txt every 15
         minutes so replication topology changes propagate automatically.
      5. Optionally seed allowlist.txt with the DC's own machine account
         SID and its known loopback / link-local addresses so that
         Windows-internal DRSUAPI traffic is not blocked when STRICT mode
         is later enabled.

    The DLL swap and lsass reload are NOT part of this script - overlay
    the built rpcFireWall.dll at the rpcFwManager install path and reboot
    the DC yourself, per the existing operational runbook.

.PARAMETER DataDir
    Where the module reads/writes its config and logs. Defaults to
    'C:\Hardening\capture'. Written to HKLM:\SOFTWARE\Hardening\DrsInspect\DataDir
    so the DLL uses the same path.

.PARAMETER SeedAllowlist
    If set, add an initial allowlist.txt entry allowing DRSUAPI opnum 3
    calls from the DC's own loopback / link-local addresses under
    S-1-5-18. Recommended before enabling STRICT mode; skip if you want
    to observe those decisions unfiltered first.

.PARAMETER SkipScheduledTask
    Skip registration of the refresh task. Use when the task is managed
    elsewhere (SCCM, DSC, GPO).

.EXAMPLE
    .\Deploy-DrsHarden.ps1

.EXAMPLE
    .\Deploy-DrsHarden.ps1 -DataDir 'D:\Ops\DrsInspect' -SeedAllowlist
#>

[CmdletBinding()]
param(
    [string]$DataDir,
    [switch]$SeedAllowlist,
    [switch]$SkipScheduledTask
)

$ErrorActionPreference = 'Stop'

function Test-Elevated {
    $me = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($me)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Elevated)) {
    throw "Run this script as an elevated administrator."
}

# ---- Resolve DataDir ---------------------------------------------------
$RegKey = 'HKLM:\SOFTWARE\Hardening\DrsInspect'
if (-not $DataDir) {
    if (Test-Path $RegKey) {
        $existing = (Get-ItemProperty -Path $RegKey -Name DataDir -ErrorAction SilentlyContinue).DataDir
        if ($existing) { $DataDir = $existing }
    }
}
if (-not $DataDir) {
    $DataDir = 'C:\Hardening\capture'
}
$DataDir = $DataDir.TrimEnd('\')

Write-Host "DataDir : $DataDir"

# ---- Persist the DataDir in the registry -------------------------------
if (-not (Test-Path $RegKey)) {
    New-Item -Path $RegKey -Force | Out-Null
}
Set-ItemProperty -Path $RegKey -Name DataDir -Value $DataDir -Type String

# ---- Create DataDir with restrictive ACLs ------------------------------
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
}

# Lock down: SYSTEM and Administrators full control; nothing else.
# Use `foreach` (statement) and materialize the collection first so we can
# safely iterate while removing. `ForEach-Object { $acl.RemoveAccessRule($_) }`
# gets mis-parsed by some PS versions as a cmdlet call with a positional
# argument - see Deploy-DrsHarden.ps1 bug fix (Fixes log 2026-09-29 #8).
$acl = Get-Acl $DataDir
[void]$acl.SetAccessRuleProtection($true, $false)
$existingRules = @($acl.Access)
foreach ($rule in $existingRules) {
    [void]$acl.RemoveAccessRule($rule)
}
$sysRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'NT AUTHORITY\SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')
$acl.AddAccessRule($sysRule)
$acl.AddAccessRule($adminRule)
Set-Acl -Path $DataDir -AclObject $acl
Write-Host "ACL     : locked to SYSTEM + Administrators"

# ---- Populate partners.txt ---------------------------------------------
function Update-PartnersFile {
    param([string]$Path)

    $ips = @()
    try {
        $ips = Get-ADDomainController -Filter * |
            ForEach-Object {
                # Prefer IPv4Address, fall back to a DNS lookup if empty
                if ($_.IPv4Address) { $_.IPv4Address }
                else {
                    (Resolve-DnsName -Name $_.HostName -Type A -ErrorAction SilentlyContinue).IPAddress
                }
            } |
            Where-Object { $_ } |
            Sort-Object -Unique
    } catch {
        Write-Warning "Get-ADDomainController failed: $($_.Exception.Message)"
    }

    if (-not $ips) {
        Write-Warning "No DC IPs discovered. Not overwriting $Path."
        return
    }

    # Preserve any user-added static entries under a "STATIC:" marker.
    $static = @()
    if (Test-Path $Path) {
        $static = Get-Content $Path |
            Where-Object { $_ -match '^\s*#\s*static\b' -or $_ -match '^\s*static:' } |
            Where-Object { $_ -notmatch '^\s*#' }
    }

    $body = @()
    $body += "# Auto-generated by Deploy-DrsHarden.ps1 on $(Get-Date -Format o)"
    $body += "# Add manual overrides on lines starting with 'static:' - they survive refresh."
    $body += $ips
    if ($static) { $body += ''; $body += '# preserved static entries'; $body += $static }

    Set-Content -Path $Path -Value $body -Encoding ASCII
    Write-Host "partners: $($ips.Count) DC IP(s) written -> $Path"
}

$partnersFile = Join-Path $DataDir 'partners.txt'
Update-PartnersFile -Path $partnersFile

# ---- Optionally seed allowlist -----------------------------------------
$allowlistFile = Join-Path $DataDir 'allowlist.txt'
if ($SeedAllowlist -and -not (Test-Path $allowlistFile)) {
    $ownLocal = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -like 'fe80::*' } |
        Select-Object -ExpandProperty IPAddress |
        ForEach-Object { ($_ -split '%')[0] }

    $seed = @(
        '# Allowlist for the DRS Request-Inspection module.',
        '# Syntax (one per line):',
        '#   sid:<SID>              - always ALLOW under this primary SID',
        '#   ip:<addr>              - always ALLOW from this address',
        '#   sid+ip:<SID>@<addr>    - always ALLOW when both match',
        '#   ip-prefix:<prefix>     - always ALLOW when srcAddr starts with prefix',
        '',
        '# Seeded by Deploy-DrsHarden.ps1 to permit Windows-internal',
        '# DRSUAPI opnum 3 traffic that originates from SYSTEM on this DC',
        '# over its own link-local IPv6. Remove these to observe those',
        '# calls unfiltered in decisions.log.',
        'ip-prefix:fe80::',
        'ip-prefix:127.',
        'ip:::1'
    )
    foreach ($addr in $ownLocal) {
        $seed += "sid+ip:S-1-5-18@$addr"
    }
    Set-Content -Path $allowlistFile -Value $seed -Encoding ASCII
    Write-Host "allowlist: seeded -> $allowlistFile"
} elseif ($SeedAllowlist) {
    Write-Host "allowlist: already exists, leaving as-is: $allowlistFile"
}

# ---- Register scheduled task to refresh partners.txt every 15 minutes --
if (-not $SkipScheduledTask) {
    $taskName = 'HardeningDrsInspectPartnersRefresh'
    $scriptPath = $MyInvocation.MyCommand.Path
    $arg = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-Command', "& { Import-Module ActiveDirectory; & '$scriptPath' -DataDir '$DataDir' -SkipScheduledTask }"
    )
    $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument ($arg -join ' ')
    # -RepetitionDuration ([TimeSpan]::MaxValue) serializes to
    # 'P99999999DT23H59M59S' which Task Scheduler rejects as out of range
    # (see Fixes log 2026-09-29 #9). Omitting -RepetitionDuration makes the
    # task repeat indefinitely, which is what we want.
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
        Write-Host "task    : scheduled '$taskName' every 15 minutes"
    }
    catch {
        Write-Warning "task    : FAILED to register '$taskName' - $($_.Exception.Message)"
        Write-Warning "         partners.txt will NOT auto-refresh. Fix and re-run, or refresh manually."
    }
}

# ---- Report the sentinel matrix so the operator knows what to toggle ---
Write-Host ""
Write-Host "Sentinel files in $DataDir (touch/create to enable):"
Write-Host "  drsi_enabled                 - module runs (audit-only)  [required]"
Write-Host "  drsi_enforce_shape           - shape BLOCK enforced       [DETECT]"
Write-Host "  drsi_enforce_sys_loopback    - sys+loopback BLOCK enforced [STRICT]"
Write-Host "  drsi_enforce                 - legacy: both of the above"
Write-Host "  drsi_alert_blocks            - also block on ALERT verdicts"
Write-Host ""
Write-Host "Do NOT enable STRICT until decisions.log shows only attack-shaped"
Write-Host "local_system=1 / loopback=1 lines during an audit soak. Add benign"
Write-Host "producers to allowlist.txt first."

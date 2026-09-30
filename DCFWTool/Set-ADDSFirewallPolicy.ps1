<#
.SYNOPSIS
Creates or modifies a Group Policy Object (GPO) that configures the Windows Firewall for Domain Controllers (DCs).

.DESCRIPTION

.PARAMETER ConfigurationFileName
Specifies the name of the configuration file from which some firewall settings are applied.

.EXAMPLE
PS> .\Set-ADDSFirewallPolicy.ps1 -Verbose

.EXAMPLE
PS> .\Set-ADDSFirewallPolicy.ps1 -ConfigurationFileName Set-ADDSFirewallPolicy.Contoso.json -Verbose

.LINK
Online documentation: https://firewall.dsinternals.com

.NOTES
Author:  Michael Grafnetter
Version: 2.9

#>

#Requires -Modules NetSecurity,GroupPolicy,ActiveDirectory
#Requires -Version 5

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ConfigurationFileName = 'Set-ADDSFirewallPolicy.json'
)

# Apply additional runtime validation
Set-StrictMode -Version Latest -ErrorAction Stop

# Stop script execution if any error occurs, to be on the safe side.
# Overrides the -ErrorAction parameter of all cmdlets.
$script:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

# Not all cmdlets inherit the -Verbose parameter, so we need to explicitly override it.
[bool] $isVerbose = $VerbosePreference -eq [System.Management.Automation.ActionPreference]::Continue

# Preload the required modules
# Ignore any warnings, including 'Unable to find a default server with Active Directory Web Services running.'
# Suppress the verbosity for module loading
Import-Module -Name NetSecurity,GroupPolicy,ActiveDirectory -WarningAction SilentlyContinue -Verbose:$false

#region Configuration

# Set the default configuration values, which can be overridden by an external JSON file
class ScriptSettings {
    # The name of the Group Policy Object (GPO) that will be created or updated.
    [string]           $GroupPolicyObjectName         = 'Domain Controller Firewall'

    # The comment that will be added to the Group Policy Object (GPO).
    [string]           $GroupPolicyObjectComment      = 'This GPO is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script.'

    # The domain in which the Group Policy Object (GPO) will be created or updated.
    [string]           $TargetDomain                  = $null

    # Indicates whether the packets dropped by the firewall should be logged.
    [bool]             $LogDroppedPackets             = $false
    
    # Indicates whether the packets allowed by the firewall should be logged.
    [bool]             $LogAllowedPackets             = $false

    # The path to the log file that will be used to store information about the allowed and/or dropped packets.
    [string]           $LogFilePath                   = '%systemroot%\system32\logfiles\firewall\pfirewall.log'

    # The maximum size of the firewall log file in kilobytes.
    [uint16]           $LogMaxSizeKilobytes           = [int16]::MaxValue

    # List of client IP adresses from which inbound traffic should be allowed.
    [string[]]         $ClientAddresses               = @('Any')

    # List of IP addresses from which inbound management traffic should be allowed.
    [string[]]         $ManagementAddresses           = @('Any')

    # List of domain controller IP addresses, between which replication and optionally management traffic should be allowed.
    [string[]]         $DomainControllerAddresses     = @('Any')

    # List of RADIUS client IP adresses from which inbound traffic should be allowed.
    [string[]]         $RadiusClientAddresses         = @('Any')

    # Static port to be used for inbound Active Directory RPC traffic.
    [Nullable[uint16]] $NtdsStaticPort                = $null

    # Static port to be used for inbound Netlogon traffic.
    [Nullable[uint16]] $NetlogonStaticPort            = $null

    # Static port to be used for DFSR traffic.
    [Nullable[uint16]] $DfsrStaticPort                = $null

    # Static port to be used for legacy FRS traffic.
    [Nullable[uint16]] $FrsStaticPort                 = $null

    # Indicates whether WMI traffic should use a static port.
    [Nullable[bool]]   $WmiStaticPort                 = $null

    # Indicates whether the Active Directory Web Services (ADWS) should only be available from management IPs.
    [bool]             $RestrictADWS                  = $false

    # Indicates whether the NetBIOS protocol should be switched to P-node (point-to-point) mode.
    [Nullable[bool]]   $DisableNetbiosBroadcasts      = $null

    # Indicates whether the Link-Local Multicast Name Resolution (LLMNR) client should be disabled.
    [bool]             $DisableLLMNR                  = $false

    # Indicates whether the Multicast DNS (mDNS) client should be disabled.
    [Nullable[bool]]   $DisableMDNS                   = $null

    # Indicates whether management traffic from other domain controllers should be blocked.
    [bool]             $BlockManagementFromDomainControllers = $false

    # Indicates whether remote service management should be enabled.
    [bool]             $EnableServiceManagement       = $true

    # Indicates whether remote event log management should be enabled.
    [bool]             $EnableEventLogManagement      = $true

    # Indicates whether remote scheduled task management should be enabled.
    [bool]             $EnableScheduledTaskManagement = $true

    # Indicates whether inbound Windows Remote Management traffic should be enabled.
    [bool]             $EnableWindowsRemoteManagement = $true

    # Indicates whether remote performance log access should be enabled.
    [bool]             $EnablePerformanceLogAccess    = $true

    # Indicates whether inbound OpenSSH traffic should be enabled.
    [bool]             $EnableOpenSSHServer           = $true

    # Indicates whether inbound Remote Desktop Protocol traffic should be enabled.
    [bool]             $EnableRemoteDesktop           = $true

    # Indicates whether remote disk management should be enabled.
    [bool]             $EnableDiskManagement          = $true

    # Indicates whether remote backup management should be enabled.
    [bool]             $EnableBackupManagement        = $true

    # Indicates whether remote firewall management should be enabled.
    [bool]             $EnableFirewallManagement      = $true

    # Indicates whether inbound COM+ management traffic should be enabled.
    [bool]             $EnableComPlusManagement       = $true

    # Indicates whether inbound legacy file replication traffic should be enabled.
    [bool]             $EnableLegacyFileReplication   = $true

    # Indicates whether inbound NetBIOS Name Service should be allowed.
    [bool]             $EnableNetbiosNameService      = $true

    # Indicates whether inbound NetBIOS Datagram Service traffic should be allowed.
    [bool]             $EnableNetbiosDatagramService  = $true

    # Indicates whether inbound NetBIOS Session Service (NBSS) traffic should be allowed.
    [bool]             $EnableNetbiosSessionService   = $true

    # Indicates whether inbound Windows Internet Name Service (WINS) traffic should be allowed.
    [bool]             $EnableWINS                    = $true

    # Indicates whether inbound Dynamic Host Configuration Protocol (DHCP) server traffic should be allowed.
    [bool]             $EnableDhcpServer              = $true

    # Indicates whether inbound Network Policy Server (NPS) / RADIUS traffic should be allowed.
    [bool]             $EnableNPS                     = $true

    # Indicates whether inbound Key Management Service (KMS) traffic should be allowed.
    [bool]             $EnableKMS                     = $true

    # Indicates whether inbound Windows Server Update Services (WSUS) traffic should be allowed.
    [bool]             $EnableWSUS                    = $true
    
    # Indicates whether inbound Windows Deployment Services (WDS) traffic should be allowed.
    [bool]             $EnableWDS                     = $true
    
    # Indicates whether inbound http.sys-based web server traffic on default HTTP and HTTPS ports should be allowed.
    [bool]             $EnableWebServer               = $true
    
    # Indicates whether inbound File Server Resource Manager (FSRM) management traffic should be allowed.
    [bool]             $EnableFSRMManagement          = $true

    # Indicates whether inbound Print Spooler traffic through RPC over TCP should be allowed.
    [bool]             $EnablePrintSpooler            = $true

    # Indicates whether the Network protection feature of Microsoft Defender Antivirus should be enabled.
    [Nullable[bool]]   $EnableNetworkProtection       = $null

    # Indicates whether to block process creations originating from PSExec and WMI commands using Defender ASR.
    [Nullable[bool]]   $BlockWmiCommandExecution      = $null

    # Indicates whether additional filtering of RPC over Named Pipes should be applied.
    [Nullable[bool]]   $EnableRpcFilters              = $null

    # Indicates whether local IPSec rules should be enabled.
    [bool]             $EnableLocalIPsecRules         = $true

    # Specifies the name(s) of additional script file(s) containing firewall rules that will be imported into the Group Policy Object (GPO).
    [string[]]         $CustomRuleFileNames           = $null
}

[ScriptSettings] $configuration = [ScriptSettings]::new()

# Load the configuration from the JSON file
[string] $configurationFilePath = Join-Path -Path $PSScriptRoot -ChildPath $ConfigurationFileName

[bool] $configurationFileExists = Test-Path -Path $configurationFilePath -PathType Leaf

if(-not $configurationFileExists) {
    # Abort script execution if the configuration file does not exist.
    [string] $message = 'The configuration file {0} was not found. Check the Set-ADDSFirewallPolicy.Starter.json and Set-ADDSFirewallPolicy.Sample.json files to see how the configuration file should look like.' -f $ConfigurationFileName
    throw [System.IO.FileNotFoundException]::new($message, $ConfigurationFileName)
}

Write-Verbose -Message "Reading the $ConfigurationFileName configuration file."
[System.Runtime.Serialization.Json.DataContractJsonSerializer] $serializer = [System.Runtime.Serialization.Json.DataContractJsonSerializer]::new([ScriptSettings])
[System.IO.FileStream] $stream = [System.IO.File]::Open($configurationFilePath, [System.IO.FileMode]::Open)
try {
    $configuration = $serializer.ReadObject($stream)
}
catch {
    # Do not continue if there is any issue reading the configuration file
    throw
}
finally {
    $stream.Close()
}

#endregion Configuration

#region Configuration Validation

if($configuration.ManagementAddresses -contains 'Any' -or $configuration.DomainControllerAddresses -contains 'Any' -and -not $configuration.BlockManagementFromDomainControllers) {
    Write-Warning -Message 'The current configuration allows management traffic from any IP address.'
}

if($configuration.EnableWINS -or $configuration.EnableDhcpServer -or $configuration.EnableNPS -or $configuration.EnableKMS -or $configuration.EnableWSUS -or $configuration.EnableWDS -or $configuration.EnableWebServer -or $configuration.EnableFSRMManagement) {
    Write-Warning -Message 'It is not recommended to host additional Windows Server roles on Domain Controllers.'
}

if($configuration.EnablePrintSpooler) {
    Write-Warning -Message 'The Print Spooler service should be disabled on Domain Controllers.'

    if($configuration.EnableRpcFilters) {
        Write-Warning -Message 'Older Windows clients use the SMB protocol to communicate with the Print Spooler service. RPC filters will block this traffic.'
    }
}

if($configuration.EnableLegacyFileReplication) {
    Write-Warning -Message 'The File Replication Service (FRS) is deprecated. Migration to Distributed File System Replication (DFSR) is highly recommended.'
}

if($configuration.EnableNetbiosNameService -or $configuration.EnableNetbiosDatagramService -or $configuration.EnableNetbiosSessionService -or -not $configuration.DisableNetbiosBroadcasts) {
    Write-Warning -Message 'NetBIOS is a legacy protocol and should be disabled in modern networks.'
}

if(-not($configuration.DisableLLMNR -and $configuration.DisableMDNS)) {
    Write-Warning -Message 'Only the DNS protocol should be used for name resolution in modern networks. Protocols using distributed name resolution, including LLMNR and mDNS, should be disabled on DCs.'
}

if(-not($configuration.LogMaxSizeKilobytes -ge 16384 -and $configuration.LogDroppedPackets -and $configuration.LogAllowedPackets)) {
    Write-Warning -Message 'The firewall log settings do not meet some standardized security baselines.'
}

if($configuration.EnableLocalIPsecRules) {
    Write-Warning -Message 'Local IPSec rules are enabled, which violates some standardized security baselines.'
}

if($configuration.BlockWmiCommandExecution) {
    Write-Warning -Message 'SCCM client and DP do not work properly on systems where command execution over WMI is blocked.'
}

if($configuration.RadiusClientAddresses -notcontains 'Any' -and -not $configuration.EnableNPS) {
    Write-Warning -Message 'Firewall rules for the Network Policy Server (NPS) are disabled, while non-default RADIUS client addresses are specified. This is probably a mistake.'
}

if([string]::IsNullOrWhiteSpace($configuration.GroupPolicyObjectName)) {
    throw [System.ArgumentNullException]::new('GroupPolicyObjectName', 'The name of the target GPO must be provided.')
}

if([string]::IsNullOrWhiteSpace($configuration.LogFilePath)) {
    throw [System.ArgumentNullException]::new('LogFilePath', 'The path to the firewall log file must be provided.')
}

#endregion Configuration Validation

#region Create and Configure the GPO

[Microsoft.ActiveDirectory.Management.ADDomain] $domain = $null

if([string]::IsNullOrWhiteSpace($configuration.TargetDomain)) {
    # Use the current domain if no target domain is specified.
    # Detection of the current domain based on the local computer works well with RDP/WinRM connections
    # to multiple domains made by Enterprise Admins.
    $domain = Get-ADDomain -Current LocalComputer
}
else {
    # Use the specified target domain
    $domain = Get-ADDomain -Identity $configuration.TargetDomain
}

# To avoid potential replication conflicts, GPOs should only be edited on the PDC Emulator.
[string] $targetDomainController = $domain.PDCEmulator

# Try to fetch the target GPO
[Microsoft.GroupPolicy.Gpo] $gpo = Get-GPO -Name $configuration.GroupPolicyObjectName `
                                           -Domain $domain.DNSRoot `
                                           -Server $targetDomainController `
                                           -ErrorAction SilentlyContinue

if($null -eq $gpo) {
    # Create the GPO if it does not exist
    $gpo = New-GPO -Name $configuration.GroupPolicyObjectName `
                   -Comment $configuration.GroupPolicyObjectComment `
                   -Domain $domain.DNSRoot `
                   -Server $targetDomainController `
                   -Verbose:$isVerbose
}

if($gpo.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled) {
    # Fix the GPO status
    Write-Verbose -Message ('Disabling user settings for GPO {0}.' -f $gpo.DisplayName)
    $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled
}

if($gpo.Description -ne $configuration.GroupPolicyObjectComment) {
    # Fix the GPO description
    Write-Verbose -Message ('Updating the description for GPO {0}.' -f $gpo.DisplayName)
    $gpo.Description = $configuration.GroupPolicyObjectComment
}

#endregion Create and configure the GPO

#region Helper Functions

<#
.SYNOPSIS
Converts a boolean value to a NetSecurity.GpoBoolean enumeration value, which is accepted by the Set-NetFirewallProfile cmdlet.

.PARAMETER Value
The boolean value to convert.

#>
function ConvertTo-GpoBoolean {
    [OutputType([Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [bool] $Value
    )

    if($Value) {
        return [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::True
    }
    else {
        return [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::False
    }
}

<#
.SYNOPSIS
Converts a boolean value to a NetSecurity.Enabled enumeration value, which is accepted by the New-NetFirewallRule cmdlet.

.PARAMETER Value
The boolean value to convert.

#>
function ConvertTo-NetSecurityEnabled {
    [OutputType([Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [bool] $Value
    )

    if($Value) {
        return [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True
    }
    else {
        return [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::False
    }
}

#endregion Helper Functions

#region Firewall Profiles

# Contruct the qualified GPO name
[string] $policyStore = '{0}\{1}' -f $gpo.DomainName,$gpo.DisplayName

# Open the GPO
# Note: The Open-NetGPO cmdlet by default contacts a random DC instead of PDC-E
Write-Verbose -Message ('Opening GPO {0}.' -f $gpo.DisplayName)

[string] $gpoSession = Open-NetGPO -PolicyStore $policyStore -DomainController $targetDomainController

# Remove any pre-existing firewall rules
# Note: As Microsoft removed the -GPOSession parameter from the Remove-NetFirewallRule in Windows Server 2022, low-level CIM operations need to be used instead.

# The source GPO session is provided as a custom CIM operation option.
[Microsoft.Management.Infrastructure.Options.CimOperationOptions] $cimOperationOptions =
    [Microsoft.Management.Infrastructure.Options.CimOperationOptions]::new()
$cimOperationOptions.SetCustomOption('GPOSession', $gpoSession, $false)

# Open a temporary local CIM session
[CimSession] $localSession = New-CimSession -Verbose:$false

try {
    # Fetch all firewall rules from the GPO
    [ciminstance[]] $gpoFirewallRules = $localSession.EnumerateInstances('ROOT\StandardCimv2','MSFT_NetFirewallRule', $cimOperationOptions)

    # Remove all firewall rules from the GPO
    foreach($rule in $gpoFirewallRules) {
        Write-Verbose -Message ('Deleting firewall rule {0}.' -f $rule.Name)
        $localSession.DeleteInstance('ROOT\StandardCimv2', $rule, $cimOperationOptions)
    }
}
finally {
    # Close the temporary local CIM session
    Remove-CimSession -CimSession $localSession -ErrorAction SilentlyContinue
}

# Sanitize the maximum log file size
if($configuration.LogMaxSizeKilobytes -gt [int16]::MaxValue -or $configuration.LogMaxSizeKilobytes -le 0) {
    # Windows only accepts 1KB-32MB as the maximum log file size.
    Write-Warning -Message 'The LogMaxSizeKilobytes value is out of the supported range. Setting it to the value of 32MB.'
    $configuration.LogMaxSizeKilobytes = [int16]::MaxValue # = 32MB
}

# Configure all firewall profiles (Domain, Private, and Public)
Set-NetFirewallProfile -GPOSession $gpoSession `
                       -All `
                       -Enabled True `
                       -AllowInboundRules True `
                       -DefaultInboundAction Block `
                       -DefaultOutboundAction Allow `
                       -AllowLocalFirewallRules False `
                       -AllowLocalIPsecRules (ConvertTo-GpoBoolean -Value $configuration.EnableLocalIPsecRules) `
                       -AllowUnicastResponseToMulticast False `
                       -NotifyOnListen False `
                       -LogFileName $configuration.LogFilePath `
                       -LogMaxSizeKilobytes $configuration.LogMaxSizeKilobytes `
                       -LogBlocked (ConvertTo-GpoBoolean -Value $configuration.LogDroppedPackets) `
                       -LogAllowed (ConvertTo-GpoBoolean -Value $configuration.LogAllowedPackets) `
                       -LogIgnored False

[string[]] $allAddresses =
    @($configuration.ClientAddresses + $configuration.DomainControllerAddresses + $configuration.ManagementAddresses) |
    Sort-Object -Unique

if($allAddresses -contains 'Any') {
    # Consolidate the remote addresses
    $allAddresses = @('Any')
}

[string[]] $remoteManagementAddresses = $configuration.ManagementAddresses

if(-not $configuration.BlockManagementFromDomainControllers) {
    # Add the domain controller addresses to the remote management addresses
    $remoteManagementAddresses = @($configuration.ManagementAddresses + $configuration.DomainControllerAddresses) |
        Sort-Object -Unique
}

if($remoteManagementAddresses -contains 'Any') {
    # Consolidate the remote addresses
    $remoteManagementAddresses = @('Any')
}

[string[]] $radiusClientAndDomainControllerAddresses =
    @($configuration.RadiusClientAddresses + $configuration.DomainControllerAddresses) |
    Sort-Object -Unique

if($radiusClientAndDomainControllerAddresses -contains 'Any') {
    # Consolidate the remote addresses
    $radiusClientAndDomainControllerAddresses = @('Any')
}

#endregion Firewall Profiles

#region Inbound Firewall Rules

# Create Inbound rule "Active Directory Domain Controller - W32Time (NTP-UDP-In)"
# As the NTP service might be used by non-Windows clients, we do not limit the remote addresses.
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'W32Time-NTP-UDP-In' `
                    -DisplayName 'Active Directory Domain Controller - W32Time (NTP-UDP-In)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow NTP traffic for the Windows Time service. [UDP 123]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 123 `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\svchost.exe' `
                    -Service 'w32time' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Active Directory Domain Controller (RPC-EPMAP)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-RPCEPMAP-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller (RPC-EPMAP)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the RPCSS service to allow RPC/TCP traffic to the Active Directory Domain Controller service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPCEPMap `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'rpcss' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Kerberos Key Distribution Center - PCR (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-Kerberos-Password-UDP-In' `
                    -DisplayName 'Kerberos Key Distribution Center - PCR (UDP-In)' `
                    -Group 'Kerberos Key Distribution Center' `
                    -Description 'Inbound rule for the Kerberos Key Distribution Center service to allow for password change requests. [UDP 464]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 464 `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Kerberos Key Distribution Center - PCR (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-Kerberos-Password-TCP-In' `
                    -DisplayName 'Kerberos Key Distribution Center - PCR (TCP-In)' `
                    -Group 'Kerberos Key Distribution Center' `
                    -Description 'Inbound rule for the Kerberos Key Distribution Center service to allow for password change requests. [TCP 464]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 464 `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Active Directory Domain Controller (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-RPC-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller (RPC)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule to allow remote RPC/TCP access to the Active Directory Domain Controller service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Active Directory Domain Controller - LDAP (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-LDAP-UDP-In' `
                    -DisplayName 'Active Directory Domain Controller - LDAP (UDP-In)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow remote LDAP traffic. [UDP 389]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 389 `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Active Directory Domain Controller - LDAP (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-LDAP-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller - LDAP (TCP-In)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow remote LDAP traffic. [TCP 389]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 389 `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Active Directory Domain Controller - Secure LDAP (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-LDAPSEC-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller - Secure LDAP (TCP-In)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow remote Secure LDAP traffic. [TCP 636]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 636 `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Active Directory Domain Controller - LDAP for Global Catalog (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-LDAPGC-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller - LDAP for Global Catalog (TCP-In)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow remote Global Catalog traffic. [TCP 3268]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 3268 `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Active Directory Domain Controller - Secure LDAP for Global Catalog (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-LDAPGCSEC-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller - Secure LDAP for Global Catalog (TCP-In)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow remote Secure Global Catalog traffic. [TCP 3269]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 3269 `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DNS (UDP, Incoming)"
# As the DNS service might be used by non-Windows clients, we do not limit the remote addresses.
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DNSSrv-DNS-UDP-In' `
                    -DisplayName 'DNS (UDP, Incoming)' `
                    -Group 'DNS Service' `
                    -Description 'Inbound rule to allow remote UDP access to the DNS service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 53 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\dns.exe' `
                    -Service 'dns' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DNS (TCP, Incoming)"
# As the DNS service might be used by non-Windows clients, we do not limit the remote addresses.
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DNSSrv-DNS-TCP-In' `
                    -DisplayName 'DNS (TCP, Incoming)' `
                    -Group 'DNS Service' `
                    -Description 'Inbound rule to allow remote TCP access to the DNS service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 53 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\dns.exe' `
                    -Service 'dns' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "File Replication (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'NTFRS-NTFRSSvc-In-TCP' `
                    -DisplayName 'File Replication (RPC)' `
                    -Group 'File Replication' `
                    -Description 'Inbound rule to allow File Replication RPC traffic.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableLegacyFileReplication) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.DomainControllerAddresses `
                    -Program '%SystemRoot%\system32\NTFRS.exe' `
                    -Service 'NTFRS' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Kerberos Key Distribution Center (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-Kerberos-TCP-In' `
                    -DisplayName 'Kerberos Key Distribution Center (TCP-In)' `
                    -Group 'Kerberos Key Distribution Center' `
                    -Description 'Inbound rule for the Kerberos Key Distribution Center service. [TCP 88]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 88 `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Kerberos Key Distribution Center (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-Kerberos-UDP-In' `
                    -DisplayName 'Kerberos Key Distribution Center (UDP-In)' `
                    -Group 'Kerberos Key Distribution Center' `
                    -Description 'Inbound rule for the Kerberos Key Distribution Center service. [UDP 88]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 88 `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Active Directory Domain Controller - SAM/LSA (NP-UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-NP-UDP-In' `
                    -DisplayName 'Active Directory Domain Controller - SAM/LSA (NP-UDP-In)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to be remotely managed over Named Pipes. [UDP 445]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 445 `
                    -RemoteAddress $allAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Active Directory Domain Controller - SAM/LSA (NP-TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-NP-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller - SAM/LSA (NP-TCP-In)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to be remotely managed over Named Pipes. [TCP 445]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 445 `
                    -RemoteAddress $allAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DFS Replication (RPC-In)"
# Note that a static port 5722 was used before Windows Server 2012
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DFSR-DFSRSvc-In-TCP' `
                    -DisplayName 'DFS Replication (RPC-In)' `
                    -Group 'DFS Replication' `
                    -Description 'Inbound rule to allow DFS Replication RPC traffic.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.DomainControllerAddresses `
                    -Program '%SystemRoot%\system32\dfsrs.exe' `
                    -Service 'Dfsr' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Active Directory Domain Controller - Echo Request (ICMPv4-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-ICMP4-In' `
                    -DisplayName 'Active Directory Domain Controller - Echo Request (ICMPv4-In)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow Echo requests (ping).' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv4 `
                    -IcmpType 8 `
                    -RemoteAddress $allAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Active Directory Domain Controller - Echo Request (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-ICMP6-In' `
                    -DisplayName 'Active Directory Domain Controller - Echo Request (ICMPv6-In)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow Echo requests (ping).' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 128 `
                    -RemoteAddress $allAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Active Directory Domain Controller - NetBIOS name resolution (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-NB-Datagram-UDP-In' `
                    -DisplayName 'Active Directory Domain Controller - NetBIOS name resolution (UDP-In)' `
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow NetBIOS name resolution. [UDP 138]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNetbiosDatagramService) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 138 `
                    -RemoteAddress $allAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "File and Printer Sharing (NB-Name-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'FPS-NB_Name-In-UDP' `
                    -DisplayName 'File and Printer Sharing (NB-Name-In)' `
                    -Group 'File and Printer Sharing' `
                    -Description 'Inbound rule for File and Printer Sharing to allow NetBIOS Name Resolution. [UDP 137]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNetbiosNameService) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 137 `
                    -RemoteAddress $allAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "File and Printer Sharing (NB-Session-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'FPS-NB_Session-In-TCP' `
                    -DisplayName 'File and Printer Sharing (NB-Session-In)' `
                    -Group 'File and Printer Sharing' `
                    -Description 'Inbound rule for File and Printer Sharing to allow NetBIOS Session Service connections. [TCP 139]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNetbiosSessionService) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 139 `
                    -RemoteAddress $allAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Internet Naming Service (WINS) (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WINS-Service-In-UDP' `
                    -DisplayName 'Windows Internet Naming Service (WINS) (UDP-In)' `
                    -Group 'Windows Internet Naming Service (WINS)' `
                    -Description 'Inbound rule for the Windows Internet Naming Service to allow WINS requests. [UDP 42]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWINS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 42 `
                    -RemoteAddress $allAddresses `
                    -Program '%SystemRoot%\System32\wins.exe' `
                    -Service 'WINS' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Internet Naming Service (WINS) (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WINS-Service-In-TCP' `
                    -DisplayName 'Windows Internet Naming Service (WINS) (TCP-In)' `
                    -Group 'Windows Internet Naming Service (WINS)' `
                    -Description 'Inbound rule for the Windows Internet Naming Service to allow WINS requests. [TCP 42]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWINS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 42 `
                    -RemoteAddress $allAddresses `
                    -Program '%SystemRoot%\System32\wins.exe' `
                    -Service 'WINS' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Internet Naming Service (WINS) - Remote Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WINS-Service-In-RPC' `
                    -DisplayName 'Windows Internet Naming Service (WINS) - Remote Management (RPC)' `
                    -Group 'Windows Internet Naming Service (WINS) - Remote Management' `
                    -Description 'Inbound rule for the Windows Internet Naming Service to allow remote management via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWINS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\System32\wins.exe' `
                    -Service 'WINS' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Core Networking - Destination Unreachable (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-ICMP6-DU-In' `
                    -DisplayName 'Core Networking - Destination Unreachable (ICMPv6-In)' `
                    -Group 'Core Networking' `
                    -Description 'Destination Unreachable error messages are sent from any node that a packet traverses which is unable to forward the packet for any reason except congestion.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 1 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-ICMP4-DUFRAG-In' `
                    -DisplayName 'Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)' `
                    -Group 'Core Networking' `
                    -Description 'Destination Unreachable Fragmentation Needed error messages are sent from any node that a packet traverses which is unable to forward the packet because fragmentation was needed and the don''t fragment bit was set.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv4 `
                    -IcmpType 3:4 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-ICMP6-NDA-In' `
                    -DisplayName 'Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)' `
                    -Group 'Core Networking' `
                    -Description 'Neighbor Discovery Advertisement messages are sent by nodes to notify other nodes of link-layer address changes or in response to a Neighbor Discovery Solicitation request.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 136 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-ICMP6-NDS-In' `
                    -DisplayName 'Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)' `
                    -Group 'Core Networking' `
                    -Description 'Neighbor Discovery Solicitations are sent by nodes to discover the link-layer address of another on-link IPv6 node.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 135 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Core Networking - Packet Too Big (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-ICMP6-PTB-In' `
                    -DisplayName 'Core Networking - Packet Too Big (ICMPv6-In)' `
                    -Group 'Core Networking' `
                    -Description 'Packet Too Big error messages are sent from any node that a packet traverses which is unable to forward the packet because the packet is too large for the next link.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 2 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Core Networking - Parameter Problem (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-ICMP6-PP-In' `
                    -DisplayName 'Core Networking - Parameter Problem (ICMPv6-In)' `
                    -Group 'Core Networking' `
                    -Description 'Parameter Problem error messages are sent by nodes as a result of incorrectly generated packets.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 4 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Core Networking - Time Exceeded (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-ICMP6-TE-In' `
                    -DisplayName 'Core Networking - Time Exceeded (ICMPv6-In)' `
                    -Group 'Core Networking' `
                    -Description 'Time Exceeded error messages are generated from any node that a packet traverses if the Hop Limit value is decremented to zero at any point on the path.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 3 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Determine the remote addresses for the ADWS service
[string[]] $adwsAddresses = $allAddresses

if($configuration.RestrictADWS) {
    # Restrict the remote addresses to the management addresses
    $adwsAddresses = $remoteManagementAddresses
}

# Create Inbound rule "Active Directory Web Services (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADWS-TCP-In' `
                    -DisplayName 'Active Directory Web Services (TCP-In)' `
                    -Group 'Active Directory Web Services' `
                    -Description 'Inbound rule for the Active Directory Web Services. [TCP]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 9389 `
                    -RemoteAddress $adwsAddresses `
                    -Program '%systemroot%\ADWS\Microsoft.ActiveDirectory.WebServices.exe' `
                    -Service 'adws' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Remote Management (HTTP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WINRM-HTTP-In-TCP-PUBLIC' `
                    -DisplayName 'Windows Remote Management (HTTP-In)' `
                    -Group 'Windows Remote Management' `
                    -Description 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWindowsRemoteManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 5985 `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Remote Management (HTTPS-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WINRM-HTTPS-In-TCP-PUBLIC' `
                    -DisplayName 'Windows Remote Management (HTTPS-In)' `
                    -Group 'Windows Remote Management' `
                    -Description 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5986]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWindowsRemoteManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 5986 `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Management Instrumentation (WMI-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WMI-WINMGMT-In-TCP' `
                    -DisplayName 'Windows Management Instrumentation (WMI-In)' `
                    -Group 'Windows Management Instrumentation (WMI)' `
                    -Description 'Inbound rule to allow WMI traffic for remote Windows Management Instrumentation. [TCP]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort Any `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'winmgmt' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote Desktop - User Mode (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteDesktop-UserMode-In-UDP' `
                    -DisplayName 'Remote Desktop - User Mode (UDP-In)' `
                    -Group 'Remote Desktop' `
                    -Description 'Inbound rule for the Remote Desktop service to allow RDP traffic. [UDP 3389]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableRemoteDesktop) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 3389 `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'termservice' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote Desktop - User Mode (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteDesktop-UserMode-In-TCP' `
                    -DisplayName 'Remote Desktop - User Mode (TCP-In)' `
                    -Group 'Remote Desktop' `
                    -Description 'Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableRemoteDesktop) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 3389 `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'termservice' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote Desktop (TCP-In)"
# Note: This redundant rule is created for backward compatibility with Windows Server 2008 R2 and earlier.
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteDesktop-In-TCP' `
                    -DisplayName 'Remote Desktop (TCP-In)' `
                    -Group 'Remote Desktop' `
                    -Description 'Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableRemoteDesktop) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 3389 `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DFS Management (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DfsMgmt-In-TCP' `
                    -DisplayName 'DFS Management (TCP-In)' `
                    -Group 'DFS Management' `
                    -Description 'Inbound rule for DFS Management to allow the DFS Management service to be remotely managed via DCOM.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\dfsfrsHost.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "RPC (TCP, Incoming)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DNSSrv-RPC-TCP-In' `
                    -DisplayName 'RPC (TCP, Incoming)' `
                    -Group 'DNS Service' `
                    -Description 'Inbound rule to allow remote RPC/TCP access to the DNS service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\System32\dns.exe' `
                    -Service 'dns' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Backup (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WindowsServerBackup-wbengine-In-TCP-NoScope' `
                    -DisplayName 'Windows Backup (RPC)' `
                    -Group 'Windows Backup' `
                    -Description 'Inbound rule for the Windows Backup Service to be remotely managed via RPC/TCP' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableBackupManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\wbengine.exe' `
                    -Service 'wbengine' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Performance Logs and Alerts (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'PerfLogsAlerts-PLASrv-In-TCP-NoScope' `
                    -DisplayName 'Performance Logs and Alerts (TCP-In)' `
                    -Group 'Performance Logs and Alerts' `
                    -Description 'Inbound rule for Performance Logs and Alerts traffic. [TCP-In]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnablePerformanceLogAccess) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort Any `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\plasrv.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote Event Log Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteEventLogSvc-In-TCP' `
                    -DisplayName 'Remote Event Log Management (RPC)' `
                    -Group 'Remote Event Log Management' `
                    -Description 'Inbound rule for the local Event Log service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableEventLogManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'Eventlog' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote Scheduled Tasks Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteTask-In-TCP' `
                    -DisplayName 'Remote Scheduled Tasks Management (RPC)' `
                    -Group 'Remote Scheduled Tasks Management' `
                    -Description 'Inbound rule for the Task Scheduler service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableScheduledTaskManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'schedule' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote Service Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteSvcAdmin-In-TCP' `
                    -DisplayName 'Remote Service Management (RPC)' `
                    -Group 'Remote Service Management' `
                    -Description 'Inbound rule for the local Service Control Manager to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableServiceManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\services.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "COM+ Remote Administration (DCOM-In)"
# This rule is required for remote connections using the Computer Management console.
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ComPlusRemoteAdministration-DCOM-In' `
                    -DisplayName 'COM+ Remote Administration (DCOM-In)' `
                    -Group 'COM+ Remote Administration' `
                    -Description 'Inbound rule to allow DCOM traffic to the COM+ System Application for remote administration.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableComPlusManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\dllhost.exe' `
                    -Service 'COMSysApp' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Defender Firewall Remote Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteFwAdmin-In-TCP' `
                    -DisplayName 'Windows Defender Firewall Remote Management (RPC)' `
                    -Group 'Windows Defender Firewall Remote Management' `
                    -Description 'Inbound rule for the Windows Defender Firewall to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableFirewallManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'policyagent' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote Volume Management - Virtual Disk Service (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RVM-VDS-In-TCP' `
                    -DisplayName 'Remote Volume Management - Virtual Disk Service (RPC)' `
                    -Group 'Remote Volume Management' `
                    -Description 'Inbound rule for the Remote Volume Management - Virtual Disk Service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDiskManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\vds.exe' `
                    -Service 'vds' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote Volume Management - Virtual Disk Service Loader (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RVM-VDSLDR-In-TCP' `
                    -DisplayName 'Remote Volume Management - Virtual Disk Service Loader (RPC)' `
                    -Group 'Remote Volume Management' `
                    -Description 'Inbound rule for the Remote Volume Management - Virtual Disk Service Loader to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDiskManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\vdsldr.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "OpenSSH SSH Server (sshd)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'OpenSSH-Server-In-TCP' `
                    -DisplayName 'OpenSSH SSH Server (sshd)' `
                    -Group 'OpenSSH Server' `
                    -Description 'Inbound rule for OpenSSH SSH Server (sshd)' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableOpenSSHServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 22 `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\OpenSSH\sshd.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DHCP Server v4 (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Microsoft-Windows-DHCP-ClientSvc-DHCPv4-In' `
                    -DisplayName 'DHCP Server v4 (UDP-In)' `
                    -Group 'DHCP Server' `
                    -Description 'An inbound rule to allow traffic to the IPv4 Dynamic Host Control Protocol Server. [UDP 67]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDhcpServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 67 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'dhcpserver' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DHCP Server v4 (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Microsoft-Windows-DHCP-SrvSvc-DHCPv4-In' `
                    -DisplayName 'DHCP Server v4 (UDP-In)' `
                    -Group 'DHCP Server' `
                    -Description 'An inbound rule to allow traffic so that rogue detection works in V4. [UDP 68]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDhcpServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 68 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'dhcpserver' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DHCP Server v6 (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Microsoft-Windows-DHCP-SrvSvc-DHCPv6-In' `
                    -DisplayName 'DHCP Server v6 (UDP-In)' `
                    -Group 'DHCP Server' `
                    -Description 'An inbound rule to allow traffic so that rogue detection works in V6. [UDP 546]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDhcpServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 546 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'dhcpserver' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DHCP Server v6 (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Microsoft-Windows-DHCP-ClientSvc-DHCPv6-In' `
                    -DisplayName 'DHCP Server v6 (UDP-In)' `
                    -Group 'DHCP Server' `
                    -Description 'An inbound rule to allow traffic to the IPv6 Dynamic Host Control Protocol Server. [UDP 547]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDhcpServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 547 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'dhcpserver' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DHCP Server Failover (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Microsoft-Windows-DHCP-Failover-TCP-In' `
                    -DisplayName 'DHCP Server Failover (TCP-In)' `
                    -Group 'DHCP Server Management' `
                    -Description 'An inbound rule to allow DHCP failover messages to the IPv4 Dynamic Host Configuration Protocol Server. [TCP 647]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDhcpServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 647 `
                    -RemoteAddress $configuration.DomainControllerAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'dhcpserver' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DHCP Server (RPC-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Microsoft-Windows-DHCP-ClientSvc-RPC-TCP-In' `
                    -DisplayName 'DHCP Server (RPC-In)' `
                    -Group 'DHCP Server Management' `
                    -Description 'An inbound rule to allow traffic to allow RPC traffic for DHCP Server management.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDhcpServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'dhcpserver' `
                    -Verbose:$isVerbose > $null
                    
# Create Inbound rule "Network Policy Server (Legacy RADIUS Authentication - UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'NPS-NPSSvc-In-UDP-1645' `
                    -DisplayName 'Network Policy Server (Legacy RADIUS Authentication - UDP-In)' `
                    -Group 'Network Policy Server' `
                    -Description 'Inbound rule to allow Network Policy Server to receive RADIUS Authentication requests. [UDP 1645]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNPS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 1645 `
                    -RemoteAddress $radiusClientAndDomainControllerAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'ias' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Network Policy Server (Legacy RADIUS Accounting - UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'NPS-NPSSvc-In-UDP-1646' `
                    -DisplayName 'Network Policy Server (Legacy RADIUS Accounting - UDP-In)' `
                    -Group 'Network Policy Server' `
                    -Description 'Inbound rule to allow Network Policy Server to receive RADIUS Accounting requests. [UDP 1646]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNPS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 1646 `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'ias' `
                    -RemoteAddress $radiusClientAndDomainControllerAddresses `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Network Policy Server (RADIUS Authentication - UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'NPS-NPSSvc-In-UDP-1812' `
                    -DisplayName 'Network Policy Server (RADIUS Authentication - UDP-In)' `
                    -Group 'Network Policy Server' `
                    -Description 'Inbound rule to allow Network Policy Server to receive RADIUS Authentication requests. [UDP 1812]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNPS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 1812 `
                    -RemoteAddress $radiusClientAndDomainControllerAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'ias' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Network Policy Server (RADIUS Accounting - UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'NPS-NPSSvc-In-UDP-1813' `
                    -DisplayName 'Network Policy Server (RADIUS Accounting - UDP-In)' `
                    -Group 'Network Policy Server' `
                    -Description 'Inbound rule to allow Network Policy Server to receive RADIUS Accounting requests. [UDP 1813]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNPS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 1813 `
                    -RemoteAddress $radiusClientAndDomainControllerAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'ias' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Network Policy Server (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'NPS-NPSSvc-In-RPC' `
                    -DisplayName 'Network Policy Server (RPC)' `
                    -Group 'Network Policy Server' `
                    -Description 'Inbound rule for the Network Policy Server to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNPS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\iashost.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "World Wide Web Services (HTTP Traffic-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'IIS-WebServerRole-HTTP-In-TCP' `
                    -DisplayName 'World Wide Web Services (HTTP Traffic-In)' `
                    -Group 'World Wide Web Services (HTTP)' `
                    -Description 'An inbound rule to allow HTTP traffic for Internet Information Services (IIS) [TCP 80]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWebServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 80 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "World Wide Web Services (HTTPS Traffic-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'IIS-WebServerRole-HTTPS-In-TCP' `
                    -DisplayName 'World Wide Web Services (HTTPS Traffic-In)' `
                    -Group 'Secure World Wide Web Services (HTTPS)' `
                    -Description 'An inbound rule to allow HTTPS traffic for Internet Information Services (IIS) [TCP 443]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWebServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 443 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Deployment Services (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WDS-WdsServer-In-UDP' `
                    -DisplayName 'Windows Deployment Services (UDP-In)' `
                    -Group 'Windows Deployment Services' `
                    -Description 'Inbound rule for Windows Deployment Services to allow UDP traffic.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWDS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort Any `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'WdsServer' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Deployment Services (RPC-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WDS-RPC-In-TCP' `
                    -DisplayName 'Windows Deployment Services (RPC-In)' `
                    -Group 'Windows Deployment Services' `
                    -Description 'Inbound rule for Windows Deployment Services to allow RPC/TCP traffic.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWDS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'WdsServer' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Key Management Service (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'SPPSVC-In-TCP' `
                    -DisplayName 'Key Management Service (TCP-In)' `
                    -Group 'Key Management Service' `
                    -Description 'Inbound rule for the Key Management Service to allow for machine counting and license compliance. [TCP 1688]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableKMS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 1688 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\sppextcomobj.exe' `
                    -Service 'sppsvc' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote File Server Resource Manager Management - FSRM Service (RPC-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'FSRM-SrmSvc-In (RPC)' `
                    -DisplayName 'Remote File Server Resource Manager Management - FSRM Service (RPC-In)' `
                    -Group 'Remote File Server Resource Manager Management' `
                    -Description 'Inbound rule for the File Server Resource Manager service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableFSRMManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'SrmSvc' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote File Server Resource Manager Management - FSRM Reports Service (RPC-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'FSRM-SrmReports-In (RPC)' `
                    -DisplayName 'Remote File Server Resource Manager Management - FSRM Reports Service (RPC-In)' `
                    -Group 'Remote File Server Resource Manager Management' `
                    -Description 'Inbound rule for the File Server Storage Reports Manager service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableFSRMManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\srmhost.exe' `
                    -Service 'SrmReports' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "File and Printer Sharing (Spooler Service - RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'FPS-SpoolSvc-In-TCP' `
                    -DisplayName 'File and Printer Sharing (Spooler Service - RPC)' `
                    -Group 'File and Printer Sharing' `
                    -Description 'Inbound rule for File and Printer Sharing to allow the Print Spooler Service to communicate via TCP/RPC.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnablePrintSpooler) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $allAddresses `
                    -Program '%SystemRoot%\system32\spoolsv.exe' `
                    -Service 'Spooler' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Server Update Services (HTTP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WSUS-In-HTTP' `
                    -DisplayName 'Windows Server Update Services (HTTP-In)' `
                    -Group 'Windows Server Update Services (WSUS)' `
                    -Description 'Inbound rule for Windows Server Update Services to allow HTTP traffic. [TCP 8530]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWSUS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 8530 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Server Update Services (HTTPS-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WSUS-In-HTTPS' `
                    -DisplayName 'Windows Server Update Services (HTTPS-In)' `
                    -Group 'Windows Server Update Services (WSUS)' `
                    -Description 'Inbound rule for Windows Server Update Services to allow HTTPS traffic. [TCP 8531]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWSUS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 8531 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Import custom firewall rules from script files
foreach($ruleFileName in $configuration.CustomRuleFileNames) {
    [string] $ruleFilePath = Join-Path -Path $PSScriptRoot -ChildPath $ruleFileName

    [bool] $ruleFileExists = Test-Path -Path $ruleFilePath -PathType Leaf

    if($ruleFileExists) {
        Write-Verbose -Message "Importing custom firewall rules from '$ruleFilePath'..."
        # Execute the custom rule script file, while suppressing any output.
        & $ruleFilePath -GPOSession $gpoSession `
                        -DomainControllerAddresses $configuration.DomainControllerAddresses `
                        -RemoteManagementAddresses $remoteManagementAddresses `
                        -AllAddresses $allAddresses > $null
    } else {
        [System.Exception] $ex = [System.IO.FileNotFoundException]::new('Could not locate the custom rule file.', $ruleFilePath)
        Write-Error -Exception $ex `
                    -Category OpenError `
                    -ErrorId CustomRuleOpenError `
                    -TargetObject $ruleFilePath
    }
}

# Commit the firewall-related GPO changes
Write-Verbose -Message 'Saving the GPO changes...'
Save-NetGPO -GPOSession $gpoSession

#endregion Inbound Firewall Rules

#region Registry Settings

# Prevent users and apps from accessing dangerous websites
# (Enables Microsoft Defender Exploit Guard Network Protection)
# This might block some Internet C2 traffic.
if($null -ne $configuration.EnableNetworkProtection) {
    # We will enable the audit mode by default
    [int] $networkProtectionState = 2

    if($configuration.EnableNetworkProtection) {
        # Switch Network Protection to Block mode
        $networkProtectionState = 1
    }

    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' `
                        -ValueName 'EnableNetworkProtection' `
                        -Value $networkProtectionState `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
                            
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' `
                        -ValueName 'AllowNetworkProtectionOnWinServer' `
                        -Value 1 `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    # Remove the Network Protection settings
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' `
                           -ValueName 'EnableNetworkProtection' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
    
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' `
                           -ValueName 'AllowNetworkProtectionOnWinServer' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Block process creations originating from PSExec and WMI commands
# Block persistence through WMI event subscription
# Uses Microsoft Defender Exploit Guard Attack Surface Reduction
if($null -ne $configuration.BlockWmiCommandExecution) {
    # Audit (Evaluate how the attack surface reduction rule would impact your organization if enabled)
    [int] $blockPsExecAndWmi = 2

    if($configuration.BlockWmiCommandExecution -eq $true) {
        # Block (Enable the attack surface reduction rule)
        $blockPsExecAndWmi = 1
    }

    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' `
                        -ValueName 'ExploitGuard_ASR_Rules' `
                        -Value 1 `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null

    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                        -ValueName 'd1e49aac-8f56-4280-b9ba-993a6d77406c' `
                        -Value $blockPsExecAndWmi.ToString() `
                        -Type String `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
    
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                        -ValueName 'e6db77e5-3df2-4cf1-b95a-636979351e5b' `
                        -Value $blockPsExecAndWmi.ToString() `
                        -Type String `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    # Remove the ASR settings
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' `
                           -ValueName 'ExploitGuard_ASR_Rules' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null

    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                           -ValueName 'd1e49aac-8f56-4280-b9ba-993a6d77406c' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null

    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                           -ValueName 'e6db77e5-3df2-4cf1-b95a-636979351e5b' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Disable MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                    -ValueName 'EnableICMPRedirect' `
                    -Value 0 `
                    -Type DWord `
                    -Domain $domain.DNSRoot `
                    -Server $targetDomainController `
                    -Verbose:$isVerbose > $null

# MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                    -ValueName 'DisableIPSourceRouting' `
                    -Value 2 `
                    -Type DWord `
                    -Domain $domain.DNSRoot `
                    -Server $targetDomainController `
                    -Verbose:$isVerbose > $null

# MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)	
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters' `
                    -ValueName 'DisableIPSourceRouting' `
                    -Value 2 `
                    -Type DWord `
                    -Domain $domain.DNSRoot `
                    -Server $targetDomainController `
                    -Verbose:$isVerbose > $null

# Disable MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                    -ValueName 'PerformRouterDiscovery' `
                    -Value 0 `
                    -Type DWord `
                    -Domain $domain.DNSRoot `
                    -Server $targetDomainController `
                    -Verbose:$isVerbose > $null

# MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\NetBT\Parameters' `
                    -ValueName 'NoNameReleaseOnDemand' `
                    -Value 1 `
                    -Type DWord `
                    -Domain $domain.DNSRoot `
                    -Server $targetDomainController `
                    -Verbose:$isVerbose > $null

if($null -ne $configuration.DisableNetbiosBroadcasts) {
    # NetBT NodeType configuration
    [int] $nodeType = 8 # Default to H-node (use WINS servers first, then use broadcast)

    if($configuration.DisableNetbiosBroadcasts) {
        $nodeType = 2 # P-node (use WINS servers only, recommended)
    }

    # Note: This is not a managed GPO setting.
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\System\CurrentControlSet\Services\NetBT\Parameters' `
                        -ValueName 'NodeType' `
                        -Value $nodeType `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null

    # Configure NetBIOS settings
    [int] $enableNetbios = 3 # Default to learning mode

    if($configuration.DisableNetbiosBroadcasts) {
        $enableNetbios = 0 # Disable NetBIOS
    }

    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                        -ValueName 'EnableNetbios' `
                        -Value $enableNetbios `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    # Remove the NetBIOS-related settings
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\System\CurrentControlSet\Services\NetBT\Parameters' `
                           -ValueName 'NodeType' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null

    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                           -ValueName 'EnableNetbios' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Turn off Link-Local Multicast Name Resolution (LLMNR)
if($configuration.DisableLLMNR -eq $true) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                        -ValueName 'EnableMulticast' `
                        -Value 0 `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                           -ValueName 'EnableMulticast' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Turn off Multicast DNS (mDNS)
# Note: This is not a managed GPO setting.
if($null -ne $configuration.DisableMDNS) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' `
                        -ValueName 'EnableMDNS' `
                        -Value ([int](-not $configuration.DisableMDNS)) `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' `
                           -ValueName 'EnableMDNS' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Configure the DRS-R protocol to use a specific port
# Note: This is not a managed GPO setting.
if($null -ne $configuration.NtdsStaticPort) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
                        -ValueName 'TCP/IP Port' `
                        -Value ([int] $configuration.NtdsStaticPort) `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
                           -ValueName 'TCP/IP Port' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Configure the NETLOGON protocol to use a specific port
# Note: This is not a managed GPO setting.
if($null -ne $configuration.NetlogonStaticPort) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
                        -ValueName 'DCTcpipPort' `
                        -Value ([int] $configuration.NetlogonStaticPort) `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
                           -ValueName 'DCTcpipPort' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Configure the FRS protocol to use a specific port
# Note: This is not a managed GPO setting.
if($null -ne $configuration.FrsStaticPort) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters' `
                        -ValueName 'RPC TCP/IP Port Assignment' `
                        -Value ([int] $configuration.FrsStaticPort) `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters' `
                           -ValueName 'RPC TCP/IP Port Assignment' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

#endregion Registry Settings

#region Startup Script

# Fetch the GPO info from the PDC emulator
[Microsoft.ActiveDirectory.Management.ADObject] $gpoContainer = Get-ADObject -Identity $gpo.Path -Properties 'gPCFileSysPath','gPCMachineExtensionNames' -Server $targetDomainController
[string] $startupScriptDirectory = Join-Path -Path $gpoContainer.gPCFileSysPath -ChildPath 'Machine\Scripts\Startup'
[string] $startupScriptPath = Join-Path -Path $startupScriptDirectory -ChildPath 'FirewallConfiguration.bat'
[string] $scriptsIniPath = Join-Path -Path $gpoContainer.gPCFileSysPath -ChildPath 'Machine\Scripts\scripts.ini'

# Create the directory for startup scripts if it does not exist
New-Item -Path $startupScriptDirectory -ItemType Directory -Force -Verbose:$isVerbose > $null

# Startup script header
[System.Text.StringBuilder] $startupScript = [System.Text.StringBuilder]::new()
$startupScript.AppendLine('@ECHO OFF') > $null
$startupScript.AppendLine('REM This script is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script.') > $null

# Configure the WMI  protocol to use the deafult static port 24158
if($configuration.WmiStaticPort -eq $true) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Move the WMI service to a standalone process listening on TCP port 24158 with authentication level set to RPC_C_AUTHN_LEVEL_PKT_PRIVACY.') > $null
    $startupScript.AppendLine('winmgmt.exe /standalonehost 6') > $null
} elseif($configuration.WmiStaticPort -eq $false) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Move the WMI service into the shared Svchost process.') > $null
    $startupScript.AppendLine('winmgmt.exe /sharedhost') > $null
}

# Configure the DFS-R protocol to use a specific port
[string] $dfsrDiagInstallScript = @'
echo Install the dfsrdiag.exe tool if absent.
if not exist "%SystemRoot%\system32\dfsrdiag.exe" (
    dism.exe /Online /Enable-Feature /FeatureName:DfsMgmt
)
'@

if($configuration.DfsrStaticPort -ge 1) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine($dfsrDiagInstallScript) > $null
    $startupScript.AppendLine('echo Set static RPC port for DFS Replication.') > $null
    $startupScript.AppendFormat('dfsrdiag.exe StaticRPC /Port:{0}', $configuration.DfsrStaticPort) > $null
    $startupScript.AppendLine() > $null
} elseif($configuration.DfsrStaticPort -eq 0) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine($dfsrDiagInstallScript) > $null
    $startupScript.AppendLine('echo Set dynamic RPC port for DFS Replication.') > $null
    $startupScript.AppendLine('dfsrdiag.exe StaticRPC /Port:0') > $null
}

# Create the firewall log file
$startupScript.AppendLine() > $null
$startupScript.AppendLine('echo Create the firewall log file and configure its DACL.') > $null
$startupScript.AppendFormat('netsh.exe advfirewall set allprofiles logging filename "{0}"', $configuration.LogFilePath) > $null
$startupScript.AppendLine() > $null

# Register RPC filters
[string] $rpcFilterScriptName = 'RpcNamedPipesFilters.txt'
[string] $rpcFilterScriptSourcePath = Join-Path -Path $PSScriptRoot -ChildPath $rpcFilterScriptName
[string] $rpcFilterScriptTargetPath = Join-Path -Path $startupScriptDirectory -ChildPath $rpcFilterScriptName

if($configuration.EnableRpcFilters -eq $true) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Register the RPC filters.') > $null
    $startupScript.AppendFormat('netsh.exe -f "%~dp0{0}"', $rpcFilterScriptName) > $null
    $startupScript.AppendLine() > $null
} elseif($null -ne $configuration.EnableRpcFilters) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Remove all RPC filters.') > $null
    $startupScript.AppendLine('netsh.exe rpc filter delete filter filterkey=all') > $null
}

# Fix the Network Policy Server (NPS) to work with Windows Firewall on Windows Server 2016 and Windows Server 2019.
# This is not required on Windows Server 2022.
if($configuration.EnableNPS -eq $true) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Fix the NPS service to work with Windows Firewall on downlevel Windows Server versions.') > $null
    $startupScript.AppendLine('sc.exe sidtype IAS unrestricted') > $null
}

# Overwrite the script files
Set-Content -Path $startupScriptPath -Value $startupScript.ToString() -Encoding Ascii -Force -Verbose:$isVerbose
Copy-Item -Path $rpcFilterScriptSourcePath -Destination $rpcFilterScriptTargetPath -Force -Confirm:$false -Verbose:$isVerbose

# Register the startup script in the scripts.ini file
[string] $scriptsIni = @'
[Startup]
0CmdLine=FirewallConfiguration.bat
0Parameters=
'@

Set-Content -Path $scriptsIniPath -Value $scriptsIni -Encoding Ascii -Verbose:$isVerbose -Force

# Register the Scripts client-side extension in AD if necessary
[string] $machineScriptsExtension = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'

if(-not $gpoContainer.gPCMachineExtensionNames.Contains($machineScriptsExtension)) {
    [string] $updatedMachineExtensionNames = $machineScriptsExtension + $gpoContainer.gPCMachineExtensionNames
    
    # The CSE GUIDs must be sorted in case-insensitive ascending order
    [string[]] $sortedExtensions =
        $updatedMachineExtensionNames.Split('[]') |
        Where-Object { -not [string]::IsNullOrWhiteSpace($PSItem) } |
        Sort-Object -Culture ([cultureinfo]::InvariantCulture)
    $updatedMachineExtensionNames = '[' + ($sortedExtensions -join '][') + ']'

    # Update the GPO
    Set-ADObject -Identity $gpoContainer -Replace @{ gPCMachineExtensionNames = $updatedMachineExtensionNames } -Server $targetDomainController  -Verbose:$isVerbose
}

#endregion Startup Script

#region Administrative Templates

# Resolve the paths to the ADMX files
[string] $policiesDirectory = Split-Path -Path $gpoContainer.gPCFileSysPath -Parent
[string] $admxTargetDirectory = Join-Path -Path $policiesDirectory -ChildPath 'PolicyDefinitions'
[string] $admxSourceDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'PolicyDefinitions'

# Check if the ADMX Central Store exists
if(Test-Path -Path $admxTargetDirectory -PathType Container) {
    # Copy the ADMX and ADML files to the Central Store
    Copy-Item -Path $admxSourceDirectory -Destination $policiesDirectory -Container -Recurse -Verbose:$isVerbose -Force > $null
}
else {
    Write-Warning -Message 'The ADMX Central Store does not exist. ADMX files have not been copied.'
}
#endregion Administrative Templates

# SIG # Begin signature block
# MIItEQYJKoZIhvcNAQcCoIItAjCCLP4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCt5egkKel5L7/6
# aiTT5AOfTchTBIdChkuAZYErZDjeN6CCEg8wggV4MIIDYKADAgECAhBLLDsBAYut
# KryMe1s+7ZBXMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENvZGUg
# U2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw00NjAzMjEyMzU5NTla
# MFYxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLTArBgNV
# BAMTJFNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBSb290IFI0NjCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAI3nlBIiBCR0Lv8WIwKSirauNoWsR9Qj
# kSs+3H3iMaBRb6yEkeNSirXilt7Qh2MkiYr/7xKTO327toq9vQV/J5trZdOlDGmx
# vEk5mvFtbqrkoIMn2poNK1DpS1uzuGQ2pH5KPalxq2Gzc7M8Cwzv2zNX5b40N+OX
# G139HxI9ggN25vs/ZtKUMWn6bbM0rMF6eNySUPJkx6otBKvDaurgL6en3G7X6P/a
# IatAv7nuDZ7G2Z6Z78beH6kMdrMnIKHWuv2A5wHS7+uCKZVwjf+7Fc/+0Q82oi5P
# MpB0RmtHNRN3BTNPYy64LeG/ZacEaxjYcfrMCPJtiZkQsa3bPizkqhiwxgcBdWfe
# beljYx42f2mJvqpFPm5aX4+hW8udMIYw6AOzQMYNDzjNZ6hTiPq4MGX6b8fnHbGD
# dGk+rMRoO7HmZzOatgjggAVIQO72gmRGqPVzsAaV8mxln79VWxycVxrHeEZ8cKqU
# G4IXrIfptskOgRxA1hYXKfxcnBgr6kX1773VZ08oXgXukEx658b00Pz6zT4yRhMg
# NooE6reqB0acDZM6CWaZWFwpo7kMpjA4PNBGNjV8nLruw9X5Cnb6fgUbQMqSNenV
# etG1fwCuqZCqxX8BnBCxFvzMbhjcb2L+plCnuHu4nRU//iAMdcgiWhOVGZAA6RrV
# wobx447sX/TlAgMBAAGjQjBAMB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJwIDaRXBeF
# 5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQwF
# AAOCAgEAdmXC49ciStcdiV7/aV7GFAJNc6bNzSjKsDfqv6fJIaqqX9q/9oNs0IDR
# ClwApMvzzDkPnkFxiNU86Ip7jBcj98o0dJFsBq5QPwBZsiY8PBeDVwM+LdEaPdTP
# B1SyQwtScqiI9cQX8m/RWKXRaOQ9mAgY7jb0SEia+lRw8IjUcBYwQknQ2T91S0Vx
# 2K6iu2EOiIVQV7m6ESs2KR+PIHKeXJ6J0YLaRY1qmdqEcWszpRC7efCX9nSBoD9X
# x4aMMIwOOJWuAcYeq9yoH28v1/92Hq4Xc23luXWzYQaolTPCTm+yN/KVvoVUErnI
# vWJCdvcq/PU3MQMmV/7R5tvwFgJyg4wIs4SsqeQH+KGIxBNaUEdUQqbt0EE0LJix
# PqI0oQxdvaz3f3mnv20MVjKFG0uXuOGs5KQ8cfGj4U5j1vRGuvULCOFjPO2iWS8K
# 1CxrI6KeoU3u0RLNGDNQ7UFuy389QWALYwt49XXvQxW3NgsQr9xcGKmY2TbZHdiE
# swaKguN7GySnQs7uDz5WXDJ97EveVis7O7r5eljQUbZs1vZYolIkekSGoRxgP0nT
# /Pr5hBwFwjS/4ubxGSqZL1ZXNZy19QfDRi/eOD0ZDfuj8d8Tnuepclgxr73q2tfW
# bXczM470rP3Bv0mH0nAFZ3QGpvZ4QC0WBJEPH9MWxLh6Fw0kybIwggYaMIIEAqAD
# AgECAhBiHW0MUgGeO5B5FSCJIRwKMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYT
# AkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28g
# UHVibGljIENvZGUgU2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0z
# NjAzMjEyMzU5NTlaMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExp
# bWl0ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBS
# MzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCbK51T+jU/jmAGQ2rA
# z/V/9shTUxjIztNsfvxYB5UXeWUzCxEeAEZGbEN4QMgCsJLZUKhWThj/yPqy0iSZ
# hXkZ6Pg2A2NVDgFigOMYzB2OKhdqfWGVoYW3haT29PSTahYkwmMv0b/83nbeECbi
# MXhSOtbam+/36F09fy1tsB8je/RV0mIk8XL/tfCK6cPuYHE215wzrK0h1SWHTxPb
# PuYkRdkP05ZwmRmTnAO5/arnY83jeNzhP06ShdnRqtZlV59+8yv+KIhE5ILMqgOZ
# YAENHNX9SJDm+qxp4VqpB3MV/h53yl41aHU5pledi9lCBbH9JeIkNFICiVHNkRmq
# 4TpxtwfvjsUedyz8rNyfQJy/aOs5b4s+ac7IH60B+Ja7TVM+EKv1WuTGwcLmoU3F
# pOFMbmPj8pz44MPZ1f9+YEQIQty/NQd/2yGgW+ufflcZ/ZE9o1M7a5Jnqf2i2/uM
# SWymR8r2oQBMdlyh2n5HirY4jKnFH/9gRvd+QOfdRrJZb1sCAwEAAaOCAWQwggFg
# MB8GA1UdIwQYMBaAFDLrkpr/NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBQPKssg
# hyi47G9IritUpimqF6TNDDAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB
# /wIBADATBgNVHSUEDDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYG
# Z4EMAQQBMEsGA1UdHwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwuc2VjdGlnby5jb20v
# U2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nUm9vdFI0Ni5jcmwwewYIKwYBBQUHAQEE
# bzBtMEYGCCsGAQUFBzAChjpodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29Q
# dWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8v
# b2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEABv+C4XdjNm57oRUg
# mxP/BP6YdURhw1aVcdGRP4Wh60BAscjW4HL9hcpkOTz5jUug2oeunbYAowbFC2AK
# K+cMcXIBD0ZdOaWTsyNyBBsMLHqafvIhrCymlaS98+QpoBCyKppP0OcxYEdU0hps
# aqBBIZOtBajjcw5+w/KeFvPYfLF/ldYpmlG+vd0xqlqd099iChnyIMvY5HexjO2A
# mtsbpVn0OhNcWbWDRF/3sBp6fWXhz7DcML4iTAWS+MVXeNLj1lJziVKEoroGs9Ml
# izg0bUMbOalOhOfCipnx8CaLZeVme5yELg09Jlo8BMe80jO37PU8ejfkP9/uPak7
# VLwELKxAMcJszkyeiaerlphwoKx1uHRzNyE6bxuSKcutisqmKL5OTunAvtONEote
# SiabkPVSZ2z76mKnzAfZxCl/3dq3dUNw4rg3sTCggkHSRqTqlLMS7gjrhTqBmzu1
# L90Y1KWN/Y5JKdGvspbOrTfOXyXvmPL6E52z1NZJ6ctuMFBQZH3pwWvqURR8AgQd
# ULUvrxjUYbHHj95Ejza63zdrEcxWLDX6xWls/GDnVNueKjWUH3fTv1Y8Wdho698Y
# ADR7TNx8X8z2Bev6SivBBOHY+uqiirZtg0y9ShQoPzmCcn63Syatatvx157YK9hl
# cPmVoa1oDE5/L9Uo2bC5a4CH2RwwggZxMIIE2aADAgECAhBsg5osz2x/Auy2idY5
# 0JFYMA0GCSqGSIb3DQEBDAUAMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmlu
# ZyBDQSBSMzYwHhcNMjIxMTA0MDAwMDAwWhcNMjUxMTAzMjM1OTU5WjBnMQswCQYD
# VQQGEwJDWjEeMBwGA1UECAwVUHJhaGEsIEhsYXZuw60gbcSbc3RvMRswGQYDVQQK
# DBJNaWNoYWVsIEdyYWZuZXR0ZXIxGzAZBgNVBAMMEk1pY2hhZWwgR3JhZm5ldHRl
# cjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMHVk5c8z27bjQ82tQNj
# cU+ilNAnWJwrb0Pa2Z643b7M+wAKi1DhCsavzRWwPYGKKpPLuSWTipw5P7Tag7i9
# H580wR+mxr1jX8Kd7Qr1Eyt3QRsqXLDAwj67ExDrzcOFcIkSK3UKgZFQL+rFy2HB
# quQsHaGQQ8Jm2sWjGZod88/cmxOGUO0w7qvsysmY0QzzRNbUPpeJMPyzuq8zo2+P
# JYP6qQS535bVGaOaCRcXz3XtpvJt8BMVOUVSjb7cEwfBgDoOL72EP6lqJrMV42TI
# VpjR/rB/zT849lJtkvyAEfEr6UiOAiH9o5hm+GahTqPNMAPovb8hDPQRdu2QUpLg
# W+KHicuQWwoFABqsMIF7Oo00xDuD+J52VU12LwobKINFDJB3BdU3L2aYQRFt3YJQ
# gwH50gh1yNqaTcd78CNb2A5VwNvzTCZ0vhBaKdCK/BsLsu9atLld6FwBI8Pak6iA
# NXuFY0W/whPwlVYzMeTdELzr/m53Fk8DQFcd48SvaYt4dbgU3Q3ySbDDnnBgn/TB
# 5E+DRg7+tZgMH4ep8XXL8F/0gmIvhFXNJGXX9f8A2ox7G7Drj2Guf34P1UKZYjs7
# D2aJ71aPtZKPmXOPpTacuhNhdSVLX4ciwJOaRcZOt9pg2lwzjQVa5kw/GOs5Epeb
# OtHry/SsgiDBiCXVxXxxE9E3AgMBAAGjggGqMIIBpjAfBgNVHSMEGDAWgBQPKssg
# hyi47G9IritUpimqF6TNDDAdBgNVHQ4EFgQUnRBKK1Ym2UQhxb0SetlSGK5huJMw
# DgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIBAwIwJTAjBggrBgEFBQcCARYXaHR0
# cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQBMEkGA1UdHwRCMEAwPqA8oDqG
# OGh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5n
# Q0FSMzYuY3JsMHkGCCsGAQUFBwEBBG0wazBEBggrBgEFBQcwAoY4aHR0cDovL2Ny
# dC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQVIzNi5jcnQw
# IwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMB8GA1UdEQQYMBaB
# FGluZm9AZHNpbnRlcm5hbHMuY29tMA0GCSqGSIb3DQEBDAUAA4IBgQAuRlAwdZ32
# WVvW4tsRBmmPtse5BOqYjCP4OkxCYn47Sc+zajMgqDj8M5kGSx6SYexUbBcVssAu
# pkpIW7YDGRDo4mGJWY6zFqTXLthtRL14TfiFTTwtpLLSWsRkHbwCbRXbhchpH3nA
# pPshTMvd49gKKRT+AtDr5RrPVnh1LMYZdwuvQpWhkPgT/P0OYKTYtiieW5hSebdl
# /IaGVx1KJi/FrC9MaXj72nvjAaCk5drri7QSsf8R+ghRy5mUJShX11L1nJrGW80s
# hjaRBroT7ktr3WKryuc1cHvkXkKWZq78JosUWfGOtSQ0TJ9AiT+wBAbqtyv1H2X7
# wYNrrcq5cT543yO+SVhiuH+OQZZFjkYdhG5OoZgzABz/mXeHY4VnJHY+SuHJV3oy
# kb4NajXiID4+iy3bgQOdghwMARNUMwsdYlpXqw13iD/Li4B4weFq8d/1ZEa1BFtV
# DALXqV5+ZB4FJ/8CmonbGFIeHZfjj2PhcPL5rgGeMnFOwBjpZyvW4FUxghpYMIIa
# VAIBATBoMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# KzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEGyD
# mizPbH8C7LaJ1jnQkVgwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEK
# MAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3
# AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg1lpq4++DDIbh9PQE
# DWA/xTgMxv8or6xliJE77HztbCAwDQYJKoZIhvcNAQEBBQAEggIAudTYaG3MgwRo
# v0n+FFBhHEaV0keDOLu9DfqFLVpDNljWHTH6LnnKPp/vTdTEsCnj7JvRnySlKtTO
# eHzosWJZiRkpF7LWTx+NW7pHvjemjU2DAy8P1mSNJkCZeS65b4fn08cstPNHIyC8
# Mya5OgPyIJbYEeg+20LA1FGHmXf3HGB8EtIpPcVGb3JreEab9kMxJhy2mjmfDE/2
# cZgzuvLPggMG1C5qyZ/5cTtkBJog56yMB+ljVwyM2Md1loTH7U12HsFGnj7v3RC/
# 9asLv9YkQbbi2IeIM9WqZ5Iuep8OZx0y83qoO5Knom+Mf9/DUk/ndB6gyqumhSmO
# uH6oiy3Aq4k3Slu+eiWK7QJg8m3ww1FsLYEfgkuBQ+8m0bTECHGt/n9wVyWc67Jh
# Ep3m44dC0y3wlKf1EYpH5FdPbMj50VFWqBqRgr8hkgEk+hcezTk20zEn1irjer1m
# qsmKtPNJSXQ7VgHydP1tk7idNABxLu+7RQQcoR2qJ22yhvEtFZxMALrFouwFKylx
# k2OGgs8chlZgz5tn10RNS84k8Ouezm7hdvnRgXCBAnlE35b7AOQ2w7LLFAxr/CJJ
# B/62Rc8DLQ+Q9oALkWKjxhO9la3LAtgMSl87XyH8w1YUIPF89QYlHGPiL3B/GC5c
# oOM9B+BSB3lgXOkV29K5uj4Tjr9RZ3+hghc6MIIXNgYKKwYBBAGCNwMDATGCFyYw
# ghciBgkqhkiG9w0BBwKgghcTMIIXDwIBAzEPMA0GCWCGSAFlAwQCAQUAMHgGCyqG
# SIb3DQEJEAEEoGkEZzBlAgEBBglghkgBhv1sBwEwMTANBglghkgBZQMEAgEFAAQg
# iaORkXJ1gB4IbBplR2SyKHpMNaYItI2fANAvLd4CKTcCEQCNk1RacZHYTOAf0w/R
# LRSjGA8yMDI1MDExMDIzMzYwOFqgghMDMIIGvDCCBKSgAwIBAgIQC65mvFq6f5WH
# xvnpBOMzBDANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNB
# NDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTI0MDkyNjAwMDAwMFoXDTM1
# MTEyNTIzNTk1OVowQjELMAkGA1UEBhMCVVMxETAPBgNVBAoTCERpZ2lDZXJ0MSAw
# HgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyNDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAL5qc5/2lSGrljC6W23mWaO16P2RHxjEiDtqmeOlwf0K
# MCBDEr4IxHRGd7+L660x5XltSVhhK64zi9CeC9B6lUdXM0s71EOcRe8+CEJp+3R2
# O8oo76EO7o5tLuslxdr9Qq82aKcpA9O//X6QE+AcaU/byaCagLD/GLoUb35SfWHh
# 43rOH3bpLEx7pZ7avVnpUVmPvkxT8c2a2yC0WMp8hMu60tZR0ChaV76Nhnj37DEY
# TX9ReNZ8hIOYe4jl7/r419CvEYVIrH6sN00yx49boUuumF9i2T8UuKGn9966fR5X
# 6kgXj3o5WHhHVO+NBikDO0mlUh902wS/Eeh8F/UFaRp1z5SnROHwSJ+QQRZ1fisD
# 8UTVDSupWJNstVkiqLq+ISTdEjJKGjVfIcsgA4l9cbk8Smlzddh4EfvFrpVNnes4
# c16Jidj5XiPVdsn5n10jxmGpxoMc6iPkoaDhi6JjHd5ibfdp5uzIXp4P0wXkgNs+
# CO/CacBqU0R4k+8h6gYldp4FCMgrXdKWfM4N0u25OEAuEa3JyidxW48jwBqIJqIm
# d93NRxvd1aepSeNeREXAu2xUDEW8aqzFQDYmr9ZONuc2MhTMizchNULpUEoA6Vva
# 7b1XCB+1rxvbKmLqfY/M/SdV6mwWTyeVy5Z/JkvMFpnQy5wR14GJcv6dQ4aEKOX5
# AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYE
# FJ9XLAN3DigVkGalY17uT5IfdqBbMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZU
# aW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEy
# NTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAD2tHh92mVvj
# OIQSR9lDkfYR25tOCB3RKE/P09x7gUsmXqt40ouRl3lj+8QioVYq3igpwrPvBmZd
# rlWBb0HvqT00nFSXgmUrDKNSQqGTdpjHsPy+LaalTW0qVjvUBhcHzBMutB6Hzele
# dbDCzFzUy34VarPnvIWrqVogK0qM8gJhh/+qDEAIdO/KkYesLyTVOoJ4eTq7gj9U
# FAL1UruJKlTnCVaM2UeUUW/8z3fvjxhN6hdT98Vr2FYlCS7Mbb4Hv5swO+aAXxWU
# m3WpByXtgVQxiBlTVYzqfLDbe9PpBKDBfk+rabTFDZXoUke7zPgtd7/fvWTlCs30
# VAGEsshJmLbJ6ZbQ/xll/HjO9JbNVekBv2Tgem+mLptR7yIrpaidRJXrI+UzB6vA
# lk/8a1u7cIqV0yef4uaZFORNekUgQHTqddmsPCEIYQP7xGxZBIhdmm4bhYsVA6G2
# WgNFYagLDBzpmk9104WQzYuVNsxyoVLObhx3RugaEGru+SojW4dHPoWrUhftNpFC
# 5H7QEY7MhKRyrBe7ucykW7eaCuWBsBb4HOKRFVDcrZgdwaSIqMDiCLg4D+TPVgKx
# 2EgEdeoHNHT9l3ZDBD+XgbF+23/zBjeCtxz+dL/9NWR6P2eZRi7zcEO1xwcdcqJs
# yz/JceENc2Sg8h3KeFUCS7tpFk7CrDqkMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhH
# rP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQD
# ExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcw
# MzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIElu
# Yy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYg
# VGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# xoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo
# +n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQX
# f6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8
# ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6l
# Y2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lX
# KZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU
# 2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2
# RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR
# 8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015L
# dhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNY
# CQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIG
# A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshv
# MB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIB
# hjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQw
# QwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZI
# AYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBgu
# EE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFn
# zbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/t
# YLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWK
# cXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7
# pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkP
# lM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4
# c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kad
# dSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYaw
# mKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL
# 5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3b
# NzgaoSv27dZ8/DCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZI
# hvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNz
# dXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVow
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjww
# IjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J5
# 8soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMH
# hOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6
# Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQ
# ecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4b
# A3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9
# WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCU
# tNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvo
# ZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/J
# vNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCP
# orF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMB
# Af8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXr
# oq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRt
# MGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEF
# BQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgw
# BgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cH
# vZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8
# UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTn
# f+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxU
# jG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8j
# LfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDGCA3Yw
# ggNyAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRp
# bWVTdGFtcGluZyBDQQIQC65mvFq6f5WHxvnpBOMzBDANBglghkgBZQMEAgEFAKCB
# 0TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDExMDIzMzYwOFowKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQU29OF7mLb0j575PZx
# SFCHJNWGW0UwLwYJKoZIhvcNAQkEMSIEIP+asupnOOVsEcumfQWPXZfMzTt7V2SF
# 7R6HCFuQvCIpMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIHZ2n6jyYy8fQws6IzCu
# 1lZ1/tdz2wXWZbkFk5hDj5rbMA0GCSqGSIb3DQEBAQUABIICAIoFdN2kJ013Z6dc
# 66BUsqLMQO1KaIz4MANtyjGPvw+YccYsMUBnD0dmQzh/3r+/ZFwEHMmVWBF3beGk
# /usn0g1Ye5ogn60B9xqmoSaglok7CiA7RV3x1qYr6g7M33rCw+CwNO3IgUQoaGvq
# 4T2ugP9vK+ZRe+zYV68QEVS1ZOzfjjtFjUMImDRa2hRp9l5JVsGH2sdD3EZ2xPDs
# gWXzpQkkjje5id7yCsA5/hvy2GCP4SvvS4jwYLiXvwD9ULI7vs+YiAJJHsTAocsm
# DbEef9ODpJBHbMbo1Do7tcX1JM1hYhdIHa1gx68/Nm3UFlTWFulXdOt9zHGgegOb
# SAv0CA/WV+fm29cOIfL2TvpUOlyI70mSdbqVc7Pq5WpNYdRRyqeuWHhA41769ew8
# eTHFnBxhN41kd5sdJToePE0sR6z8jNWI+GG+HDoNMC/TFQdialZXaljz7h5OqXdM
# NJwJrd3g4khyITZxlFyIsKYfU6BA5Zsk86VDoMs5vLKm/Emwx3vCRAxiYLURr3NB
# SGJUlboK3cyVJnU1pZauHafO56K/l8V69tCDPYUM0t/Pl+vp2t5/dHLQjv23TsW/
# bZi+MqAsSEQoJ6BbEtAzs2SlSajoZpvbjGowK2jQawJVSJsdduHQ1VHLb8pp2hGE
# hpsmNBsSnlOck/01C/BimpHNXOq2
# SIG # End signature block

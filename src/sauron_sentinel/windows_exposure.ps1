#requires -Version 5.1
<#
.SYNOPSIS
  Read-only, local Windows exposure review. No elevation or configuration changes.
.DESCRIPTION
  Prints limited risk indicators only; never reads keys, passwords, files, browser data
  or full IP/account lists. Findings are leads for review, not proof of compromise.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This script is for Windows only.' }

$script:Results = [System.Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Name, [string]$Status, [string]$Detail)
    $script:Results.Add([pscustomobject]@{ Check = $Name; Status = $Status; Detail = $Detail })
}
function Run-Check {
    param([string]$Name, [scriptblock]$Action)
    try { & $Action } catch { Add-Check $Name 'UNKNOWN' 'Could not read with current permissions or available modules.' }
}
Run-Check 'Firewall' {
    $p = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($p.Count -eq 0) { Add-Check 'Firewall' 'UNKNOWN' 'No profiles returned.' }
    elseif (@($p | Where-Object { -not $_.Enabled }).Count -gt 0) {
        Add-Check 'Firewall' 'REVIEW' 'One or more firewall profiles report disabled.'
    } else { Add-Check 'Firewall' 'OK' 'All returned firewall profiles enabled.' }
}
Run-Check 'Defender real-time protection' {
    $d = Get-MpComputerStatus
    if ($d.RealTimeProtectionEnabled -eq $true) {
        Add-Check 'Defender real-time protection' 'OK' 'Enabled.'
    } else {
        Add-Check 'Defender real-time protection' 'REVIEW' 'Not enabled or a different antivirus may be managing protection.'
    }
}
Run-Check 'Remote Desktop' {
    $key = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
    if ($key.fDenyTSConnections -eq 1) { Add-Check 'Remote Desktop' 'OK' 'RDP host connection setting disabled.' }
    else { Add-Check 'Remote Desktop' 'REVIEW' 'RDP host connection setting allows access; check edition, firewall and users.' }
}
Run-Check 'Remote Assistance' {
    $key = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp'
    if ($key.fAllowToGetHelp -eq 0) { Add-Check 'Remote Assistance' 'OK' 'Disabled in registry.' }
    else { Add-Check 'Remote Assistance' 'REVIEW' 'Remote Assistance enabled; confirm necessity.' }
}
foreach ($name in @('WinRM', 'RemoteRegistry')) {
    $serviceName = $name
    Run-Check $serviceName {
        $svc = Get-Service -Name $serviceName
        if ($svc.Status -eq 'Running') {
            Add-Check $serviceName 'REVIEW' 'Service running; review listeners, access control and firewall.'
        } else { Add-Check $serviceName 'OK' 'Service not running at the time of inspection.' }
    }
}
Run-Check 'Remote support software' {
    # Names are examples; this does not detect renamed, covert or custom remote tools.
    $pattern = '(?i)anydesk|teamviewer|rustdesk|screenconnect|connectwise|splashtop|logmein|dwagent|chromeremotedesktop|ultravnc|tightvnc|realvnc|meshagent|ateraagent'
    $services = @(Get-Service | Where-Object {
        $_.Status -eq 'Running' -and ($_.Name -match $pattern -or $_.DisplayName -match $pattern)
    } | Select-Object -ExpandProperty Name -Unique)
    $processes = @(Get-Process | Where-Object { $_.ProcessName -match $pattern } |
        Select-Object -ExpandProperty ProcessName -Unique)
    $names = @($services + $processes | Sort-Object -Unique)
    if ($names.Count -gt 0) {
        Add-Check 'Remote support software' 'REVIEW' ('Active indicators: ' + ($names -join ', ') + '. Check whether you installed/authorized these.')
    } else {
        Add-Check 'Remote support software' 'OK' 'No named remote-support services/processes found; this cannot rule out hidden or renamed tools.'
    }
}
Run-Check 'OpenSSH server' {
    $svc = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Add-Check 'OpenSSH server' 'OK' 'Service not installed under standard name.'
    } elseif ($svc.Status -eq 'Running') {
        Add-Check 'OpenSSH server' 'REVIEW' 'SSH daemon running; review users, host firewall and key access.'
    } else {
        Add-Check 'OpenSSH server' 'OK' 'Service present but not running.'
    }
}
Run-Check 'SMBv1 server' {
    $cfg = Get-SmbServerConfiguration
    if ($cfg.EnableSMB1Protocol) {
        Add-Check 'SMBv1 server' 'REVIEW' 'Legacy SMBv1 server protocol enabled.'
    } else {
        Add-Check 'SMBv1 server' 'OK' 'Legacy SMBv1 server protocol disabled.'
    }
}
Run-Check 'Sensitive TCP listeners' {
    $ports = @(Get-NetTCPConnection -State Listen |
        Where-Object { $_.LocalPort -in @(22, 135, 139, 445, 3389, 5985, 5986) } |
        Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
    if ($ports.Count -eq 0) { Add-Check 'Sensitive TCP listeners' 'OK' 'No selected listeners found at this instant.' }
    else { Add-Check 'Sensitive TCP listeners' 'REVIEW' ('Review local ports: ' + ($ports -join ', ') + '. A listener does not prove Internet exposure.') }
}
Run-Check 'System drive encryption' {
    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive
    if ($vol.ProtectionStatus -eq 'On') { Add-Check 'System drive encryption' 'OK' 'BitLocker reports protection on.' }
    else { Add-Check 'System drive encryption' 'REVIEW' 'BitLocker protection not reported on; check device encryption alternatives.' }
}
Run-Check 'Windows Update service' {
    $svc = Get-Service -Name 'wuauserv'
    if ($svc.StartType -eq 'Disabled') { Add-Check 'Windows Update service' 'REVIEW' 'Service start type disabled.' }
    else { Add-Check 'Windows Update service' 'OK' 'Service not disabled; install pending updates separately.' }
}
if ($env:SAURON_EXPOSURE_JSON -eq '1') {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    # Local machine-readable mode for the opt-in Sentinel desktop security panel.
    # No network upload, disk write, elevation or security-setting changes.
    ConvertTo-Json -InputObject @($script:Results.ToArray()) -Depth 3 -Compress
} else {
    Write-Output 'Windows exposure: READ-ONLY indicators (OK is not a clean bill of health)'
    $script:Results | Format-Table -AutoSize -Wrap
}

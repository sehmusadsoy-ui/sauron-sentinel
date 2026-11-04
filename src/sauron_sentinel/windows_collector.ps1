# Read selected local Windows event records. No audit or security settings change.
param(
    [ValidateNotNullOrEmpty()][string]$Since = $env:SAURON_SENTINEL_SINCE,
    [ValidateRange(1,1000)][int]$Limit = $env:SAURON_SENTINEL_LIMIT
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$start = [DateTimeOffset]::Parse($Since, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
$channels = @(
    @{ Name = 'System'; Ids = @(7045,7040,104,6005,6006,6008,41); Providers = @('Service Control Manager','Microsoft-Windows-Eventlog','EventLog','Microsoft-Windows-Kernel-Power') },
    @{ Name = 'Security'; Ids = @(4625,4624,4720,4732,1102); Providers = @('Microsoft-Windows-Security-Auditing','Microsoft-Windows-Eventlog') },
    @{ Name = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1116,1117,5001,5007); Providers = @('Microsoft-Windows-Windows Defender') }
)
$records = New-Object System.Collections.ArrayList
$sources = New-Object System.Collections.ArrayList

function Read-Field($fields, [string[]]$names) {
    foreach ($name in $names) {
        if ($fields.ContainsKey($name)) { return [string]$fields[$name] }
    }
    return $null
}

foreach ($channel in $channels) {
    $source = [ordered]@{ channel = $channel.Name; status = 'ok'; event_count = 0; limit_reached = $false }
    try {
        $log = Get-WinEvent -ListLog $channel.Name -Force -ErrorAction Stop
        if (-not $log.IsEnabled) {
            $source.status = 'unavailable'; $source.error = 'channel_disabled'
            [void]$sources.Add($source)
            continue
        }
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = $channel.Name; Id = $channel.Ids; ProviderName = $channel.Providers; StartTime = $start } -MaxEvents $Limit -ErrorAction Stop)
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @() }
            else { throw }
        }
        $source.limit_reached = ($events.Count -ge $Limit)
        foreach ($event in $events) {
            try {
                [xml]$xml = $event.ToXml()
                $fields = @{}
                foreach ($node in $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
                    if ($node.HasAttribute('Name')) {
                        $fields[$node.GetAttribute('Name')] = $node.InnerText
                    }
                }
                # Event 1102 uses UserData rather than EventData.
                foreach ($node in $xml.SelectNodes("//*[local-name()='UserData']//*[local-name()='SubjectUserName']")) {
                    $fields['SubjectUserName'] = $node.InnerText
                }
                $data = @{}
                $id = [int]$event.Id
                if ($id -in @(4624,4625,4720)) {
                    $data.user = Read-Field $fields @('TargetUserName')
                    $data.target_user = $data.user
                }
                if ($id -in @(4732,1102)) { $data.user = Read-Field $fields @('SubjectUserName') }
                if ($id -eq 4732) { $data.group_name = Read-Field $fields @('TargetUserName') }
                if ($id -in @(4624,4625)) { $data.logon_type = Read-Field $fields @('LogonType') }
                if ($id -eq 7045) {
                    $data.service_name = Read-Field $fields @('ServiceName')
                    $data.service_type = Read-Field $fields @('ServiceType')
                    $data.start_type = Read-Field $fields @('StartType')
                }
                if ($id -eq 7040) {
                    $data.service_name = Read-Field $fields @('param1','ServiceName')
                    $data.old_start_type = Read-Field $fields @('param2')
                    $data.start_type = Read-Field $fields @('param3','StartType')
                }
                if ($id -in @(1116,1117)) { $data.threat_name = Read-Field $fields @('Threat Name','ThreatName') }
                $safe = @{}
                $truncated = $false
                foreach ($key in $data.Keys) {
                    $value = [string]$data[$key]
                    if (-not [string]::IsNullOrWhiteSpace($value) -and $value -ne '-') {
                        $value = [regex]::Replace($value, '[\x00-\x1f\x7f]', ' ')
                        if ($value.Length -gt 256) { $value = $value.Substring(0,256); $truncated = $true }
                        $safe[$key] = $value
                    }
                }
                [void]$records.Add([ordered]@{
                    channel = $channel.Name; provider = [string]$event.ProviderName
                    event_id = $id; record_id = [long]$event.RecordId
                    timestamp = $event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
                    data = $safe; fields_truncated = $truncated
                })
                $source.event_count++
            } catch {
                $source.status = 'error'; $source.error = 'invalid_event'
            }
        }
    } catch {
        $errorId = [string]$_.FullyQualifiedErrorId
        $permissionDenied = $false
        $exception = $_.Exception
        while ($null -ne $exception) {
            if ($exception -is [UnauthorizedAccessException] -or $exception -is [System.Security.SecurityException]) { $permissionDenied = $true }
            $exception = $exception.InnerException
        }
        if ($permissionDenied -or $errorId -match 'Unauthorized|AccessDenied|PermissionDenied') {
            $source.status = 'unavailable'; $source.error = 'permission_denied'
        } elseif ($errorId -match 'NoMatchingLogsFound|LogNotFound') {
            $source.status = 'unavailable'; $source.error = 'channel_unavailable'
        } else {
            $source.status = 'error'; $source.error = 'collection_failed'
        }
    }
    [void]$sources.Add($source)
}
[ordered]@{ sources = @($sources); records = @($records) } | ConvertTo-Json -Depth 8 -Compress

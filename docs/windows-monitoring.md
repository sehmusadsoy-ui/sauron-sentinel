# Windows monitoring

## Start and stop

Double-click `start-sentinel.cmd`, or run `Start-Sentinel.ps1` from PowerShell. The application uses the current account, opens a local browser dashboard, and keeps monitoring while the terminal remains open. Press Ctrl+C to stop.

For a manual launch after installation:

```sh
sauron-sentinel serve --port 8765 --data-dir sentinel-data --interval 15 --lookback-hours 24 --open-browser
```

There is no administrator prompt, remote-computer query, audit-policy edit, or active test attack. The browser connects to `127.0.0.1` only. Choosing another port can resolve a conflict with an existing local application.

## Selected events

The collector uses bounded, read-only `Get-WinEvent` queries. Its event families are deliberately selected; it does not copy every Windows event.

| Channel | Windows event ID | Normalized kind |
| --- | --- | --- |
| System | 7045 | `service.installed` |
| System | 7040 | `service.start_changed` |
| System | 104 | `log.cleared` |
| System | 6005 | `system.started` |
| System | 6006 | `system.stopped` |
| System | 6008, 41 | `system.unexpected_shutdown` |
| Security | 4625 | `auth.failure` |
| Security | 4624 | `auth.success` |
| Security | 4720 | `account.created` |
| Security | 4732 | `group.member_added` |
| Security | 1102 | `log.cleared` |
| Microsoft-Windows-Windows Defender/Operational | 1116 | `defender.threat` |
| Microsoft-Windows-Windows Defender/Operational | 1117 | `defender.action` |
| Microsoft-Windows-Windows Defender/Operational | 5001 | `defender.disabled` |
| Microsoft-Windows-Windows Defender/Operational | 5007 | `defender.config_changed` |

Channel/provider pairs are validated before normalization. All collected observations use `source=windows-eventlog` and `synthetic=false`. Selected attributes include the provider, channel, Windows event ID, record ID, and allowlisted contextual fields when present. The device label is derived from the local computer name; no external lookup is needed.

System startup/shutdown records are informational observations, not automatic evidence of compromise. A service/account/group rule match may reflect authorized administration. The dashboard keeps ordinary events visible without needing to invent an alert.

## Source status

| Status | Meaning |
| --- | --- |
| `ok`, `event_count=0` | Log is accessible; no selected records matched this query |
| `ok`, positive count | Selected records were collected successfully |
| `unavailable` | Current access/platform cannot provide this source |
| `error` | Collection/decoding failed; this is not an empty successful query |
| `limit_reached=true` | The query returned its cap; additional matching records may have been omitted |

Error details can include `permission_denied`, `channel_unavailable`, `channel_disabled`, `not_windows`, `powershell_unavailable`, `timeout`, `collection_failed`, or `invalid_response`. Do not interpret an unavailable log as proof that no relevant activity occurred.

Windows permissions can restrict event-log access, especially without administrator rights. Microsoft documents this behavior for [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent). The collector reports the result of its existing access and does not change permissions.

## Polling, history, and omissions

The initial lookback defaults to 24 hours. Every channel returns at most 200 newest matching records by default, with a supported one-time collection limit of 1–1,000 per channel. When all sources are healthy, subsequent monitor polls overlap the previous scan start by 120 seconds to reduce ordinary boundary misses. If any channel is unavailable or reports an error, the monitor retries the configured rolling lookback until every source is healthy. Retrying does not remove the per-channel cap; `limit_reached` remains important. Recollected retained observations are deduplicated by normalized ID.

Live observations are evaluated chronologically. A newly discovered record older than the current engine watermark is saved to the timeline immediately and counted in `late_events`, but skipped for the current live alert pass. Chronological replay on restart or recovery can add historical alerts from retained late records. Poll overlap and result caps are not a durable Windows event subscription; very busy logs, unavailable channels, long delays, or retention can lead to omissions.

SQLite keeps up to 20,000 events and 2,000 alerts, including alert evidence snapshots created before the current batch is pruned. Restart/recovery replay reconstructs rule state and inserts previously missing alerts without overwriting existing alert IDs. If the application stops after an event is committed but before its alert is saved, replay can recover that alert while the event remains retained. This is local operational history, not a full audit archive or evidence-signing system.

Database errors are reported without automatically resetting existing data. Stop Sentinel before inspecting or moving its database, preserve a copy when investigating corruption, and do not assume an error means the earlier history was deleted.

## One-time collection

```sh
sauron-sentinel collect-windows --output windows-output --since-hours 24 --limit 200
```

Choose a new directory for each snapshot. Inspect its source-status information as well as its events. A partially available collection can still be useful and returns success; if every source is unavailable, the command returns exit code `3`. Argument or processing failures return `2`.

## Privacy

Selected account/service names and threat labels may be sensitive. Values are capped to 256 characters and marked when truncated; full rendered event messages and raw XML are not stored. The database and exports are plaintext. Keep them local, review before sharing, and never commit real captures to the repository.

The collector does not change Defender or Windows auditing settings. Microsoft's [Defender event reference](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus) explains the corresponding Defender records. Sentinel displays those observations; it does not implement the protection engine itself.

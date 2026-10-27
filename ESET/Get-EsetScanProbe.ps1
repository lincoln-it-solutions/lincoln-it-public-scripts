<#
.SYNOPSIS
    Read-only probe: what does ESET report about the last scans and the detections log?
.DESCRIPTION
    Written 2026-10-26. "ermm get scan-info" on one client PC showed a finished scan with
    infected_object_count = 1, while Monitor-ESET reported no detections in the last 24 h. This
    prints, for that comparison only:
      1. the whole "get scan-info" reply (scan ids, states, counts - no file contents)
      2. the whole Detections log ("get logs --name virlog", no date filter), first 1500 characters
    Nothing on the machine is changed.
#>
$ermm = Join-Path $env:ProgramFiles 'ESET\ESET Security\ermm.exe'
if (-not (Test-Path $ermm)) { Write-Output "ermm.exe not found on $env:COMPUTERNAME"; exit 0 }
Write-Output "== $env:COMPUTERNAME  $(Get-Date -Format s)"
$scan = (& $ermm get scan-info 2>&1 | Out-String).Trim()
Write-Output "-- get scan-info ($($scan.Length) chars):"
Write-Output $scan.Substring(0, [Math]::Min(2500, $scan.Length))
$vir = (& $ermm get logs --name virlog 2>&1 | Out-String).Trim()
# One compact line per detection (time | name | action | handled | object), newest 12 by Time, so the
# list can be compared with the scan counts above without dumping the whole log.
try {
    $j = $vir | ConvertFrom-Json
    $entries = @($j.result.virlog.logs)
    Write-Output "-- virlog entries: $($entries.Count) (newest 12 by Time)"
    $entries | Sort-Object { $_.'Time' } -Descending | Select-Object -First 12 | ForEach-Object {
        Write-Output ('   {0} | {1} | {2} | handled={3} | scanner={4}' -f $_.'Time', $_.'Threat Name', $_.'Action Taken', $_.'Threat Handled', $_.'Scanner ID')
    }
} catch { Write-Output "-- virlog not parsed: $($vir.Substring(0, [Math]::Min(300, $vir.Length)))" }

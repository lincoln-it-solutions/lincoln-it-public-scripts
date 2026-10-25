<#
.SYNOPSIS
    TRMM script check: alerts when ShadowProtect ImageManager (StorageCraft or Arcserve
    branded) has failing managed folders, has stopped consolidating, or its service is down.

.DESCRIPTION
    Safe to put on every Windows device: if ImageManager is not installed it exits 0.
    It only reads the service and the Application event log; it never changes anything.

    What it checks
      1. Service       - "StorageCraft ImageManager" must be Running. (The Arcserve-branded
                         8.x releases still use this service name - seen on Steve-Win11, 8.1.2.6.)
      2. Current error - for each managed folder / replication target seen in the last
                         LookbackDays, Errors newer than that folder's last success mean it is
                         still failing: MinErrorsForCritical or more = critical, fewer = warning.
                         Why: a single "network path was not found" blip (seen on D5C8JM54 at
                         07:24 while the same NAS took backups fine at 10:00) would otherwise
                         stay critical until the next nightly consolidation. Real faults repeat
                         (e.g. LINCOLNDC03 logged 1124, 1123 then 1121 for one bad chain).
                         A single error that has NOT repeated within TransientClearHours is
                         treated as cleared. Evidence (event history 2026-10-20): a real outage
                         repeats within minutes (LCM-SRV-HPV logged 1129 for all 4 folders at
                         13:12, 13:21 and 13:36 on 2026-10-14), while blips log once and stop
                         (D5C8JM54 07:24 on 2026-10-20 with ImageManager idle and healthy;
                         Steve-Win11 16:13 on 2026-10-13). A consolidation that keeps failing
                         is still caught by the freshness rule below.
                         A Warning newer than the last success is reported as a warning.
      3. Freshness     - each folder that normally logs successes must have one recently.
                         Learned per folder like the ShadowProtect check: the larger of
                         MaxHoursSinceSuccess and IntervalMultiplier x its median gap.
      4. Error-only    - some keys only ever log errors (e.g. a replication target such as
                         "host:2211/LCM-SRV-SQL"): ImageManager logs no "replicated OK" event,
                         so recovery shows only as the errors STOPPING. While a send keeps
                         failing, ImageManager retries and logs 1126 about once an hour per
                         target (LCM-SRV-HPV: hourly from 2026-10-21 17:06 to 2026-10-22 09:21,
                         then it recovered - console showed Queued Files: 0). So:
                           latest error older than RecentErrorHours (2h)  -> cleared (OK)
                           only 1 error in 24h and older than TransientClearHours -> cleared blip
                           MinErrorsForCritical+ errors in 24h, still recent -> critical
                           otherwise -> warning

    Where the data comes from
      Arcserve/StorageCraft do not publish an ImageManager event Id list that we could find,
      so the Ids below are what was actually logged on Lincoln IT devices (Steve-Win11,
      LCM-SRV-HPV, D5C8JM54, Belvin SERVER) on 2026-10-20. Provider: "StorageCraft ImageManager".
        1120 Information  first line = image file processed, e.g. "\\nas\backups\X\C_VOL-b002-i8326-cd.spi"
                          ("-cd"/"-cw" = daily/weekly consolidated file) -> success for that folder
        1121 Error        "Collapse Daily Exception: Daily collapse aborted due to verification status..."
        1123 Error        "Image file data verification failed: <file>"
        1124 Error        "Image chain dependency verification failed: <file>"
        1126 Error        "Does not connect to any remote file: <file>"   (replication target)
        1129 Error        "unable to enumerate files: The network path was not found."
        0/1101/1102/1103  service start-up messages (no folder - ignored)
      The event LEVEL decides the result (Error/Critical = failure, Warning = warning,
      Information = success), so an Id we have not seen is still classified correctly.
      The first line of each message names the folder (or the file, whose parent folder is used).

    Exit codes (same convention as Monitor-ESET.ps1)
      0 = OK, or ImageManager not installed
      1 = Warning  (set "Warning return codes" = 1 on the TRMM script check)
      2 = Critical
      3 = Script could not read the event log

    Windows PowerShell 5.1 syntax only.
#>
[CmdletBinding()]
param(
    # Minimum allowed hours since a folder's last success. 72 = 3 days (was 36, changed 2026-10-25
    # at Ethan's request): some managed devices are workstations that are off or asleep over the
    # weekend, so nothing is consolidated or replicated from Friday evening to Monday morning
    # (~62 h). Also the grace period before a device with too short an event log starts alerting.
    [int]$MaxHoursSinceSuccess = 72,

    # How many times its usual interval a folder may go without a success.
    [double]$IntervalMultiplier = 1.5,

    # Folders not seen for this long are treated as no longer managed and ignored.
    # 30 (was 7): a folder whose ImageManager silently stopped must stay in view long enough
    # for the freshness rule to flag it. Shelley_Beans_2 (Lindum, 2026-10-22): service Running,
    # console Idle, but no consolidation or log writes since 2026-10-13/14 - with 7 days the
    # folder had dropped out and only a vague "no activity" warning remained.
    # A folder that was deliberately removed will alert for up to this long; use -ExcludeFolder.
    [int]$LookbackDays = 30,

    # Errors since the last success needed before it is critical (fewer = warning).
    [int]$MinErrorsForCritical = 2,

    # A single (non-repeated) error older than this many hours is treated as a cleared blip.
    # The check runs hourly and needs 2 failures in a row to alert, so a one-off blip never alerts.
    [double]$TransientClearHours = 1,

    # For keys that never log a success (replication targets): once no new error has been logged
    # for this many hours, the target is treated as recovered. ImageManager retries roughly hourly
    # (seen on LCM-SRV-HPV), so 2h = at least one retry passed without an error.
    [double]$RecentErrorHours = 2,

    # Folder paths / targets to ignore. Wildcards allowed, matched case-insensitively,
    # e.g. '\\oldnas\*'.
    [string[]]$ExcludeFolder = @(),

    # Per-device record of each folder's recent successes, so the check doesn't depend on the
    # Application log keeping enough history. Why: on a Simpler Law server (2026-10-23) a SQL
    # instance logged ~120 events/minute, the 20 MB circular log held only ~8 hours, and the
    # previous evening's consolidation event was gone by morning -> false "no folder activity".
    # If the file can't be read or written the check still runs on the event log alone.
    [string]$HistoryFile = (Join-Path $env:ProgramData 'LincolnIT\BackupMonitoring\imagemanager-history.json'),

    # Per-device opt-out, fed from an agent custom field. Comma-separated list of
    # ShadowProtect, ImageManager, Veeam or All. Matching is case-insensitive.
    [string]$SkipChecks = ''
)


# ---------------------------------------------------------------------------
# Exit helper. The TRMM agent runs scripts as "powershell.exe ... <file>" without -File
# (rmmagent agent_windows.go), so Windows PowerShell treats it as -Command and a plain
# "exit 2" reaches TRMM as 1. SetShouldExit passes the real code through - tested via a
# TRMM script check on Steve-Win11 2026-10-20: plain exit 2 -> 1, SetShouldExit(2) -> 2.
# ---------------------------------------------------------------------------
function Stop-Check([int]$Code) {
    $host.SetShouldExit($Code)
    exit $Code
}

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 0. Per-device opt-out.
#    TRMM passes the agent custom field in via the script argument
#    -SkipChecks {{agent.Backup Monitoring Skip}}. If it names this check (or "All"),
#    stop here and pass. If the field doesn't exist TRMM passes the text through unchanged
#    (per TRMM's script-variable docs), so anything still containing "{{" is ignored.
# ---------------------------------------------------------------------------
if ($SkipChecks -and $SkipChecks -notmatch '\{\{') {
    $skip = @($SkipChecks -split '[,;\s]+' | Where-Object { $_ })
    if ($skip -contains 'All' -or $skip -contains 'ImageManager') {
        Write-Output "OK: ImageManager check skipped on this device (Backup Monitoring Skip = '$SkipChecks')."
        Stop-Check 0
    }
}

$script:Critical = New-Object System.Collections.Generic.List[string]
$script:Warning  = New-Object System.Collections.Generic.List[string]
$script:Ok       = New-Object System.Collections.Generic.List[string]

function Test-Excluded([string]$Name) {
    foreach ($p in $ExcludeFolder) { if ($Name -like $p) { return $true } }
    return $false
}

function Get-AllowedHours([datetime[]]$SuccessTimes) {
    # Median gap between successes x multiplier, never below MaxHoursSinceSuccess.
    # Median so a past outage doesn't loosen the check.
    $allowed = [double]$MaxHoursSinceSuccess
    $t = @($SuccessTimes | Sort-Object)
    if ($t.Count -ge 2) {
        $gaps = @(for ($i = 1; $i -lt $t.Count; $i++) { ($t[$i] - $t[$i - 1]).TotalHours }) | Sort-Object
        $median = $gaps[[int][math]::Floor(($gaps.Count - 1) / 2)]
        $allowed = [math]::Max($allowed, $median * $IntervalMultiplier)
    }
    return [math]::Round($allowed, 1)
}

function Get-FolderKey([string]$FirstLine) {
    # Turns the first message line into a folder key, or $null if it isn't a path.
    $line = $FirstLine.Trim()
    $isUnc     = $line -match '^\\\\'
    $isLocal   = $line -match '^[A-Za-z]:\\'
    $isRemote  = $line -match '^[^\s\\/]+:\d+/'          # replication target, e.g. host:2211/NAME
    if (-not ($isUnc -or $isLocal -or $isRemote)) { return $null }
    # A file (has an extension like .spi/.spf/.md5) -> use its folder.
    if (($isUnc -or $isLocal) -and $line -match '\.[A-Za-z0-9]{2,5}$') { $line = Split-Path $line -Parent }
    # Lower-case and drop trailing slashes: the same folder is logged as both
    # "\\bifrangioffsite\..." and "\\BIFRANGIOFFSITE\..." (seen on Steve-Win11).
    return ($line.TrimEnd('\', '/')).ToLowerInvariant()
}

# ---------------------------------------------------------------------------
# 1. Detect ImageManager by its service.
# ---------------------------------------------------------------------------
$svc = Get-Service -Name 'StorageCraft ImageManager' -ErrorAction SilentlyContinue
if (-not $svc) {
    # Fallback in case a future release renames the service.
    $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'ImageManager' } | Select-Object -First 1
}
if (-not $svc) {
    Write-Output 'OK: ImageManager is not installed on this device - nothing to check.'
    Stop-Check 0
}
if ($svc.Status -ne 'Running') {
    $script:Critical.Add("Service '$($svc.DisplayName)' is $($svc.Status) - no verification, consolidation or replication is happening.")
} else {
    $script:Ok.Add("Service '$($svc.DisplayName)' is Running.")
}

# ---------------------------------------------------------------------------
# 2. Read ImageManager events and turn each into (Key, Result, Time, Detail).
# ---------------------------------------------------------------------------
$since = (Get-Date).AddDays(-$LookbackDays)
try {
    # Find the provider name(s) actually registered rather than assuming one.
    $providers = @(Get-WinEvent -ListProvider '*ImageManager*' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    if ($providers.Count -eq 0) { $providers = @('StorageCraft ImageManager') }
    $raw = @()
    try {
        $raw = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $providers; StartTime = $since } -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found|not an event provider') { throw }
    }
} catch {
    Write-Output "UNKNOWN: could not read the Application event log: $($_.Exception.Message)"
    Stop-Check 3
}

$events = foreach ($e in $raw) {
    $lines = @($e.Message -split "`r?`n" | Where-Object { $_.Trim() -ne '' })
    if ($lines.Count -eq 0) { continue }
    $key = Get-FolderKey $lines[0]
    if (-not $key) { continue }                           # start-up / licence messages etc.
    if (Test-Excluded $key) { continue }
    $result = switch ([int]$e.Level) { 1 { 'Failed' } 2 { 'Failed' } 3 { 'Warning' } default { 'Success' } }
    # The detail is the last non-empty line, which is where the error text sits, e.g.
    # "Image file data verification failed: D_VOL-b002-i24312.spi".
    $detail = if ($lines.Count -gt 1) { $lines[-1].Trim() } else { '' }
    [pscustomobject]@{ Key = $key; Id = $e.Id; Result = $result; Time = $e.TimeCreated; Detail = $detail }
}
$events = @($events)

# ---------------------------------------------------------------------------
# 2a. Only judge folders ImageManager is configured to manage right now.
#     The folder list lives in the registry, one subkey per managed folder with a Path value
#     (HKLM\SYSTEM\CurrentControlSet\Services\StorageCraft ImageManager\Parameters\Watches).
#     Why: Steve-Win11 (2026-10-23) still alerted on \\iema-off-site\... folders that had been
#     removed from ImageManager on ~5 Oct when they moved to \\nas2022-offsite\... - their old
#     events were still in the log. Replication targets (host:port/name) are not in this list,
#     so they are kept. If the list can't be read, nothing is filtered.
# ---------------------------------------------------------------------------
$watchRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\StorageCraft ImageManager\Parameters\Watches'
$watches = @()
try {
    $watches = @(Get-ChildItem -LiteralPath $watchRoot -ErrorAction Stop | ForEach-Object { $_.GetValue('Path') } |
        Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\', '/').ToLowerInvariant() })
} catch { $watches = @() }

function Test-Managed([string]$Key) {
    # Replication targets and "unknown" keys are always kept.
    if ($Key -notmatch '^(\\\\|[a-z]:\\)') { return $true }
    if ($watches.Count -eq 0) { return $true }
    # A folder counts if it is a managed folder or sits inside one.
    foreach ($w in $watches) { if ($Key -eq $w -or $Key.StartsWith($w + '\')) { return $true } }
    return $false
}

$retired = @($events | Where-Object { -not (Test-Managed $_.Key) } | ForEach-Object { $_.Key } | Sort-Object -Unique)
$events  = @($events | Where-Object { Test-Managed $_.Key })

# ---------------------------------------------------------------------------
# 2b. Merge with the per-device history of successes (see -HistoryFile).
#     Stored as { "<folder key>": ["2026-10-22T17:42:00.0000000Z", ...] } in UTC.
# ---------------------------------------------------------------------------
$history = @{}
try {
    if (Test-Path -LiteralPath $HistoryFile) {
        $raw = Get-Content -LiteralPath $HistoryFile -Raw | ConvertFrom-Json
        foreach ($p in $raw.PSObject.Properties) {
            # "__firstRun" is metadata (when this device started keeping history), not a folder.
            if ($p.Name -eq '__firstRun') { continue }
            # Windows PowerShell 5.1 returns these as strings; newer versions may already give DateTime.
            $history[$p.Name] = @($p.Value | ForEach-Object { if ($_ -is [datetime]) { $_.ToLocalTime() } else { ([datetime]::Parse($_, $null, [Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime() } })
        }
    }
} catch { $history = @{} }   # unreadable/corrupt history: rebuild from the event log

# When this device started keeping its own history (kept across runs; set on first run).
$firstRun = Get-Date
try {
    if ($raw -and $raw.PSObject.Properties['__firstRun']) {
        $v = $raw.__firstRun
        $firstRun = if ($v -is [datetime]) { $v.ToLocalTime() } else { ([datetime]::Parse($v, $null, [Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime() }
    }
} catch { $firstRun = Get-Date }

foreach ($e in ($events | Where-Object { $_.Result -eq 'Success' })) {
    if (-not $history.ContainsKey($e.Key)) { $history[$e.Key] = @() }
    $history[$e.Key] = @($history[$e.Key]) + $e.Time
}
# Tidy: de-duplicate to the minute, keep within the lookback, newest 30 per folder.
foreach ($k in @($history.Keys)) {
    $history[$k] = @($history[$k] | Where-Object { $_ -gt $since } |
        Sort-Object -Unique { $_.ToString('yyyyMMddHHmm') } | Sort-Object -Descending | Select-Object -First 30)
    if ($history[$k].Count -eq 0 -or (Test-Excluded $k) -or -not (Test-Managed $k)) { $history.Remove($k) }
}
try {
    $dirOut = Split-Path -Parent $HistoryFile
    if (-not (Test-Path -LiteralPath $dirOut)) { New-Item -ItemType Directory -Path $dirOut -Force | Out-Null }
    $outObj = [ordered]@{ '__firstRun' = $firstRun.ToUniversalTime().ToString('o') }
    foreach ($k in ($history.Keys | Sort-Object)) { $outObj[$k] = @($history[$k] | ForEach-Object { $_.ToUniversalTime().ToString('o') }) }
    ($outObj | ConvertTo-Json -Depth 3) | Set-Content -LiteralPath $HistoryFile -Encoding UTF8
} catch { }   # not fatal

# Add remembered successes that are no longer in the event log, so folders whose events have
# rolled out are still judged on their real last success.
$seen = @{}
foreach ($e in $events) { if ($e.Result -eq 'Success') { $seen["$($e.Key)|$($e.Time.ToString('yyyyMMddHHmm'))"] = $true } }
$fromHistory = foreach ($k in $history.Keys) {
    foreach ($t in $history[$k]) {
        if (-not $seen.ContainsKey("$k|$($t.ToString('yyyyMMddHHmm'))")) {
            [pscustomobject]@{ Key = $k; Id = 1120; Result = 'Success'; Time = $t; Detail = '(from history file)' }
        }
    }
}
$events = @($events) + @($fromHistory)

# How far back the Application log actually reaches - reported when it's too short to see much.
$logStart = $null
try { $logStart = (Get-WinEvent -LogName Application -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated } catch { }
$logNote = ''
if ($logStart -and $logStart -gt $since) {
    $logNote = " The Application event log only reaches back to $($logStart.ToString('yyyy-MM-dd HH:mm')) ($([math]::Round(((Get-Date) - $logStart).TotalHours,1)) h), so older ImageManager activity can't be seen - check the console and consider a larger Application log."
}

$historyAgeH = ((Get-Date) - $firstRun).TotalHours
if ($events.Count -eq 0 -and $logNote -and $historyAgeH -lt $MaxHoursSinceSuccess) {
    # The Application log is too short to show any ImageManager activity, and this device has only
    # just started keeping its own history. Not enough evidence either way, so don't alert yet.
    # Why: Simpler Law SERVER2023 (2026-10-23) - log held ~8 h, console showed consolidation working.
    # If no consolidation has been recorded MaxHoursSinceSuccess after history started, the
    # warning below takes over, so a stuck ImageManager can't hide behind a short log.
    $judgeFrom = $firstRun.AddHours($MaxHoursSinceSuccess).ToString('yyyy-MM-dd HH:mm')
    $script:Ok.Add("ImageManager activity can't be confirmed yet: the Application event log only reaches back to $($logStart.ToString('yyyy-MM-dd HH:mm')). This check is recording ImageManager's own history from $($firstRun.ToString('yyyy-MM-dd HH:mm')) and will alert from $judgeFrom if no consolidation has been seen by then.")
}
elseif ($events.Count -eq 0) {
    # Say when ImageManager last logged anything at all, so "never used" and "went quiet" can
    # be told apart. Wrapped in try: no events at all throws.
    $lastAny = $null
    try { $lastAny = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $providers } -MaxEvents 1 -ErrorAction Stop } catch { }
    $lastTxt = if ($lastAny) { "last ImageManager event of any kind: $($lastAny.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" } else { 'no ImageManager events in the log at all' }
    $script:Warning.Add("ImageManager is installed but logged no folder activity in the last $LookbackDays days ($lastTxt). Either nothing is managed here, or ImageManager has stopped working - check the console.$logNote")
}

# ---------------------------------------------------------------------------
# 3. Judge each folder / target.
# ---------------------------------------------------------------------------
$now = Get-Date
foreach ($g in ($events | Group-Object Key | Sort-Object Name)) {
    $sorted      = @($g.Group | Sort-Object Time -Descending)
    $successes   = @($sorted | Where-Object { $_.Result -eq 'Success' })
    $lastSuccess = $successes | Select-Object -First 1
    $fmt         = 'yyyy-MM-dd HH:mm'

    if (-not $lastSuccess) {
        # Error/warning-only key (e.g. replication target). Recovery = the errors stop.
        $latest  = $sorted[0]
        $ageH    = ($now - $latest.Time).TotalHours
        $day     = @($sorted | Where-Object { $_.Result -eq 'Failed' -and ($now - $_.Time).TotalHours -le 24 })
        $first   = if ($day.Count -gt 0) { $day[-1].Time.ToString($fmt) } else { $latest.Time.ToString($fmt) }
        $summary = "$($day.Count) error(s) in 24h, first $first, latest $($latest.Time.ToString($fmt)) (event $($latest.Id)): $($latest.Detail)"
        if ($ageH -gt $RecentErrorHours) {
            # Summarise the whole lookback (not just 24h) so an old episode doesn't read "0 errors".
            $allErr = @($sorted | Where-Object { $_.Result -eq 'Failed' })
            $was = "$($allErr.Count) error(s) from $($allErr[-1].Time.ToString($fmt)) to $($latest.Time.ToString($fmt)) (event $($latest.Id)): $($latest.Detail)"
            $script:Ok.Add("$($g.Name): no new error for $([math]::Round($ageH,1)) h - treated as recovered. Was: $was")
        } elseif ($day.Count -le 1 -and $ageH -gt $TransientClearHours) {
            $script:Ok.Add("$($g.Name): one-off error at $($latest.Time.ToString($fmt)) not repeated in $([math]::Round($ageH,1)) h - treated as cleared.")
        } elseif ($latest.Result -eq 'Failed' -and $day.Count -ge $MinErrorsForCritical) {
            $script:Critical.Add("$($g.Name): STILL FAILING - $summary")
        } else {
            $script:Warning.Add("$($g.Name): $summary")
        }
        continue
    }

    # Problems logged since the last success = still failing.
    $newer   = @($sorted | Where-Object { $_.Time -gt $lastSuccess.Time })
    $errors  = @($newer | Where-Object { $_.Result -eq 'Failed' })
    $warns   = @($newer | Where-Object { $_.Result -eq 'Warning' })
    $allowed = Get-AllowedHours @($successes | ForEach-Object { $_.Time })
    $stale   = ($now - $lastSuccess.Time).TotalHours -gt $allowed
    $lastTxt = $lastSuccess.Time.ToString($fmt)

    if ($errors.Count -gt 0) {
        $e1  = $errors[0]
        $msg = "$($g.Name): $($errors.Count) error(s) since last success ($lastTxt), latest $($e1.Time.ToString($fmt)) (event $($e1.Id)): $($e1.Detail)"
        $ageH = ($now - $e1.Time).TotalHours
        if ($errors.Count -ge $MinErrorsForCritical -or $stale) { $script:Critical.Add("FAILING - $msg") }
        elseif ($ageH -gt $TransientClearHours) {
            # One error, not repeated since: a blip that ImageManager has recovered from.
            $script:Ok.Add("$($g.Name): one-off error at $($e1.Time.ToString($fmt)) (event $($e1.Id)) not repeated in $([math]::Round($ageH,1)) h - treated as cleared. Last success $lastTxt (alerts after $allowed h).")
        }
        else { $script:Warning.Add("single error, may be transient - $msg") }
    } elseif ($stale) {
        $script:Critical.Add("$($g.Name): no successful ImageManager activity for more than $allowed h. Last success: $lastTxt.")
    } elseif ($warns.Count -gt 0) {
        $w1 = $warns[0]
        $script:Warning.Add("$($g.Name): warning at $($w1.Time.ToString($fmt)) (event $($w1.Id)): $($w1.Detail)")
    } else {
        $script:Ok.Add("$($g.Name): last success $lastTxt (alerts after $allowed h).")
    }
}

foreach ($r in $retired) { $script:Ok.Add("${r}: no longer managed by ImageManager (not in its folder list) - old events ignored.") }

# ---------------------------------------------------------------------------
# 4. Report, problems first.
# ---------------------------------------------------------------------------
foreach ($m in $script:Critical) { Write-Output "CRITICAL: $m" }
foreach ($m in $script:Warning)  { Write-Output "WARNING: $m" }
foreach ($m in $script:Ok)       { Write-Output "OK: $m" }

if ($script:Critical.Count -gt 0) { Stop-Check 2 }
if ($script:Warning.Count  -gt 0) { Stop-Check 1 }
Stop-Check 0
<#
.SYNOPSIS
    TRMM script check: alerts when ShadowProtect (SPX or classic 5.x) backups are failing,
    have warnings, have stopped running, or the ShadowProtect service is not running.

.DESCRIPTION
    Safe to put on every Windows device (server AND workstation policies): if neither
    ShadowProtect SPX nor classic ShadowProtect is installed, it exits 0 and does nothing.
    It only reads services and the Application event log; it never changes anything.

    What it checks
      1. Service      - SPX "SPXService" / classic "ShadowProtectSvc" must be Running.
      2. Last result  - for every backup job seen in the last LookbackDays, the most
                        recent result must not be Failed (critical) or Warning (warning).
      3. Freshness    - every one of those jobs must have a successful backup recently
                        (catches jobs that silently stopped running). "Recently" is learned
                        per job from its own history, so hourly incrementals and weekly fulls
                        on the same server are each judged on their own schedule:
                          allowed gap = the larger of MaxHoursSinceSuccess and
                                        IntervalMultiplier x the job's usual (median) gap
                                        between successful backups.
                        e.g. hourly job -> 26h; weekly full -> 1.5 x 168h = 252h (10.5 days).
                        History survives event log roll-over: each job's recent good runs are
                        kept in HistoryFile on the device. Why: HTSERVER1's Application log is
                        20 MB circular and holds ~12 days, so the previous weekly full rolled
                        out, only one WeeklyFull success remained and the weekly job fell back
                        to the 26h floor (false alert, 2026-10-23).
                        If a job still has only ONE known good run, its interval is at least the
                        quiet time between the start of the event log and that run (it didn't
                        run before it), capped at MaxInferredIntervalHours.
      4. No history   - product installed but no backup events at all in LookbackDays
                        (warning: unused install, or the event log has been cleared).

    Where the data comes from (all seen on real Lincoln IT devices on 2026-10-20)
      SPX     Application log, provider "ShadowProtectSPX":
                Id 3 (Information) "Backup Finished ... Backup "<job>" on <host> successfully finished"
                Id 5 (Error)       "Backup Failed ... Backup "<job>" on <host> failed backing up ..."
              Seen on BIFL2K20 (SPX 6.8.4). A Warning-level SPX event was NOT seen on any device,
              so the event LEVEL (not the Id) decides the result: Error = failed,
              Warning = warning, Information = success. That covers a warning Id we have not seen.
      Classic Application log, provider "ShadowProtectSvc":
                Id 1120 (Information) "Backup status: completed"
                Id 1121 (Error)       "Backup status: failed"
              Seen on PRIME2016 (ShadowProtect 5.2.3). N-able's ShadowProtect check uses the
              same Ids: 1120 = success, 1121 = failure.
              Classic events do not carry a job name, so a "job" is identified by the image
              destination folder plus the volume letter (e.g. "\\NAS\backups\PRIME2016-Continuous [C]").

    Exit codes (same convention as Monitor-ESET.ps1)
      0 = OK, or ShadowProtect not installed
      1 = Warning  (set "Warning return codes" = 1 on the TRMM script check)
      2 = Critical (failed job, stale job, or service stopped)
      3 = Script could not read the event log

    Windows PowerShell 5.1 syntax only.

.SOURCES
    SPX job status meanings (success / warning / failure / missing):
      https://documentation.arcserve.com/Arcserve-ShadowProtect/Available/ENU/SPX_ug/Content/ShadowProtect_SPX_UG/Monitoring-SPX-Backup-Jobs.htm
    Classic ShadowProtect event Ids 1120 / 1121:
      https://documentation.n-able.com/remote-management/userguide/Content/shadowprotect.htm
    Time-since-last-success as an SPX health metric:
      https://documentation.n-able.com/N-central/userguide/Content/Services/Backup/Services_ShadowProtect_SPX.htm
#>
[CmdletBinding()]
param(
    # Minimum allowed gap since a job's last success, in hours. 26 = daily schedule + 2 hours
    # slack. Jobs whose own history shows a longer normal interval get more (see IntervalMultiplier).
    # Raise it on the check (script arguments) for laptops that are often switched off.
    [int]$MaxHoursSinceSuccess = 26,

    # How many times its usual interval a job may go without a success before alerting.
    [double]$IntervalMultiplier = 1.5,

    # How far back to look for jobs. 21 days means a weekly job has at least two successes
    # to learn its interval from. A job that has logged nothing for this long is treated as
    # deleted and ignored, so old/removed jobs don't alert forever.
    [int]$LookbackDays = 21,

    # Job names (SPX) or destination keys (classic) to ignore. Wildcards allowed, e.g. 'Test*'.
    [string[]]$ExcludeJob = @(),

    # Per-device record of each job's recent good runs (see "Freshness" above). SYSTEM can write
    # to ProgramData. If it can't be read or written the check still runs on the event log alone.
    [string]$HistoryFile = (Join-Path $env:ProgramData 'LincolnIT\BackupMonitoring\shadowprotect-history.json'),

    # Cap for the one-good-run fallback: never infer an interval longer than this (7 days), so a
    # newly created job on a server with months of log can't make the check endlessly tolerant.
    [double]$MaxInferredIntervalHours = 168,

    # SPX warning texts to ignore (wildcards). A Warning event whose warnings ALL match is
    # treated as a plain success. Default ignores "The backup images from this job may be
    # unmanaged..." (Ethan, 2026-10-20: not wanted as an alert).
    [string[]]$IgnoreWarning = @('*may be unmanaged*'),

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
    if ($skip -contains 'All' -or $skip -contains 'ShadowProtect') {
        Write-Output "OK: ShadowProtect check skipped on this device (Backup Monitoring Skip = '$SkipChecks')."
        Stop-Check 0
    }
}

# ---------------------------------------------------------------------------
# Results are collected here and the worst one sets the exit code at the end.
# ---------------------------------------------------------------------------
$script:Critical = New-Object System.Collections.Generic.List[string]
$script:Warning  = New-Object System.Collections.Generic.List[string]
$script:Ok       = New-Object System.Collections.Generic.List[string]

function Test-Excluded([string]$Name) {
    # True if the job matches any -ExcludeJob pattern.
    foreach ($p in $ExcludeJob) { if ($Name -like $p) { return $true } }
    return $false
}

function Get-AllowedHours([datetime[]]$SuccessTimes, [double]$InferredIntervalHours = 0) {
    # Works out how long this job may go without a success.
    # Median (not average or max) gap, so one outage in the history doesn't make the check
    # more tolerant. With fewer than 2 successes there is no gap to learn from, so the
    # MaxHoursSinceSuccess floor is used.
    $allowed = [double]$MaxHoursSinceSuccess
    $t = @($SuccessTimes | Sort-Object)
    if ($t.Count -ge 2) {
        $gaps = @(for ($i = 1; $i -lt $t.Count; $i++) { ($t[$i] - $t[$i - 1]).TotalHours }) | Sort-Object
        $median = $gaps[[int][math]::Floor(($gaps.Count - 1) / 2)]
        $allowed = [math]::Max($allowed, $median * $IntervalMultiplier)
    } elseif ($InferredIntervalHours -gt 0) {
        # Only one good run known: use the inferred minimum interval instead (capped).
        $allowed = [math]::Max($allowed, [math]::Min($InferredIntervalHours, $MaxInferredIntervalHours) * $IntervalMultiplier)
    }
    return [math]::Round($allowed, 1)
}

function Get-ResultFromLevel([int]$Level) {
    # Windows event levels: 1 Critical, 2 Error, 3 Warning, 4 Information (0 = LogAlways, treat as info).
    switch ($Level) {
        1 { 'Failed' }
        2 { 'Failed' }
        3 { 'Warning' }
        default { 'Success' }
    }
}

# ---------------------------------------------------------------------------
# 1. Detect which ShadowProtect flavour is installed (by its service).
#    Not installed = nothing to monitor, so pass quietly.
# ---------------------------------------------------------------------------
$spxSvc     = Get-Service -Name 'SPXService'       -ErrorAction SilentlyContinue
$classicSvc = Get-Service -Name 'ShadowProtectSvc' -ErrorAction SilentlyContinue

if (-not $spxSvc -and -not $classicSvc) {
    Write-Output 'OK: ShadowProtect is not installed on this device - nothing to check.'
    Stop-Check 0
}

foreach ($svc in @($spxSvc, $classicSvc)) {
    if (-not $svc) { continue }
    if ($svc.Status -ne 'Running') {
        # A stopped service means no scheduled backups will run at all.
        $script:Critical.Add("Service '$($svc.DisplayName)' ($($svc.Name)) is $($svc.Status).")
    } else {
        $script:Ok.Add("Service '$($svc.DisplayName)' is Running.")
    }
}

# ---------------------------------------------------------------------------
# 2. Read backup events and turn each one into (Job, Result, Time, Reason).
# ---------------------------------------------------------------------------
$since  = (Get-Date).AddDays(-$LookbackDays)
$events = New-Object System.Collections.Generic.List[object]

function Read-Events([string]$Provider) {
    # FilterHashtable makes the event log do the filtering, which is much faster than
    # piping the whole Application log through Where-Object.
    # "No events found" is thrown as an error by Get-WinEvent; that is not a failure here.
    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $Provider; StartTime = $since } -ErrorAction Stop)
    } catch {
        # Also tolerate the provider not being registered (e.g. a half-removed install).
        if ($_.Exception.Message -match 'No events were found|not an event provider') { return @() }
        throw
    }
}

try {
    if ($spxSvc) {
        foreach ($e in (Read-Events 'ShadowProtectSPX')) {
            # Only "Backup ..." events carry a job; skip e.g. Id 1 "service started".
            if ($e.Message -notmatch 'Backup "([^"]+)" on ') { continue }
            $job = $Matches[1]
            $reason = ''
            $lines = $e.Message -split "`r?`n"
            $result = Get-ResultFromLevel $e.Level
            if ($e.Level -eq 3) {
                # Warning events list their warnings as bullets under a "Warnings" heading, e.g.
                # " * The backup images from this job may be unmanaged ..." (seen on DESKTOP-476I4LG).
                $bullets = @($lines | Where-Object { $_ -match '^\s*\*\s+\S' } | ForEach-Object { ($_ -replace '^\s*\*\s+', '').Trim() })
                # Drop warnings on the ignore list; if none are left this run is a plain success.
                $kept = @($bullets | Where-Object { $b = $_; -not ($IgnoreWarning | Where-Object { $b -like $_ }) })
                if ($bullets.Count -gt 0 -and $kept.Count -eq 0) { $result = 'Success' }
                elseif ($kept.Count -gt 0) { $reason = $kept -join ' | ' }
            } elseif ($e.Level -le 2) {
                # Failed events put the reason on the first indented line after the summary,
                # e.g. "    The backup destination is not accessible." (seen on BIFL2K20).
                $hit = $lines | Where-Object { $_ -match '^\s{2,}\S' } | Select-Object -First 1
                if ($hit) { $reason = $hit.Trim() }
            }
            $events.Add([pscustomobject]@{ Job = "SPX: $job"; Result = $result; Time = $e.TimeCreated; Reason = $reason })
        }
    }

    if ($classicSvc) {
        foreach ($e in (Read-Events 'ShadowProtectSvc')) {
            if ($e.Id -ne 1120 -and $e.Id -ne 1121) { continue }
            # "Image file: \\NAS\backups\PRIME2016-Continuous\C_VOL-b002-i41151.spi" (success)
            # "Image file: \\NAS\backups\PRIME2016-Continuous\C_VOL"                  (failure)
            # Key = destination folder + volume letter, so success and failure line up.
            $job = 'unknown destination'
            if ($e.Message -match 'Image file:\s*(.+?)\\([A-Za-z])_VOL') { $job = "$($Matches[1]) [$($Matches[2].ToUpper())]" }
            elseif ($e.Message -match 'Image file:\s*(.+)') { $job = $Matches[1].Trim() }
            $reason = ''
            if ($e.Message -match 'Message:\s*(.+)') { $reason = $Matches[1].Trim() }
            $result = if ($e.Id -eq 1121) { 'Failed' } else { Get-ResultFromLevel $e.Level }
            $events.Add([pscustomobject]@{ Job = "Classic: $job"; Result = $result; Time = $e.TimeCreated; Reason = $reason })
        }
    }
} catch {
    Write-Output "UNKNOWN: could not read the Application event log: $($_.Exception.Message)"
    Stop-Check 3
}

# ---------------------------------------------------------------------------
# 3. Judge each job on its newest event and its newest success.
# ---------------------------------------------------------------------------
# Good runs (Success or Warning) count towards freshness. A Warning still produced a backup
# image (Arcserve: "SPX performed the backup but may have logged error messages"); the warning
# itself is reported separately below.
$events = @($events | Where-Object { -not (Test-Excluded ($_.Job -replace '^(SPX|Classic): ', '')) })

# 3a. Load the per-device history and merge in good runs from the event log.
#     Stored as { "SPX: WeeklyFull": ["2026-10-18T05:08:00.0000000Z", ...] } in UTC.
$history = @{}
try {
    if (Test-Path -LiteralPath $HistoryFile) {
        $raw = Get-Content -LiteralPath $HistoryFile -Raw | ConvertFrom-Json
        foreach ($p in $raw.PSObject.Properties) {
            # Windows PowerShell 5.1 returns these as strings; newer versions may already give DateTime.
            $history[$p.Name] = @($p.Value | ForEach-Object { if ($_ -is [datetime]) { $_.ToLocalTime() } else { ([datetime]::Parse($_, $null, [Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime() } })
        }
    }
} catch { $history = @{} }   # unreadable/corrupt history: rebuild from the event log

foreach ($e in $events) {
    if ($e.Result -eq 'Failed') { continue }
    if (-not $history.ContainsKey($e.Job)) { $history[$e.Job] = @() }
    $history[$e.Job] = @($history[$e.Job]) + $e.Time
}
# Tidy: de-duplicate to the minute, drop anything older than 90 days, keep the newest 20 per job.
$keepFrom = (Get-Date).AddDays(-90)
foreach ($k in @($history.Keys)) {
    $history[$k] = @($history[$k] | Where-Object { $_ -gt $keepFrom } |
        Sort-Object -Unique { $_.ToString('yyyyMMddHHmm') } | Sort-Object -Descending | Select-Object -First 20)
    if ($history[$k].Count -eq 0) { $history.Remove($k) }
}
try {
    $dirOut = Split-Path -Parent $HistoryFile
    if (-not (Test-Path -LiteralPath $dirOut)) { New-Item -ItemType Directory -Path $dirOut -Force | Out-Null }
    $outObj = [ordered]@{}
    foreach ($k in ($history.Keys | Sort-Object)) { $outObj[$k] = @($history[$k] | ForEach-Object { $_.ToUniversalTime().ToString('o') }) }
    ($outObj | ConvertTo-Json -Depth 3) | Set-Content -LiteralPath $HistoryFile -Encoding UTF8
} catch { }   # not fatal: the check still works from the event log

# Start of the event log, for the one-good-run fallback.
$logStart = $null
try { $logStart = (Get-WinEvent -LogName Application -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated } catch { }

# 3b. Jobs to judge: anything in the event log window, plus jobs whose last good run is in the
#     history and within LookbackDays (so a weekly job whose event rolled out of the log is still
#     watched). Jobs not seen for LookbackDays are treated as deleted.
$lookFrom = (Get-Date).AddDays(-$LookbackDays)
$jobNames = @(@($events | ForEach-Object { $_.Job }) +
              @($history.Keys | Where-Object { -not (Test-Excluded ($_ -replace '^(SPX|Classic): ', '')) -and ($history[$_][0] -gt $lookFrom) }) |
              Sort-Object -Unique)

if ($jobNames.Count -eq 0) {
    # Installed but nothing has backed up for LookbackDays: either never configured,
    # or every job stopped long ago. Worth a look, not necessarily an emergency.
    $script:Warning.Add("ShadowProtect is installed but logged no backup events in the last $LookbackDays days.")
}

$fmt = 'yyyy-MM-dd HH:mm'
foreach ($name in $jobNames) {
    $jobEvents = @($events | Where-Object { $_.Job -eq $name } | Sort-Object Time -Descending)
    $good      = @(if ($history.ContainsKey($name)) { $history[$name] })   # newest first, includes this run's events
    $lastGood  = if ($good.Count -gt 0) { $good[0] } else { $null }
    # Latest result: newest event if the log still has one, otherwise the newest remembered good run.
    $latest    = if ($jobEvents.Count -gt 0) { $jobEvents[0] } else { [pscustomobject]@{ Result = 'Success'; Time = $lastGood; Reason = '' } }

    # One-good-run fallback: the job did not run between the start of the log and its only good run.
    $inferred = 0
    if ($good.Count -eq 1 -and $logStart -and $lastGood -gt $logStart) { $inferred = ($lastGood - $logStart).TotalHours }

    $allowedH = Get-AllowedHours $good $inferred
    $cutoff   = (Get-Date).AddHours(-$allowedH)
    $lastText = if ($lastGood) { $lastGood.ToString($fmt) } else { "none in $LookbackDays days" }

    if ($latest.Result -eq 'Failed') {
        $why = if ($latest.Reason) { " Reason: $($latest.Reason)" } else { '' }
        $script:Critical.Add("${name}: last backup FAILED at $($latest.Time.ToString($fmt)). Last good backup: $lastText.$why")
    } elseif (-not $lastGood -or $lastGood -lt $cutoff) {
        # Latest is not a failure, but nothing has succeeded recently (schedule stopped).
        $script:Critical.Add("${name}: no successful backup in the last $allowedH hours. Last good backup: $lastText.")
    } elseif ($latest.Result -eq 'Warning') {
        $why = if ($latest.Reason) { " Warning: $($latest.Reason)" } else { '' }
        $script:Warning.Add("${name}: last backup finished with WARNINGS at $($latest.Time.ToString($fmt)).$why")
    } else {
        $basis = if ($good.Count -ge 2) { "$($good.Count) known runs" } elseif ($inferred -gt 0) { 'one known run, interval inferred from log start' } else { 'one known run' }
        $script:Ok.Add("${name}: last good backup $lastText (alerts after $allowedH h; $basis).")
    }
}

# ---------------------------------------------------------------------------
# 4. Report. Problems first so the TRMM alert/ticket text starts with what failed.
# ---------------------------------------------------------------------------
foreach ($m in $script:Critical) { Write-Output "CRITICAL: $m" }
foreach ($m in $script:Warning)  { Write-Output "WARNING: $m" }
foreach ($m in $script:Ok)       { Write-Output "OK: $m" }

if ($script:Critical.Count -gt 0) { Stop-Check 2 }
if ($script:Warning.Count  -gt 0) { Stop-Check 1 }
Stop-Check 0
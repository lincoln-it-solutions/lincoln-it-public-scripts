<#
.SYNOPSIS
    TRMM script check: alerts when Veeam Backup & Replication jobs, or a standalone
    Veeam Agent for Microsoft Windows, are failing, warning, have stopped running, or the
    core Veeam service is not running.

.DESCRIPTION
    Safe to put on every Windows device: if neither Veeam B&R nor Veeam Agent for Windows is
    installed it exits 0. It only reads services and event logs; it never changes anything.

    Covers Veeam Agent for LINUX too, indirectly: Linux agents managed by B&R (e.g. the stack
    VMs backed up by Steve-Win11) report each run to the B&R server as event 790, so their
    jobs are checked here on the B&R server.

    What it checks
      1. Service     - B&R "VeeamBackupSvc" and/or Agent "VeeamEndpointBackupSvc" must be Running.
                       Only these core services are checked: other Veeam services can be stopped
                       normally (VeeamDistributionSvc is Stopped/Automatic on Steve-Win11).
      2. Last result - for each job seen in the last LookbackDays, the newest run must not be
                       Failed (critical) or Warning (warning).
      3. Freshness   - each job must have a Success/Warning run recently: the larger of
                       MaxHoursSinceSuccess and IntervalMultiplier x the job's median gap,
                       so daily and weekly jobs are each judged on their own schedule.
      4. No history  - product installed but no job results at all in LookbackDays (warning).

    Where the data comes from
      B&R    "Veeam Backup" event log. Job-finished event Ids (Veeam event reference):
               190 Backup Job Finished        151 File Backup Job Finished
               490 Backup Copy Job Finished   451 File Backup Copy Job Finished
               790 Agent Backup Job Finished
             Message format: "<type> job '<JobName>' finished with <State>." Event parameters
             include JobResult (0 success, 1 warning, 2 failed) and JobName; on Steve-Win11
             (B&R 13.1.1.18) these are EventData items 3 and 7, matching Veeam's parameter order.
             Task-level events (e.g. 150 "Backup Task Finished") are deliberately ignored so one
             VM inside a job isn't double-counted.
      Agent  "Veeam Agent" event log, Id 190 "Veeam Agent <jobname> finished with <status>",
             severity Information / Warning / Error. Id 191 (failed, will be retried) is ignored:
             the retry's own 190 is the result that counts.
             NOTE: no standalone Veeam Agent for Windows exists on a TRMM device yet, so this
             part is written from Veeam's documentation and has not been run against a real agent.

    Exit codes (same convention as Monitor-ESET.ps1)
      0 = OK, or Veeam not installed
      1 = Warning  (set "Warning return codes" = 1 on the TRMM script check)
      2 = Critical
      3 = Script could not read the event log

    Windows PowerShell 5.1 syntax only.

.SOURCES
    B&R event Id list:   https://helpcenter.veeam.com/docs/vbr/events/event_id_list.html
    B&R event 190:       https://helpcenter.veeam.com/docs/vbr/events/event_190.html
    B&R event 790:       https://helpcenter.veeam.com/docs/vbr/events/event_790.html
    Agent events:        https://helpcenter.veeam.com/docs/agentforwindows/userguide/appendix_events.html
    Agent service name:  https://community.veeam.com/discussion-boards-66/failed-to-start-service-veeamendpointbackupsvc-9614
#>
[CmdletBinding()]
param(
    # Minimum allowed hours since a job's last good run (daily schedule + 2h slack).
    [int]$MaxHoursSinceSuccess = 26,

    # How many times its usual interval a job may go without a good run.
    [double]$IntervalMultiplier = 1.5,

    # Jobs not seen for this long are treated as deleted/disabled and ignored. 21 days gives
    # weekly jobs at least two runs to learn their interval from.
    [int]$LookbackDays = 21,

    # B&R job-finished event Ids to read (see header).
    [int[]]$VbrEventIds = @(190, 151, 490, 451, 790),

    # Job names to ignore. Wildcards allowed, e.g. 'Test*'.
    [string[]]$ExcludeJob = @(),

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
    if ($skip -contains 'All' -or $skip -contains 'Veeam') {
        Write-Output "OK: Veeam check skipped on this device (Backup Monitoring Skip = '$SkipChecks')."
        Stop-Check 0
    }
}

$script:Critical = New-Object System.Collections.Generic.List[string]
$script:Warning  = New-Object System.Collections.Generic.List[string]
$script:Ok       = New-Object System.Collections.Generic.List[string]

function Test-Excluded([string]$Name) {
    foreach ($p in $ExcludeJob) { if ($Name -like $p) { return $true } }
    return $false
}

function Get-AllowedHours([datetime[]]$SuccessTimes) {
    # Median gap between good runs x multiplier, never below MaxHoursSinceSuccess.
    $allowed = [double]$MaxHoursSinceSuccess
    $t = @($SuccessTimes | Sort-Object)
    if ($t.Count -ge 2) {
        $gaps = @(for ($i = 1; $i -lt $t.Count; $i++) { ($t[$i] - $t[$i - 1]).TotalHours }) | Sort-Object
        $median = $gaps[[int][math]::Floor(($gaps.Count - 1) / 2)]
        $allowed = [math]::Max($allowed, $median * $IntervalMultiplier)
    }
    return [math]::Round($allowed, 1)
}

function Convert-State([string]$State, [int]$Level) {
    # Prefer the state word Veeam writes ("Success", "Warning", "Failed"); fall back to level.
    switch -Regex ($State) {
        '^Success' { return 'Success' }
        '^Warn'    { return 'Warning' }
        '^(Fail|Error)' { return 'Failed' }
    }
    switch ($Level) { 1 { 'Failed' } 2 { 'Failed' } 3 { 'Warning' } default { 'Success' } }
}

function Read-Log([string]$LogName, [int[]]$Ids, [datetime]$Since) {
    # Returns @() when the log has no matching events instead of throwing.
    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Ids; StartTime = $Since } -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -match 'No events were found|There is not an event log') { return @() }
        throw
    }
}

# ---------------------------------------------------------------------------
# 1. Detect what is installed, by service (and by event log for the agent).
# ---------------------------------------------------------------------------
$vbrSvc   = Get-Service -Name 'VeeamBackupSvc'         -ErrorAction SilentlyContinue
$agentSvc = Get-Service -Name 'VeeamEndpointBackupSvc' -ErrorAction SilentlyContinue
$agentLog = Get-WinEvent -ListLog 'Veeam Agent' -ErrorAction SilentlyContinue

if (-not $vbrSvc -and -not $agentSvc -and -not $agentLog) {
    Write-Output 'OK: Veeam Backup & Replication / Veeam Agent for Windows is not installed - nothing to check.'
    Stop-Check 0
}

foreach ($svc in @($vbrSvc, $agentSvc)) {
    if (-not $svc) { continue }
    if ($svc.Status -ne 'Running') {
        $script:Critical.Add("Service '$($svc.DisplayName)' ($($svc.Name)) is $($svc.Status) - scheduled jobs will not run.")
    } else {
        $script:Ok.Add("Service '$($svc.DisplayName)' is Running.")
    }
}

# ---------------------------------------------------------------------------
# 2. Read job results as (Job, Result, Time, Detail).
# ---------------------------------------------------------------------------
$since = (Get-Date).AddDays(-$LookbackDays)
$runs  = New-Object System.Collections.Generic.List[object]

try {
    if ($vbrSvc) {
        foreach ($e in (Read-Log 'Veeam Backup' $VbrEventIds $since)) {
            $job = $null; $state = ''
            # Structured parameters first: item 3 = JobResult (0/1/2), item 7 = JobName.
            $p = $e.Properties
            if ($p.Count -ge 7 -and "$($p[2].Value)" -match '^[012]$' -and "$($p[6].Value)" -ne '') {
                $job   = "$($p[6].Value)"
                $state = @('Success', 'Warning', 'Failed')[[int]"$($p[2].Value)"]
            }
            # Fall back to the message text: "... job 'NAME' finished with STATE."
            if (-not $job -and $e.Message -match "job '(.+?)' (?:has )?finished with (\w+)") {
                $job = $Matches[1]; $state = $Matches[2]
            }
            if (-not $job) { continue }
            $lines  = @($e.Message -split "`r?`n" | Where-Object { $_.Trim() -ne '' })
            $detail = if ($lines.Count -gt 1) { ($lines[1..($lines.Count - 1)] -join ' ').Trim() } else { '' }
            $runs.Add([pscustomobject]@{ Job = "B&R: $job"; Name = $job; Result = (Convert-State $state $e.Level); Time = $e.TimeCreated; Detail = $detail })
        }
    }

    if ($agentLog) {
        foreach ($e in (Read-Log 'Veeam Agent' @(190) $since)) {
            $job = 'Veeam Agent job'; $state = ''
            # "Veeam Agent <jobname> finished with <status>." - job name may or may not be quoted.
            if ($e.Message -match "Veeam Agent\s+'?(.+?)'?\s+finished with (\w+)") { $job = $Matches[1]; $state = $Matches[2] }
            $detail = ''
            if ($e.Message -match 'Job details:\s*(.+)') { $detail = $Matches[1].Trim() }
            $runs.Add([pscustomobject]@{ Job = "Agent: $job"; Name = $job; Result = (Convert-State $state $e.Level); Time = $e.TimeCreated; Detail = $detail })
        }
    }
} catch {
    Write-Output "UNKNOWN: could not read the Veeam event logs: $($_.Exception.Message)"
    Stop-Check 3
}

# ---------------------------------------------------------------------------
# 3. Judge each job on its newest run and its newest good run.
# ---------------------------------------------------------------------------
$jobs = @($runs | Where-Object { -not (Test-Excluded $_.Name) } | Group-Object Job | Sort-Object Name)
if ($jobs.Count -eq 0) {
    $script:Warning.Add("Veeam is installed but logged no job results in the last $LookbackDays days.")
}

$fmt = 'yyyy-MM-dd HH:mm'
foreach ($g in $jobs) {
    $sorted  = @($g.Group | Sort-Object Time -Descending)
    $latest  = $sorted[0]
    # Warning runs still produced a restore point, so they count towards freshness.
    $good    = @($sorted | Where-Object { $_.Result -ne 'Failed' })
    $lastOk  = $good | Select-Object -First 1
    $allowed = Get-AllowedHours @($good | ForEach-Object { $_.Time })
    $lastTxt = if ($lastOk) { $lastOk.Time.ToString($fmt) } else { "none in $LookbackDays days" }
    $stale   = (-not $lastOk) -or (((Get-Date) - $lastOk.Time).TotalHours -gt $allowed)
    $why     = if ($latest.Detail) { " Details: $($latest.Detail)" } else { '' }

    if ($latest.Result -eq 'Failed') {
        $script:Critical.Add("$($g.Name): last run FAILED at $($latest.Time.ToString($fmt)). Last good run: $lastTxt.$why")
    } elseif ($stale) {
        $script:Critical.Add("$($g.Name): no good run for more than $allowed h. Last good run: $lastTxt.")
    } elseif ($latest.Result -eq 'Warning') {
        $script:Warning.Add("$($g.Name): last run finished with WARNING at $($latest.Time.ToString($fmt)).$why")
    } else {
        $script:Ok.Add("$($g.Name): last good run $lastTxt (alerts after $allowed h).")
    }
}

# ---------------------------------------------------------------------------
# 4. Report, problems first.
# ---------------------------------------------------------------------------
foreach ($m in $script:Critical) { Write-Output "CRITICAL: $m" }
foreach ($m in $script:Warning)  { Write-Output "WARNING: $m" }
foreach ($m in $script:Ok)       { Write-Output "OK: $m" }

if ($script:Critical.Count -gt 0) { Stop-Check 2 }
if ($script:Warning.Count  -gt 0) { Stop-Check 1 }
Stop-Check 0
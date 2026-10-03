<#
.SYNOPSIS
    Monitors ESET Endpoint Security / Endpoint Antivirus / Server Security for
    conditions that need actioning, using ESET's own ermm.exe command-line tool.

.DESCRIPTION
    Checks performed (each one maps to a documented ermm.exe command):
      1. ermm.exe is present            -> ESET missing/removed
      2. get protection-status          -> any non-green product status
                                           (not activated, network isolated,
                                           modules disabled, etc.)
      3. get license-info               -> licence expired / expiring soon
      4. get activation-status          -> last activation attempt failed
      5. get logs --name virlog         -> detections in the last N hours,
                                           flagged critical if they look unhandled

    Exit codes (so an RMM script check can alert on them):
      0 = OK
      1 = Warning  (needs a look, not urgent)
      2 = Critical (action required)
      3 = Script could not query ESET (e.g. RMM interface disabled)

.PREREQUISITE
    ESET RMM is DISABLED by default. Enable it (ideally via an ESET PROTECT policy):
    Advanced setup > Tools > ESET RMM > Enable RMM, Working mode "Safe operations only".
    Source: https://help.eset.com/eea/12/en-US/how_activate_rmm.html

.SOURCES
    Command list:     https://help.eset.com/eea/12/en-US/rmm_json_commands.html
    protection-status https://help.eset.com/eea/12/en-US/rmm_json_get_protection.html
    license-info      https://help.eset.com/eea/12/en-US/rmm_json_commands_license.html
    activation-status https://help.eset.com/eea/12/en-US/rmm_json_commands_activation_status.html
    get logs          https://help.eset.com/eea/12/en-US/rmm_json_commands_logs.html
    Server Security   https://help.eset.com/efsw/12.0/en-US/idh_config_ermm.html
    Isolation status  https://help.eset.com/efsw/12.0/en-US/network_isolation.html
#>

param(
    # How far back to look in the detection (virlog) log.
    # Match this to how often the check runs, plus some overlap.
    [int]$DetectionLookbackHours = 24,

    # Warn this many days before the licence expiry date.
    [int]$LicenceWarnDays = 30,

    # Default behaviour: if ESET is not installed at all, PASS (exit 0) so the
    # check can be applied globally to every agent.
    # Add -RequireEset as a script argument on clients/policies where ESET
    # MUST be present, and a missing install becomes CRITICAL instead.
    [switch]$RequireEset
)

# ---------------------------------------------------------------------------
# Result collectors. Every finding is added to one of these lists so the
# script can print a single readable summary and pick one exit code at the end.
# ---------------------------------------------------------------------------
$Critical = New-Object System.Collections.Generic.List[string]
$Warning  = New-Object System.Collections.Generic.List[string]
$Info     = New-Object System.Collections.Generic.List[string]

# ---------------------------------------------------------------------------
# 1. Locate ermm.exe
# Paths are the documented defaults:
#   Endpoint products -> C:\Program Files\ESET\ESET Security
#   Server Security   -> C:\Program Files\ESET\ESET Server Security
#   Older File Security (6.x) -> C:\Program Files\ESET\ESET File Security
# We check all three so one script covers workstations and servers.
#
# Three outcomes:
#   a) ermm.exe found                        -> carry on with the checks
#   b) a product folder exists, no ermm.exe  -> ESET is there but damaged
#                                               -> CRITICAL, always (a partly
#                                               removed AV is exactly what we
#                                               want to hear about)
#   c) no product folder at all              -> ESET not installed
#                                               -> PASS by default so the
#                                               check can be applied globally,
#                                               or CRITICAL with -RequireEset
# ---------------------------------------------------------------------------
$ProductFolders = @(
    "$env:ProgramFiles\ESET\ESET Security",
    "$env:ProgramFiles\ESET\ESET Server Security",
    "$env:ProgramFiles\ESET\ESET File Security"
)

# Build the ermm.exe path for each product folder.
$CandidatePaths = $ProductFolders | ForEach-Object { Join-Path $_ 'ermm.exe' }
$Ermm = $CandidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $Ermm) {
    # Which product folders (if any) exist on this machine?
    $FoundFolders = @($ProductFolders | Where-Object { Test-Path $_ })

    if ($FoundFolders.Count -gt 0) {
        # Case b: product folder present but ermm.exe missing.
        Write-Output "CRITICAL: ESET product folder found but ermm.exe is missing - installation damaged or partly removed."
        Write-Output "Found: $($FoundFolders -join '; ')"
        exit 2
    }

    # Case c: no ESET product installed.
    if ($RequireEset) {
        Write-Output "CRITICAL: ESET is not installed on $env:COMPUTERNAME (this check was run with -RequireEset)."
        Write-Output "Checked: $($ProductFolders -join '; ')"
        exit 2
    }

    Write-Output "OK: ESET not installed on $env:COMPUTERNAME - nothing to monitor."
    exit 0
}
$Info.Add("ermm.exe found at: $Ermm")

# ---------------------------------------------------------------------------
# Helper: run an ermm.exe command and return the parsed JSON 'result' object.
# ermm.exe prints JSON of the form {"id":..,"result":{...},"error":..}
# (see the example outputs on the ESET pages listed above).
# Returns $null if the call fails, so the caller can report it.
# ---------------------------------------------------------------------------
function Invoke-Ermm {
    param([string[]]$Arguments)

    try {
        # Join output lines into one string because ConvertFrom-Json in
        # Windows PowerShell 5.1 needs the whole document, not line by line.
        $raw = (& $Ermm @Arguments 2>&1 | Out-String).Trim()
        if (-not $raw) { return $null }

        $json = $raw | ConvertFrom-Json -ErrorAction Stop

        # ESET returns a non-null 'error' field when the command is refused
        # (for example RMM disabled, or not allowed in the chosen working mode).
        if ($json.error) {
            $script:Warning.Add("ermm $($Arguments -join ' ') returned error: $($json.error | ConvertTo-Json -Compress)")
            return $null
        }
        return $json.result
    }
    catch {
        # Non-JSON output usually means the RMM interface is disabled or the
        # caller is not in the allowed application paths.
        $script:Warning.Add("ermm $($Arguments -join ' ') failed or gave non-JSON output: $raw")
        return $null
    }
}

# ---------------------------------------------------------------------------
# 2. Protection status
# ESET's example shows: statuses[] with id/status/priority/description, and
# an overall 'status'. In that example status 2 = "Security alert" (red),
# e.g. id "EkrnNotActivated" / "Product not activated".
# ESET does not publish the full list of status IDs or values, so rather than
# guessing IDs we treat ANY non-zero status as a finding and report the ID and
# description exactly as ESET gives them. This catches isolation ("Network
# access blocked" turns the product status red, per the isolation doc),
# not activated, expired licence, disabled modules, and anything new ESET adds.
# ---------------------------------------------------------------------------
$prot = Invoke-Ermm @('get', 'protection-status')

if ($null -eq $prot) {
    # If we cannot even read protection status, the monitor is blind.
    Write-Output "UNKNOWN: Could not query ESET protection status."
    Write-Output "Most likely cause: ESET RMM is disabled (it is off by default) or the"
    Write-Output "authorization method blocks this caller. See script header."
    $Warning | ForEach-Object { Write-Output "  $_" }
    exit 3
}

foreach ($s in $prot.statuses) {
    $line = "[$($s.id)] $($s.description) (status=$($s.status), priority=$($s.priority))"

    # Status 2 is documented (by example) as a red security alert -> critical.
    # Status 1 is not documented; we treat it as a warning so it is not missed.
    if ($s.status -ge 2)     { $Critical.Add("Protection status: $line") }
    elseif ($s.status -eq 1) { $Warning.Add("Protection status: $line") }

    # Extra explicit tag for isolation so it stands out in the ticket.
    # Text match is used because ESET documents the message, not the status ID.
    if ($s.description -match 'Network access blocked|isolat') {
        $Critical.Add("MACHINE IS NETWORK ISOLATED by ESET - investigate before releasing.")
    }
}
$Info.Add("Overall ESET status: $($prot.status) - $($prot.description)")

# ---------------------------------------------------------------------------
# 3. Licence info
# ESET's example returns expiration_date (YYYY-MM-DD) and expiration_state ("ok").
# Only "ok" is shown in the docs, so anything other than "ok" is treated as critical.
# We also calculate days remaining ourselves to give early warning.
# ---------------------------------------------------------------------------
$lic = Invoke-Ermm @('get', 'license-info')
if ($lic) {
    if ($lic.expiration_state -and $lic.expiration_state -ne 'ok') {
        $Critical.Add("Licence state is '$($lic.expiration_state)' (expires $($lic.expiration_date)).")
    }

    if ($lic.expiration_date) {
        try {
            $exp  = [datetime]::ParseExact($lic.expiration_date, 'yyyy-MM-dd', $null)
            $days = [int]($exp - (Get-Date).Date).TotalDays
            if ($days -lt 0) {
                $Critical.Add("Licence EXPIRED $([math]::Abs($days)) day(s) ago ($($lic.expiration_date)).")
            }
            elseif ($days -le $LicenceWarnDays) {
                $Warning.Add("Licence expires in $days day(s) ($($lic.expiration_date)).")
            }
            $Info.Add("Licence: type=$($lic.type) seat=$($lic.seat_name) expires=$($lic.expiration_date)")
        }
        catch {
            # Date not in the documented format - report rather than guess.
            $Warning.Add("Could not parse licence expiry date '$($lic.expiration_date)'.")
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Activation status
# Documented values: success, running, failure. Output field name is not shown
# in the docs, so we search every property of the result for 'failure'.
#
# AUTO-REMEDIATION: this command reports the LAST activation attempt, not the
# current state. A failed attempt followed by a successful re-activation
# (e.g. ESET PROTECT re-pushing the licence) would still say 'failure'.
# So we only raise it as critical if protection-status (the CURRENT state,
# checked above) still shows an activation problem. Otherwise it is logged as
# info so there is a record, but it does not fail the check.
# ---------------------------------------------------------------------------
$act = Invoke-Ermm @('get', 'activation-status')
if ($act) {
    $actText = $act | ConvertTo-Json -Compress
    if ($actText -match 'failure') {

        # Does the live protection status still show an activation issue?
        # Matched on ID or description because ESET does not publish the full
        # status ID list; 'EkrnNotActivated' is the one documented example.
        $activationIssueNow = $prot.statuses | Where-Object {
            $_.id -match 'Activat' -or $_.description -match 'not activated'
        }

        if ($activationIssueNow) {
            $Critical.Add("Last ESET activation attempt FAILED and product is still not activated: $actText")
        }
        else {
            $Info.Add("Earlier activation attempt failed but product currently reports activated (self-recovered): $actText")
        }
    }
}

# ---------------------------------------------------------------------------
# 5. Detections (virlog) in the lookback window
#
# EVIDENCE (live testing, 23 Sep 2026):
#   - STEVE-WIN11: 'get logs --name virlog' with a date range that CONTAINS
#     detections (2026-09-01 to 2026-09-02) returned them correctly, so
#     ESET's date filtering works.
#   - STEVE-WIN11: every date range with NO matching entries (2017 dates,
#     22-23 Sep 2026) returned error id 3 "General error executing command".
#   - W2019114: 'get logs --name warnlog' (no dates) worked, but
#     'get logs --name virlog' (no dates) returned error id 3.
#   => Observed pattern: error 3 is returned when the query has no entries.
#      ESET does not document this, so the script only treats error 3 as
#      "empty" after confirming the WHOLE Detections log also returns error 3.
#   - Real field names returned by ESET: "Time" (yyyy-MM-dd HH-mm-ss),
#     "Action Taken", "Action Error", "Threat Handled" ("1" / "0"),
#     "Hash SHA256", "Object URI", "Threat Name", "Threat Type".
#   - Observed values: "Retained" + Handled 0, "Unable to clean" + Handled 0,
#     "Cleaned by deleting" + Handled 1.
#     => "Threat Handled" is ESET's own verdict, so we use it directly.
#
# AUTO-REMEDIATION LOGIC:
#   - Handled = 1                                   -> INFO (no alert)
#   - Handled = 0 but a LATER entry for the same file (same SHA256 + same path)
#     has Handled = 1                               -> INFO (ESET fixed it later)
#   - Handled = 0 with no later clean               -> CRITICAL
#   - Field missing/unexpected value                -> WARNING (cannot prove
#     either way, so never silently ignore it)
#
# NOT VERIFIED: whether "Time" is local time or UTC. It is treated as local.
# With a 24h lookback an offset of an hour or two has little practical impact.
# ---------------------------------------------------------------------------
$cutoff = (Get-Date).AddHours(-$DetectionLookbackHours)

# Helper: turn ESET's "yyyy-MM-dd HH-mm-ss" string into a DateTime.
# Returns $null if the format is ever different, so bad data is reported
# rather than mis-filtered.
function ConvertFrom-EsetTime {
    param([string]$Text)
    try {
        return [datetime]::ParseExact($Text, 'yyyy-MM-dd HH-mm-ss',
            [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch { return $null }
}

# Helper: run ermm.exe and return the WHOLE parsed JSON (including 'error'),
# so we can look at ESET's error id. Returns $null only if the output was not
# JSON at all (e.g. RMM disabled, crash).
function Invoke-ErmmRaw {
    param([string[]]$Arguments)
    try {
        $raw = (& $Ermm @Arguments 2>&1 | Out-String).Trim()
        if (-not $raw) { return $null }
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    }
    catch { return $null }
}

# Dates in ESET's documented format (note dashes in the time part).
$startText = $cutoff.ToString('yyyy-MM-dd HH-mm-ss')
$endText   = (Get-Date).ToString('yyyy-MM-dd HH-mm-ss')

# Step 1: ask ESET for just the lookback window.
$resp = Invoke-ErmmRaw @('get', 'logs', '--name', 'virlog', '--start-date', $startText, '--end-date', $endText)

$allEntries   = @()     # detections to evaluate
$logReadable  = $true   # false = we genuinely do not know the detection state

if ($null -eq $resp) {
    $logReadable = $false
    $Warning.Add("ermm get logs (virlog) returned non-JSON output - detection status UNKNOWN.")
}
elseif ($null -eq $resp.error) {
    # Success: entries in the window.
    if ($resp.result.virlog -and $resp.result.virlog.logs) {
        $allEntries = @($resp.result.virlog.logs)
    }
}
elseif ($resp.error.id -eq 3) {
    # Step 2: error 3 seen. Confirm by asking for the WHOLE log (no dates).
    $full = Invoke-ErmmRaw @('get', 'logs', '--name', 'virlog')

    if ($full -and $null -eq $full.error) {
        # The log has entries, just none in our window. Keep them anyway;
        # the time filter below drops anything outside the window, so a
        # misbehaving date filter can never hide a detection.
        if ($full.result.virlog -and $full.result.virlog.logs) {
            $allEntries = @($full.result.virlog.logs)
        }
    }
    elseif ($full -and $full.error.id -eq 3) {
        # Whole log also returns error 3 -> treated as an EMPTY Detections log
        # (observed behaviour on W2019114, not documented by ESET).
        $Info.Add("Detections log is empty (ESET returned error 3 for both the window and the full log).")
    }
    else {
        $logReadable = $false
        $Warning.Add("Detection log could not be read (full-log retry failed: $($full.error | ConvertTo-Json -Compress)) - detection status UNKNOWN.")
    }
}
else {
    # Any error other than 3 is a real, unexplained failure.
    $logReadable = $false
    $Warning.Add("ermm get logs (virlog) returned error: $($resp.error | ConvertTo-Json -Compress) - detection status UNKNOWN.")
}

if ($logReadable) {
    # Pre-parse every entry once: the time is needed both to filter the window
    # and to find later "cleaned" entries for the same file.
    $parsed = foreach ($e in $allEntries) {
        [pscustomobject]@{
            Entry   = $e
            Time    = ConvertFrom-EsetTime $e.'Time'
            # Same file = same hash AND same path. Hash alone could match
            # copies of the file in other folders that are still infected.
            FileKey = "$($e.'Hash SHA256')|$($e.'Object URI')"
            Handled = $e.'Threat Handled'
        }
    }

    # Entries we could not date are reported, never silently dropped.
    foreach ($p in ($parsed | Where-Object { $null -eq $_.Time })) {
        $Warning.Add("Detection with unreadable Time '$($p.Entry.'Time')' - verify manually.")
    }

    $inWindow = @($parsed | Where-Object { $_.Time -and $_.Time -ge $cutoff })

    if ($inWindow.Count -eq 0) {
        $Info.Add("No detections logged in the last $DetectionLookbackHours hour(s).")
    }

    foreach ($p in $inWindow) {
        $e = $p.Entry

        # Short, readable summary for the check output / ticket. Object URI is
        # URL-encoded by ESET, so decode it to a normal Windows path.
        $path    = [uri]::UnescapeDataString("$($e.'Object URI')") -replace '^file:///', ''
        $summary = "$($e.'Time') | $($e.'Threat Type'): $($e.'Threat Name') | $path | " +
                   "Action='$($e.'Action Taken')' Error='$($e.'Action Error')'"

        if ($p.Handled -eq '1') {
            $Info.Add("Detection auto-remediated by ESET: $summary")
        }
        elseif ($p.Handled -eq '0') {
            # Was the same file cleaned by a LATER entry (anywhere in the log)?
            $laterClean = $parsed | Where-Object {
                $_.FileKey -eq $p.FileKey -and $_.Handled -eq '1' -and
                $_.Time -and $_.Time -gt $p.Time
            } | Select-Object -First 1

            if ($laterClean) {
                $Info.Add("Detection initially unhandled, later cleaned by ESET at $($laterClean.Entry.'Time'): $summary")
            }
            else {
                $Critical.Add("Detection NOT handled: $summary")
            }
        }
        else {
            $Warning.Add("Detection with unexpected 'Threat Handled' value '$($p.Handled)' - verify manually: $summary")
        }
    }
}

# ---------------------------------------------------------------------------
# Output summary and exit code.
# Critical beats warning beats OK. Output is kept plain text so it reads well
# in RMM check history and in any ticket it generates.
# ---------------------------------------------------------------------------
if ($Critical.Count -gt 0) {
    Write-Output "CRITICAL: $($Critical.Count) critical, $($Warning.Count) warning finding(s) on $env:COMPUTERNAME"
    $Critical | ForEach-Object { Write-Output "  [CRIT] $_" }
    $Warning  | ForEach-Object { Write-Output "  [WARN] $_" }
    $Info     | ForEach-Object { Write-Output "  [INFO] $_" }
    exit 2
}
elseif ($Warning.Count -gt 0) {
    Write-Output "WARNING: $($Warning.Count) finding(s) on $env:COMPUTERNAME"
    $Warning | ForEach-Object { Write-Output "  [WARN] $_" }
    $Info    | ForEach-Object { Write-Output "  [INFO] $_" }
    exit 1
}
else {
    Write-Output "OK: ESET healthy on $env:COMPUTERNAME"
    $Info | ForEach-Object { Write-Output "  [INFO] $_" }
    exit 0
}

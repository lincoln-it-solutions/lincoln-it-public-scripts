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
      3. get license-info               -> licence EXPIRED (renewals due do not alert)
      4. get activation-status          -> last activation attempt failed
      5. get logs --name virlog         -> detections in the last N hours,
                                           flagged critical if they look unhandled
      6. LICENCE IDENTITY (merged in from the old "ESET - Licence Check", 2026-10-26):
         get license-info public_id/type vs the TRMM client fields
           ESET_LICENCE_TYPE={{client.ESET Licence Type}}   MSP / EBA / NFR
           ESET_LICENCE={{client.ESET Licence}}             "<public ID> | <key>"
         passed in as environment variables on checks 416/417 (not arguments,
         so the key isn't in the argument list). ermm types: MSP=MSP, EBA=PAID,
         NFR=NFR (all seen live). "Not activated" is reported ONCE, here, with
         what to do - protection-status no longer raises its own copy.
      7. FIXES (only with -Fix; Ethan 2026-10-26: pilot first, then add -Fix to
         checks 416/417). Each fix is re-checked; a fixed problem does not alert.
           Not activated / wrong licence, EBA or NFR -> ermm start activation --key
                 (needs ESET RMM working mode "All operations" - Ethan confirmed)
           Not activated / wrong licence, MSP -> NOT fixable here (ESET's MSP
                 portal shows no full keys): alert says activate in the
                 ESET PROTECT portal (Product Activation task)
           Detection engine / modules not updated -> ermm start update
         Diagnosed, not fixed (always, read-only):
           LiveGrid servers unreachable -> DNS + TCP tests to ESET's LiveGrid
                 hosts/ports (KB332) and which one is blocked
           Push Notification Service unreachable -> network/proxy (KB8207)
           Restart required, modules disabled -> what to do
      9. MUTE BY LICENCE TYPE: env ESET_MUTE_TYPES (e.g. EBA) silences every finding
         for clients of that licence type except unhandled detections / network
         isolation; muted findings print as [MUTED] lines (see note in the code).
      8. ESET Management Agent installed but NO ESET security product -> WARNING
         (managed by us but unprotected; previously passed as "not installed").
         Not raised for clients with the "ESET Product Not Required" box ticked
         (env var ESET_PRODUCT_NOT_REQUIRED={{client.ESET Product Not Required}}).

    Exit codes (so an RMM script check can alert on them):
      0 = OK
      1 = Warning  (needs a look, not urgent)
      2 = Critical (action required)
      3 = Info: ESET is managed (ESET Management Agent installed) but its RMM
          interface (ermm.exe) is not answering, so health can't be read

    Unmanaged machines: ESET installed WITHOUT the ESET Management Agent is not
    ours to monitor, so the check passes (exit 0) whatever ermm.exe says.

    Exit codes reach Tactical RMM unchanged via Stop-Check (see below). Before
    2026-10-25 a plain "exit 2" arrived as 1, so every result looked the same.

.PREREQUISITE
    ESET RMM is DISABLED by default. Enable it (ideally via an ESET PROTECT policy):
    Advanced setup > Tools > ESET RMM > Enable RMM.
    Working mode: "Safe operations only" allows reads + start scan/update;
    "All operations" also allows start activation and set configuration
    (needed for -Fix activation). Ethan's policy: All operations (2026-10-26).
    Source: https://help.eset.com/ees/13/en-US/how_activate_rmm.html

.SOURCES
    Command list:     https://help.eset.com/eea/12/en-US/rmm_json_commands.html
    protection-status https://help.eset.com/eea/12/en-US/rmm_json_get_protection.html
    license-info      https://help.eset.com/eea/12/en-US/rmm_json_commands_license.html
    activation-status https://help.eset.com/eea/12/en-US/rmm_json_commands_activation_status.html
    get logs          https://help.eset.com/eea/12/en-US/rmm_json_commands_logs.html
    Server Security   https://help.eset.com/efsw/12.0/en-US/idh_config_ermm.html
    Isolation status  https://help.eset.com/efsw/12.0/en-US/network_isolation.html
    start activation  https://help.eset.com/ees/13/en-US/rmm_json_commands_start_activation.html
    start update      https://help.eset.com/ees/13/en-US/rmm_json_commands_start_update.html
    update-status     https://help.eset.com/ees/13/en-US/rmm_json_commands_update_status.html
    LiveGrid hosts    https://support.eset.com/en/kb332  (TCP 80, TCP/UDP 53535)
    Push Notification https://support.eset.com/en/kb8207-resolve-push-notification-service-servers-cannot-be-reached-alert-in-eset-endpoint-products
    MSP activation    https://help.eset.com/msp_getting_started/en-INT/protect_automated_activation.html
#>

param(
    # How far back to look in the detection (virlog) log.
    # Match this to how often the check runs, plus some overlap.
    [int]$DetectionLookbackHours = 24,

    # Licence expiry early warning. 0 = OFF (Ethan, 2026-10-26: alert on an
    # EXPIRED licence only; licences pending renewal must not fail the check).
    # Kept as a parameter so existing TRMM check arguments don't break; set it
    # above 0 to bring the "expires in N days" warning back.
    [int]$LicenceWarnDays = 0,

    # Maximum seconds any single ermm.exe call may run before it is killed.
    # The script makes up to 5 ermm.exe calls, so worst case is roughly
    # 5 x (30 + 5 s grace) = 175 s, safely under a 300 s Tactical timeout.
    # Keeps the whole script well inside Tactical RMM's script timeout
    # (Tactical reported "Script timed out after 300 seconds" on an affected machine).
    [int]$ErmmTimeoutSeconds = 30,

    # Default behaviour: if ESET is not installed at all, PASS (exit 0) so the
    # check can be applied globally to every agent.
    # Add -RequireEset as a script argument on clients/policies where ESET
    # MUST be present, and a missing install becomes CRITICAL instead.
    [switch]$RequireEset,

    # ESET products this check should NOT monitor (e.g. consumer NOD32 on a
    # user's own licence). Each entry is a regex matched against the product
    # name from the Windows uninstall entry and from ermm "application-info".
    # Pass extra patterns from Tactical like: -ExcludeProducts 'NOD32','Smart Security'
    [string[]]$ExcludeProducts = @('NOD32'),

    # Uninstall DisplayNames used by ESET home products that do NOT include
    # ermm.exe. EXACT match (not regex), and only acted on when no ermm.exe
    # exists, so a business product can never be excluded by this.
    # Evidence: NOD32 machine uninstall entry reported as 'ESET Security'
    # (checked in Tactical terminal, 28 Sep 2026); NOD32 has no ermm.exe.
    [string[]]$HomeProductNames = @('ESET Security'),

    # By default ESET error 3 on 'get protection-status' is treated as HEALTHY (see the
    # protection status section for the evidence). Add -StrictProtectionStatus to go back
    # to reporting it as "RMM not answering" (Info, exit 3).
    [switch]$StrictProtectionStatus,

    # Run the fixes in section 7 (activation for EBA/NFR, detection engine
    # update). Off by default: without it the check only reports.
    [switch]$Fix,

    # After starting an activation / update, how long to wait for the result.
    [int]$ActivationWaitSeconds = 60,
    [int]$UpdateWaitSeconds = 90,

    # Don't START a fix once the run has used this many seconds, so the whole
    # check stays inside its TRMM timeout (check 417 = 300 s). Skipped fixes are
    # reported and simply happen on the next run.
    [int]$FixTimeBudgetSeconds = 150,

    # RETRY LIMITS per kind of fix, attempts in any rolling 24 hours (Ethan 2026-10-26:
    # "activation twice a day but a threat isn't limited"). 0 = no limit. Activation is
    # limited because a wrong/used-up key would otherwise be retried on every run; the
    # state is kept in $StateDir so it survives between check runs.
    [int]$MaxActivationsPerDay = 2,
    [int]$MaxUpdatesPerDay = 0,
    [string]$StateDir = 'C:\ProgramData\LincolnIT\ESETMonitor',

    # Where the Reboot Nag (Invoke-RebootNag.ps1) keeps its files. Restart requests go
    # in <NagDir>\requests. Only used with -Fix, workstations, and a nag that is running.
    [string]$NagDir = 'C:\ProgramData\LincolnIT\RebootNag',

    # ESET restart handling (Ethan 2026-10-26).
    #  RestartPostponeHours      : the ONE postpone the user gets before the window becomes permanent.
    #  RestartAlertAfterHours    : alert if the user has been asked this long and the PC still has not
    #                              restarted (my choice of 24 h - change if you want sooner/later).
    #  PostRestartGraceMinutes   : after a restart, how long ESET may still show "restart" before it is
    #                              treated as a fault rather than ESET still starting up (my choice, 30).
    [int]$RestartPostponeHours = 4,
    [int]$RestartAlertAfterHours = 24,
    [int]$PostRestartGraceMinutes = 30,

    # TEST HOOKS ONLY (offline testing with a fake ermm). Leave unset in TRMM.
    [long]$TestBootEpoch = 0,
    [int]$TestProductType = 0,
    [string]$ErmmPath = '',
    [switch]$SkipInstallChecks
)

# Time the run so fixes never push the check past its TRMM timeout.
$RunTimer = [System.Diagnostics.Stopwatch]::StartNew()

# ---------------------------------------------------------------------------
# Result collectors. Every finding is added to one of these lists so the
# script can print a single readable summary and pick one exit code at the end.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Exit code helper.
# WHY: the Tactical RMM Windows agent runs scripts as
#   powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass <file>
# without -File, so a plain "exit 2" reaches TRMM as 1. SetShouldExit passes
# the real code through - tested via a TRMM script check on Steve-Win11
# 2026-10-20: plain exit 2 -> 1, SetShouldExit(2) -> 2. (Same helper as the
# backup monitoring scripts.)
# ---------------------------------------------------------------------------
function Stop-Check([int]$Code) {
    $host.SetShouldExit($Code)
    exit $Code
}

$Critical = New-Object System.Collections.Generic.List[string]
$Warning  = New-Object System.Collections.Generic.List[string]
$Info     = New-Object System.Collections.Generic.List[string]

# ---------------------------------------------------------------------------
# MUTE BY LICENCE TYPE (Ethan, 2026-10-26: "mute alerting on all EBA clients for
# now, as I'm still locked out of the portal so cannot fix them").
# The check is given
#   ESET_MUTE_TYPES=EBA                         (set on checks 416/417; remove to unmute)
#   ESET_LICENCE_TYPE={{client.ESET Licence Type}}
# A client whose licence type is in the mute list gets NO ESET alert except the
# live-threat ones in $KeepAlways below. Everything else (not activated, wrong
# licence, status warnings, agent-only, damaged install, fields unset ...) is
# still worked out and printed as [MUTED] lines in the check output - so it
# stays visible in the check history - but the check passes (exit 0).
# Why threats are kept: the muted problems are ones fixed in the ESET portal;
# an unhandled detection or a network-isolated machine is not, so it still alerts.
# A client with NO licence type set is never muted (we don't know what it is).
# ---------------------------------------------------------------------------
$ClientLicType = ("$env:ESET_LICENCE_TYPE").Trim().ToUpper()
if ($ClientLicType -match '^\{\{') { $ClientLicType = '' }   # unresolved TRMM variable
$MuteTypes = @(("$env:ESET_MUTE_TYPES") -split '[,;\s]+' | Where-Object { $_ -and $_ -notmatch '^\{\{' } | ForEach-Object { $_.ToUpper() })
$MuteThisClient = [bool]($ClientLicType -and ($MuteTypes -contains $ClientLicType))
# Findings that are never muted: unhandled/odd detections and ESET network isolation.
$KeepAlways = '^Detection (NOT handled|with )|NETWORK ISOLATED'

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
# ---------------------------------------------------------------------------
# 0. Excluded products (checked first, before ermm.exe)
#
# WHY the uninstall registry: it is written by the product's own installer
# and exists whether or not that product ships ermm.exe (ESET documents
# ermm.exe for its business products; I found no documentation either way
# for NOD32). Both 64-bit and 32-bit uninstall locations are read.
# Only entries whose DisplayName or Publisher mentions ESET are considered,
# so other vendors' software can never trigger the exclusion.
# ---------------------------------------------------------------------------
# Each uninstall key is read on its own (2026-10-26). WHY: on BIFRANGI22-PC one
# malformed entry made a single wildcard Get-ItemProperty call throw "Specified
# cast is not valid" and return NOTHING, so the Management Agent wasn't seen and
# the machine was skipped as "unmanaged" - i.e. never monitored. Per-key
# try/catch means one bad entry only loses itself.
$UninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
$EsetInstalls = @(
    foreach ($root in $UninstallRoots) {
        foreach ($key in (Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
            try {
                $p = Get-ItemProperty -Path $key.PSPath -ErrorAction Stop
                if ($p.DisplayName -match 'ESET' -or $p.Publisher -match 'ESET') { $p }
            } catch {
                # Unreadable entry (bad value type etc.) - skip just this one.
            }
        }
    }
)

foreach ($pattern in $ExcludeProducts) {
    $hit = $EsetInstalls | Where-Object { $_.DisplayName -match $pattern } | Select-Object -First 1
    if ($hit) {
        Write-Output "OK: '$($hit.DisplayName)' is excluded from this check (matched '$pattern') on $env:COMPUTERNAME."
        Stop-Check 0
    }
}

# Home-product rule (NOD32 and similar, no ermm.exe).
# Both conditions must be true:
#   a) an ESET uninstall entry's DisplayName EXACTLY equals a name in
#      $HomeProductNames, and
#   b) ermm.exe is absent from every known ESET product folder.
# (b) is what stops a business product with a generic name being excluded:
# every business product tested so far ships ermm.exe.
$ErmmAnywhere = @(
    "$env:ProgramFiles\ESET\ESET Security\ermm.exe",
    "$env:ProgramFiles\ESET\ESET Server Security\ermm.exe",
    "$env:ProgramFiles\ESET\ESET File Security\ermm.exe"
) | Where-Object { Test-Path $_ }

if (-not $ErmmAnywhere) {
    $homeHit = $EsetInstalls | Where-Object { $HomeProductNames -contains $_.DisplayName } | Select-Object -First 1
    if ($homeHit) {
        Write-Output "OK: '$($homeHit.DisplayName)' $($homeHit.DisplayVersion) is an ESET home product without RMM support - excluded from this check on $env:COMPUTERNAME."
        Stop-Check 0
    }
}

$ProductFolders = @(
    "$env:ProgramFiles\ESET\ESET Security",
    "$env:ProgramFiles\ESET\ESET Server Security",
    "$env:ProgramFiles\ESET\ESET File Security"
)

# ---------------------------------------------------------------------------
# Unmanaged rule: ESET product present but no ESET Management Agent -> OK.
# WHY: the Management Agent is what connects a machine to our ESET PROTECT
# console. Without it the install isn't one we manage (e.g. a client's own
# licence), so we don't alert on it - even if ermm.exe reports problems.
# Agent names are the uninstall DisplayNames seen in TRMM software inventory
# 2026-10-25: "ESET Management Agent" (current) and "ESET Remote
# Administrator Agent" (older 6.x name).
# ---------------------------------------------------------------------------
$AgentNamePattern = '^ESET (Management|Remote Administrator) Agent'
$MgmtAgent = $EsetInstalls | Where-Object { $_.DisplayName -match $AgentNamePattern } | Select-Object -First 1

# ---------------------------------------------------------------------------
# BACKUP PRODUCT INSTALLER STATUS (2026-10-27, Ethan: "The monitor should track if it
# installs or not").
# Install-EsetProduct.ps1 installs the ESET product on machines that have the Management
# Agent but no product. It runs detached (a one-off scheduled task), so nobody sees its
# result in TRMM; it writes it to $StateDir\product-install-status.json instead, and this
# check reads that file so the result shows up where the alerts are:
#   started / downloading / installing  -> Info (exit 3) while recent, WARNING if stalled > 90 min
#   failed                              -> the WARNING for 'no product' now carries the reason
#   installed (viaBackup)               -> an Info line for 14 days on the healthy run
#   file missing                        -> 'the backup installer has not run on this PC'
# Times are unix seconds ('updatedEpoch') so there is no time-zone parsing.
# ---------------------------------------------------------------------------
$InstallStatus = $null
$InstallStatusFile = Join-Path $StateDir 'product-install-status.json'
if (Test-Path -LiteralPath $InstallStatusFile) {
    try { $InstallStatus = Get-Content -LiteralPath $InstallStatusFile -Raw | ConvertFrom-Json } catch { $InstallStatus = $null }
}
$InstallAgeMin = $null
if ($InstallStatus -and $InstallStatus.updatedEpoch) {
    $InstallAgeMin = [int](([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [long]$InstallStatus.updatedEpoch) / 60)
}
function Get-InstallStatusText {
    if (-not $InstallStatus) { return 'The backup installer (Install-EsetProduct.ps1) has not run on this PC.' }
    $when = if ($null -ne $InstallAgeMin) { "$InstallAgeMin min ago" } else { 'time unknown' }
    return "Backup installer: $($InstallStatus.state) ($when) - $($InstallStatus.message)"
}
$InstallInProgress = [bool]($InstallStatus -and ($InstallStatus.state -in 'started', 'downloading', 'installing') -and $null -ne $InstallAgeMin -and $InstallAgeMin -lt 90)

# "Product present" = ermm.exe or any ESET product folder exists.
$ProductPresent = [bool]$ErmmAnywhere -or [bool]($ProductFolders | Where-Object { Test-Path $_ })

if ($ProductPresent -and -not $MgmtAgent -and -not $SkipInstallChecks) {
    # Product name/version from the uninstall entries, for the record (agents excluded).
    $prod = $EsetInstalls | Where-Object { $_.DisplayName -notmatch $AgentNamePattern } | Select-Object -First 1
    Write-Output "OK: ESET is unmanaged on $env:COMPUTERNAME (no ESET Management Agent installed) - not monitored."
    if ($prod) { Write-Output "  [INFO] Product: $($prod.DisplayName) $($prod.DisplayVersion)" }
    Stop-Check 0
}

# Build the ermm.exe path for each product folder.
$CandidatePaths = $ProductFolders | ForEach-Object { Join-Path $_ 'ermm.exe' }
$Ermm = $CandidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($ErmmPath) { $Ermm = $ErmmPath }   # test hook

# Managed by us (Management Agent present) but NO ESET security product at all.
# Before 2026-10-26 this fell through to "ESET not installed" and passed; the
# 2026-10-26 audit found 26 such machines (PC Coaches 14, Simpler Law 9, ...).
if (-not $Ermm -and $MgmtAgent -and -not ($ProductFolders | Where-Object { Test-Path $_ })) {
    # Per-client opt-out (Ethan 2026-10-26: "PC Coaches doesnt need installing"):
    # client checkbox "ESET Product Not Required", passed in by the check as
    #   ESET_PRODUCT_NOT_REQUIRED={{client.ESET Product Not Required}}
    # TRMM gives PowerShell a ticked box as the text "$True" (seen live on
    # DESKTOP-0IOM5IT, 2026-10-26); True/1/yes accepted too.
    if ("$env:ESET_PRODUCT_NOT_REQUIRED".Trim() -match '^\$?(true|1|yes)$') {
        Write-Output "OK: $env:COMPUTERNAME has the ESET Management Agent but no ESET product - allowed for this client ('ESET Product Not Required' is ticked)."
        Stop-Check 0
    }
    if ($MuteThisClient) {
        Write-Output "OK (muted): $env:COMPUTERNAME has the ESET Management Agent but NO ESET security product - alerting is muted for $ClientLicType clients."
        Write-Output "  [INFO] $(Get-InstallStatusText)"
        Stop-Check 0
    }
    if ($InstallInProgress) {
        # The backup installer is working on it right now: say so instead of raising a warning.
        Write-Output "INFO: $env:COMPUTERNAME has the ESET Management Agent and no ESET product yet - the backup installer is installing it."
        Write-Output "  $(Get-InstallStatusText)"
        Stop-Check 3
    }
    Write-Output "WARNING: $env:COMPUTERNAME has the ESET Management Agent but NO ESET security product installed - it is not protected by ESET."
    Write-Output "  Management Agent: $($MgmtAgent.DisplayName) $($MgmtAgent.DisplayVersion)"
    Write-Output "  $(Get-InstallStatusText)$(if ($InstallStatus -and $InstallStatus.state -in 'started', 'downloading', 'installing') { ' (no update for over 90 minutes - looks stalled)' })"
    $other = $EsetInstalls | Where-Object { $_.DisplayName -notmatch $AgentNamePattern } | Select-Object -First 1
    if ($other) { Write-Output "  Other ESET entry: $($other.DisplayName) $($other.DisplayVersion)" }
    Write-Output "  ACTION: install ESET Endpoint Security from ESET PROTECT (Software Install task), or remove the agent if this machine shouldn't have ESET."
    Stop-Check 1
}

if (-not $Ermm) {
    # Which product folders (if any) exist on this machine?
    $FoundFolders = @($ProductFolders | Where-Object { Test-Path $_ })

    if ($FoundFolders.Count -gt 0) {
        # Case b: product folder present but ermm.exe missing.
        if ($MuteThisClient) {
            Write-Output "OK (muted): ESET product folder found but ermm.exe is missing on $env:COMPUTERNAME - alerting is muted for $ClientLicType clients. Found: $($FoundFolders -join '; ')"
            Stop-Check 0
        }
        Write-Output "CRITICAL: ESET product folder found but ermm.exe is missing - installation damaged or partly removed."
        Write-Output "Found: $($FoundFolders -join '; ')"
        Stop-Check 2
    }

    # Case c: no ESET product installed.
    if ($RequireEset) {
        Write-Output "CRITICAL: ESET is not installed on $env:COMPUTERNAME (this check was run with -RequireEset)."
        Write-Output "Checked: $($ProductFolders -join '; ')"
        Stop-Check 2
    }

    Write-Output "OK: ESET not installed on $env:COMPUTERNAME - nothing to monitor."
    Stop-Check 0
}
$Info.Add("ermm.exe found at: $Ermm")
if ($InstallStatus -and $InstallStatus.state -eq 'installed' -and $InstallStatus.viaBackup -eq $true -and $null -ne $InstallAgeMin -and $InstallAgeMin -lt (14 * 24 * 60)) {
    $Info.Add("ESET product installed by the backup installer: $($InstallStatus.message) ($InstallAgeMin min ago).")
}

# ---------------------------------------------------------------------------
# Helper: run an ermm.exe command and return the parsed JSON 'result' object.
# ermm.exe prints JSON of the form {"id":..,"result":{...},"error":..}
# (see the example outputs on the ESET pages listed above).
# Returns $null if the call fails, so the caller can report it.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Helper: run ermm.exe with a hard time limit and return its text output.
#
# WHY: on an affected machine (24 Sep 2026) the script printed its full OK summary
# but Tactical still reported "Script timed out after 300 seconds". The cause
# is not yet known. Running ermm.exe through System.Diagnostics.Process lets
# us stop waiting after $ErmmTimeoutSeconds, kill it, and record exactly which
# command hung, instead of the whole check timing out with no explanation.
#
# Output is read asynchronously so that a process which keeps the output pipe
# open cannot block us either; we only wait up to the timeout for it.
# Returns the output string, or $null on timeout/launch failure (a warning is
# recorded in both cases).
# ---------------------------------------------------------------------------
function Invoke-ErmmProcess {
    param([string[]]$Arguments)

    # Quote any argument containing a space (the date values do) so ermm.exe
    # receives it as one argument, exactly as with the & call operator.
    $argString = ($Arguments | ForEach-Object {
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }) -join ' '

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $Ermm
    $psi.Arguments              = $argString
    $psi.UseShellExecute        = $false   # required to capture output
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    try {
        [void]$proc.Start()

        # Start reading both streams in the background immediately, so a full
        # output buffer can never deadlock the process.
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()

        $timeoutMs = $ErmmTimeoutSeconds * 1000

        if (-not $proc.WaitForExit($timeoutMs)) {
            # ermm.exe itself did not finish in time: kill it and report.
            try { $proc.Kill() } catch { }
            $script:Warning.Add("ermm $argString did not finish within $ErmmTimeoutSeconds s and was stopped.")
            return $null
        }

        # Process has exited; give the output readers a short grace period.
        # If something else is still holding the pipe open, do not hang on it.
        if (-not $outTask.Wait(5000)) {
            $script:Warning.Add("ermm $argString exited but its output stream stayed open - output discarded.")
            return $null
        }
        [void]$errTask.Wait(1000)

        return ($outTask.Result + $errTask.Result).Trim()
    }
    catch {
        $script:Warning.Add("ermm $argString could not be started: $($_.Exception.Message)")
        return $null
    }
    finally {
        $proc.Dispose()
    }
}

function Invoke-Ermm {
    param([string[]]$Arguments)

    try {
        # Join output lines into one string because ConvertFrom-Json in
        # Windows PowerShell 5.1 needs the whole document, not line by line.
        $raw = Invoke-ErmmProcess $Arguments
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
# Second exclusion check using ESET's own product name.
# ESET documents 'get application-info' returning "description" (e.g.
# "ESET Endpoint Antivirus") and "product" (e.g. "eea").
# Source: https://help.eset.com/eea/12/en-US/rmm_json_commands_application.html
# This catches an excluded product whose uninstall entry was missed above.
# ---------------------------------------------------------------------------
# Called quietly (no warning if it fails): this is only a secondary exclusion
# check, and I have not confirmed application-info is permitted under
# "Safe operations only", so a refusal here must not raise a false warning.
$appInfo = $null
try {
    $appRaw = Invoke-ErmmProcess @('get', 'application-info')
    if ($appRaw) {
        $appJson = $appRaw | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $appJson.error) { $appInfo = $appJson.result }
    }
}
catch { $appInfo = $null }

if ($appInfo) {
    foreach ($pattern in $ExcludeProducts) {
        if ($appInfo.description -match $pattern) {
            Write-Output "OK: '$($appInfo.description)' is excluded from this check (matched '$pattern') on $env:COMPUTERNAME."
            Stop-Check 0
        }
    }
    $Info.Add("Product: $($appInfo.description) $($appInfo.version) (product code '$($appInfo.product)')")
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
# ERROR 3 = HEALTHY (provisional, Ethan's decision 2026-10-25, to be tested):
# On ESET Endpoint 13.1.2036.0, 'get protection-status' returns error 3 "General error
# executing command." on 176 of 183 machines, while application-info, license-info,
# activation-status and update-status all answer. Every 13.1 machine that DID answer had a
# non-green status (LiveGrid unreachable x4, not activated x1); none answered while green.
# So error 3 most likely means "nothing to report", like the empty-log error 3 from
# 'get logs' below. Not yet proven (needs a deliberately non-green 13.1 test).
# Licence, activation and detection checks below still run, so those problems are still caught.
$prot = $null
$protError3 = $false
$protText = Invoke-ErmmProcess @('get', 'protection-status')
if ($protText) {
    try {
        $protJson = $protText | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $protJson.error) {
            $prot = $protJson.result
        }
        elseif ($protJson.error.id -eq 3 -and -not $StrictProtectionStatus) {
            $protError3 = $true
            # Empty stand-in so the checks below run unchanged (no status items to judge).
            $prot = [pscustomobject]@{ statuses = @(); status = 'n/a'; description = 'ESET returned error 3, treated as healthy' }
            $Info.Add("Protection status: ESET returned error 3 - treated as healthy (provisional; add -StrictProtectionStatus to report it instead).")
        }
        else {
            $Warning.Add("ermm get protection-status returned error: $($protJson.error | ConvertTo-Json -Compress)")
        }
    }
    catch {
        $Warning.Add("ermm get protection-status failed or gave non-JSON output: $protText")
    }
}

if ($null -eq $prot) {
    # If we cannot even read protection status, the monitor is blind.
    # Managed machine (agent present, checked above) whose RMM interface won't answer:
    # report as Info (exit 3), not a failure, with the product and agent versions.
    # 2026-10-25: 175 workstations gave error 3 "General error executing command";
    # all 40 sampled run ESET Endpoint 13.1.2036.0 (sampled healthy ones run 13.0.x).
    $prod = $EsetInstalls | Where-Object { $_.DisplayName -notmatch $AgentNamePattern } | Select-Object -First 1
    Write-Output "INFO: ESET is managed on $env:COMPUTERNAME but its RMM interface (ermm.exe) is not answering - health can't be read."
    if ($prod) { Write-Output "  Product: $($prod.DisplayName) $($prod.DisplayVersion)" }
    Write-Output "  Management Agent: $($MgmtAgent.DisplayName) $($MgmtAgent.DisplayVersion)"
    Write-Output "  Check ESET RMM is enabled in the ESET PROTECT policy (Tools > ESET RMM)."
    # Right after the backup installer has put the product on, RMM stays disabled until the PROTECT
    # policy arrives (seen 2026-10-27: a few minutes), so show the installer's state here too.
    if ($InstallStatus -and $InstallStatus.viaBackup -eq $true -and $null -ne $InstallAgeMin -and $InstallAgeMin -lt 180) { Write-Output "  $(Get-InstallStatusText)" }
    $Warning | ForEach-Object { Write-Output "  $_" }
    Stop-Check 3
}

# Protection-status items that must NOT alert (Ethan, 2026-10-26: alert on an
# EXPIRED licence only, no pre-warning). Exact ESET status IDs, as seen live:
#   eset_licensing_integration.renewable_license.expires_soon
#     -> "Subscription expires", status 1 (LEANNE, 2026-10-26, licence state
#        'will-expire', expiry 2026-11-05)
# A genuinely expired licence is still caught by the licence check (section 3),
# and any other status ID still alerts as before.
$IgnoredStatusIds = @(
    'eset_licensing_integration.renewable_license.expires_soon'
)

# Status items we may diagnose or fix later (section 7), remembered by the
# exact text added to the Critical/Warning lists so a fixed item can be removed.
# IDs seen live 2026-10-26:
#   eset_licensing_integration.no_product_activated  "Product not activated" (2)
#   cloud_classification_integration.cloud_not_reachable
#        "The ESET LiveGrid(R) servers cannot be reached" (1)
$NotActivatedStatus = $null   # reported ONCE in section 6, not here
$LiveGridLine = $null; $PushLine = $null; $UpdateLine = $null
$RestartLine = $null; $ModuleLine = $null

foreach ($s in $prot.statuses) {
    $line = "[$($s.id)] $($s.description) (status=$($s.status), priority=$($s.priority))"

    # Record ignored items as Info so they stay visible, then skip alerting.
    if ($IgnoredStatusIds -contains $s.id) {
        $Info.Add("Protection status (not alerted - licence not expired): $line")
        continue
    }

    # Not activated: held back and reported once by the licence section (6),
    # which knows the client's licence and what to do. Avoids two alerts for
    # one problem (Ethan, 2026-10-26).
    if ($s.id -match 'no_product_activated|NotActivated' -or $s.description -match 'not activated') {
        $NotActivatedStatus = $line
        continue
    }

    # Status 2 is documented (by example) as a red security alert -> critical.
    # Status 1 is not documented; we treat it as a warning so it is not missed.
    $entry = "Protection status: $line"
    if ($s.status -ge 2)     { $Critical.Add($entry) }
    elseif ($s.status -eq 1) { $Warning.Add($entry) }

    # Remember items section 7 can diagnose or fix (only ones that alerted).
    # Text matches because ESET documents only one status ID; the LiveGrid ID
    # is from live output.
    if ($s.status -lt 1) { }
    elseif ($s.id -match 'cloud_not_reachable' -or $s.description -match 'LiveGrid') { $LiveGridLine = $entry }
    elseif ($s.description -match 'Push Notification') { $PushLine = $entry }
    elseif ($s.description -match 'restart') { $RestartLine = $entry }
    elseif (($s.id + ' ' + $s.description) -match 'update|detection engine|modules? (are |is )?out of date' -and
            $s.description -notmatch 'operating system|windows') { $UpdateLine = $entry }
    elseif ($s.description -match 'disabled|paused|turned off|not functional') { $ModuleLine = $entry }

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
# Source: https://help.eset.com/eea/12/en-US/rmm_json_commands_license.html
#
# ALERT ON EXPIRED ONLY (Ethan, 2026-10-26). A licence that is still valid but
# due for renewal must not fail the check. So:
#   - expiry date in the past                      -> CRITICAL
#   - expiration_state says "expired"              -> CRITICAL (covers MSP seats,
#     whose license-info has no top-level expiration_date - see project note
#     eset_monitor_managed_info_2026-10-25)
#   - any other non-"ok" state (ESET only documents "ok", so other values such
#     as a "nearly expired" state are undocumented) -> INFO only, so it is
#     recorded in the output but does not alert.
#   - "expires in N days" warning only if -LicenceWarnDays is set above 0.
# ---------------------------------------------------------------------------
$lic = Invoke-Ermm @('get', 'license-info')
if ($lic) {
    if ($lic.expiration_state -and $lic.expiration_state -ne 'ok') {
        if ($lic.expiration_state -match 'expired') {
            $Critical.Add("Licence state is '$($lic.expiration_state)' (expires $($lic.expiration_date)).")
        }
        else {
            # Not expired (e.g. pending renewal): record it, don't alert.
            $Info.Add("Licence state is '$($lic.expiration_state)' (expires $($lic.expiration_date)) - not expired, no alert.")
        }
    }

    if ($lic.expiration_date) {
        try {
            $exp  = [datetime]::ParseExact($lic.expiration_date, 'yyyy-MM-dd', $null)
            $days = [int]($exp - (Get-Date).Date).TotalDays
            if ($days -lt 0) {
                # Avoid a second line if expiration_state already reported it.
                if ($lic.expiration_state -notmatch 'expired') {
                    $Critical.Add("Licence EXPIRED $([math]::Abs($days)) day(s) ago ($($lic.expiration_date)).")
                }
            }
            elseif ($LicenceWarnDays -gt 0 -and $days -le $LicenceWarnDays) {
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
# 6. Licence identity vs the client's TRMM fields (+ activation fix)
# ---------------------------------------------------------------------------
# Small helpers used by sections 6 and 7.
function Hide-Key([string]$Key) {
    if (-not $Key) { return '(none)' }
    if ($Key.Length -le 4) { return '****' }
    return ('****-****-****-****-' + $Key.Substring($Key.Length - 4))
}
# Replace a finding's text in whichever list holds it (to add diagnosis).
function Update-Finding([string]$Old, [string]$New) {
    foreach ($list in @($script:Critical, $script:Warning)) {
        $i = $list.IndexOf($Old)
        if ($i -ge 0) { $list[$i] = $New; return }
    }
}
# Remove a finding that a fix has resolved.
function Clear-Finding([string]$Old) {
    [void]$script:Critical.Remove($Old); [void]$script:Warning.Remove($Old)
}
function Test-FixTime { return ($RunTimer.Elapsed.TotalSeconds -lt $FixTimeBudgetSeconds) }

# Retry limit. Asks "may I make another attempt of this KIND of fix?" and, if yes, RECORDS the
# attempt straight away (before the fix runs, so a crash or timeout still counts).
#   - attempts are kept as unix seconds in $StateDir\fix-attempts.json, one list per kind;
#     only the last 24 h count (a rolling window, not a calendar day);
#   - $Max = 0 means no limit (attempts are still recorded so the output can show them);
#   - if the attempt cannot be RECORDED (folder not writable) the answer is "no": without a record
#     the limit could not work and the fix could repeat on every run.
# Returns an object with Allowed (bool) and Reason (text for the output).
function Reserve-FixAttempt([string]$Kind, [int]$Max) {
    $now  = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $file = Join-Path $StateDir 'fix-attempts.json'
    $all  = [ordered]@{}
    if (Test-Path $file) {
        try {
            $j = Get-Content $file -Raw | ConvertFrom-Json
            foreach ($p in $j.PSObject.Properties) {
                $all[$p.Name] = @($p.Value | ForEach-Object { [long]$_ } | Where-Object { $_ -gt ($now - 86400) })
            }
        } catch { $all = [ordered]@{} }   # unreadable record: start again (it is rewritten below)
    }
    $list = if ($all.Contains($Kind)) { @($all[$Kind]) } else { @() }
    if ($Max -gt 0 -and $list.Count -ge $Max) {
        $free = [DateTimeOffset]::FromUnixTimeSeconds([long](($list | Sort-Object | Select-Object -First 1) + 86400)).LocalDateTime.ToString('HH:mm')
        return [pscustomobject]@{ Allowed = $false; Reason = "limit of $Max attempt(s) per 24 h reached ($($list.Count) used); next attempt allowed after $free." }
    }
    $list = @($list) + $now
    $all[$Kind] = $list
    try {
        if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
        [System.IO.File]::WriteAllText($file, ($all | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false)))
    } catch {
        return [pscustomobject]@{ Allowed = $false; Reason = "could not record the attempt in $StateDir ($($_.Exception.Message)), so not retrying (it could repeat every run)." }
    }
    $of = if ($Max -gt 0) { " of $Max" } else { ' (no limit)' }
    return [pscustomobject]@{ Allowed = $true; Reason = "$Kind attempt $($list.Count)$of in the last 24 h" }
}

# Client fields, from the check's environment variables.
$LicType = ("$env:ESET_LICENCE_TYPE").Trim().ToUpper()
$LicRaw  = ("$env:ESET_LICENCE").Trim()
if ($LicType -match '^\{\{') { $LicType = '' }   # unresolved TRMM variable
if ($LicRaw  -match '^\{\{') { $LicRaw  = '' }
# The 'ESET Licence' field default is an example (XXX-XXX-XXX | ...) and TRMM
# passes a field's default when the client has no value - treat it as unset.
if ($LicRaw.Split('|')[0].Trim().ToUpper() -eq 'XXX-XXX-XXX') { $LicRaw = '' }

$WantId = ''; $WantKey = ''; $FieldProblem = $null
if (-not $LicType) { $FieldProblem = "client field 'ESET Licence Type' is not set" }
elseif (@('MSP', 'EBA', 'NFR') -notcontains $LicType) { $FieldProblem = "client field 'ESET Licence Type' is '$LicType' (must be MSP, EBA or NFR)" }
elseif (-not $LicRaw) { $FieldProblem = "client field 'ESET Licence' is empty (or still the example)" }
else {
    $parts = @($LicRaw.Split('|') | ForEach-Object { $_.Trim().ToUpper() })
    if ($parts.Count -eq 1) { $parts += '' }
    if ($parts.Count -ne 2) { $FieldProblem = "client field 'ESET Licence' must be '<public ID> | <activation key>'" }
    else {
        $WantId = $parts[0]; $WantKey = $parts[1]
        if ($WantId -notmatch '^[A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{3}$') { $FieldProblem = "public ID '$WantId' in client field 'ESET Licence' is not XXX-XXX-XXX" }
        elseif ($WantKey -and $WantKey -notmatch '^[A-Z0-9]{4}(-[A-Z0-9]{4}){4}$') { $FieldProblem = "activation key in client field 'ESET Licence' is not XXXX-XXXX-XXXX-XXXX-XXXX" }
    }
}

# What ermm reports as 'type' for each client licence type (all seen live).
$ExpectedErmmType = @{ 'MSP' = 'MSP'; 'EBA' = 'PAID'; 'NFR' = 'NFR' }
$HaveId   = if ($lic) { ("$($lic.public_id)").Trim().ToUpper() } else { '' }
$HaveType = if ($lic) { ("$($lic.type)").Trim().ToUpper() } else { '' }
# Not activated = protection status says so, or license-info has no public ID.
$NotActivated = [bool]$NotActivatedStatus -or ($lic -and -not $HaveId)
$ActivationHandled = $false   # tells section 4 not to raise a second alert

function Test-LicenceMatch($id, $type) {
    if (-not $WantId) { return $false }
    if ($id -ne $WantId) { return $false }
    $exp = $ExpectedErmmType[$LicType]
    return (-not $exp -or $type -eq $exp)
}

if ($FieldProblem) {
    # Without the client's licence we can still report "not activated", once.
    if ($NotActivated) {
        $Critical.Add("ESET is NOT ACTIVATED. $FieldProblem, so TRMM can't tell which licence it needs or activate it. Fill the client fields, or activate in the ESET PROTECT portal.")
        $ActivationHandled = $true
    }
    else {
        $Warning.Add("Licence identity not checked: $FieldProblem. Fill it in TRMM (Clients > Edit): type MSP/EBA/NFR, licence '<public ID> | <activation key>' (MSP: just the public ID).")
    }
}
elseif ($lic -and -not $NotActivated -and (Test-LicenceMatch $HaveId $HaveType)) {
    $Info.Add("Licence matches the client: $LicType $WantId (ermm type $HaveType).")
}
elseif ($lic -or $NotActivated) {
    $ActivationHandled = $true
    $state = if ($NotActivated) { 'NOT ACTIVATED' }
             elseif ($HaveId -eq $WantId) { "on licence $WantId but as type $HaveType - client field says $LicType (expected ermm type $($ExpectedErmmType[$LicType]))" }
             else { "on licence $HaveId (type $HaveType), not the client's $LicType licence $WantId" }
    $msg = "ESET is $state."
    $isCrit = [bool]$NotActivated

    if ($LicType -eq 'MSP') {
        # ESET's MSP portal shows no full keys, so TRMM can't activate MSP seats.
        $msg += " ACTION: activate it in the ESET PROTECT portal - run a Product Activation task on $env:COMPUTERNAME with this customer's MSP licence $WantId."
        if ($isCrit) { $Critical.Add($msg) } else { $Warning.Add($msg) }
    }
    elseif (-not $WantKey) {
        $msg += " Can't activate from TRMM: client field 'ESET Licence' has no activation key ($LicType needs one) - add it, or activate in the portal."
        if ($isCrit) { $Critical.Add($msg) } else { $Warning.Add($msg) }
    }
    elseif (-not $Fix) {
        $msg += " TRMM will activate it with key $(Hide-Key $WantKey) once this check runs with -Fix."
        if ($isCrit) { $Critical.Add($msg) } else { $Warning.Add($msg) }
    }
    elseif (-not (Test-FixTime)) {
        $msg += " Activation skipped this run (check already ran $([int]$RunTimer.Elapsed.TotalSeconds) s) - it will be tried next run."
        if ($isCrit) { $Critical.Add($msg) } else { $Warning.Add($msg) }
    }
    elseif (-not (($gate = Reserve-FixAttempt 'activation' $MaxActivationsPerDay).Allowed)) {
        # Retry limit reached (or attempt can't be recorded): say so, don't try again.
        $msg += " Activation NOT retried: $($gate.Reason)"
        if ($isCrit) { $Critical.Add($msg) } else { $Warning.Add($msg) }
    }
    else {
        # FIX: activate with the key, wait for the result, then re-read the licence.
        $Info.Add("Fix attempt: $($gate.Reason).")
        $start = Invoke-ErmmProcess @('start', 'activation', '--key', $WantKey)
        $startJson = $null; try { $startJson = $start | ConvertFrom-Json -ErrorAction Stop } catch { }
        if (-not $startJson -or $startJson.error) {
            $why = if ($startJson.error) { $startJson.error | ConvertTo-Json -Compress } else { 'no JSON reply' }
            $Critical.Add("$msg Activation with key $(Hide-Key $WantKey) could not start: $why (ESET RMM must be in 'All operations' mode).")
        }
        else {
            $deadline = (Get-Date).AddSeconds($ActivationWaitSeconds); $status = ''
            do {
                Start-Sleep -Seconds 5
                $st = Invoke-Ermm @('get', 'activation-status')
                if ($st) { $status = "$($st.status)".ToLower() }
            } while ($status -eq 'running' -and (Get-Date) -lt $deadline)
            $after = Invoke-Ermm @('get', 'license-info')
            $afterId = if ($after) { ("$($after.public_id)").Trim().ToUpper() } else { '' }
            $afterType = if ($after) { ("$($after.type)").Trim().ToUpper() } else { '' }
            if ($after -and (Test-LicenceMatch $afterId $afterType)) {
                $Info.Add("FIXED: was $state - activated with key $(Hide-Key $WantKey); now on $LicType licence $WantId.")
                $lic = $after
            }
            elseif ($afterId -and $afterId -ne $WantId -and $afterId -ne $HaveId) {
                $Critical.Add("$msg Activated with the key in client field 'ESET Licence' but it gave licence $afterId, not $WantId - the key and public ID in the field don't belong together.")
            }
            elseif ($status -eq 'running') {
                $Warning.Add("$msg Activation started with key $(Hide-Key $WantKey) and still running after $ActivationWaitSeconds s - next run will confirm.")
            }
            else {
                $Critical.Add("$msg Activation with key $(Hide-Key $WantKey) did not work (activation-status '$status'; licence now '$afterId').")
            }
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

        if ($ActivationHandled) {
            # Section 6 already raised (or fixed) the activation problem once.
            $Info.Add("Last ESET activation attempt failed (already covered by the licence finding): $actText")
        }
        elseif ($protError3) {
            $Warning.Add("Last ESET activation attempt failed and current activation state can't be confirmed (protection status returned error 3): $actText")
        }
        elseif ($activationIssueNow) {
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
#   - test machine A: 'get logs --name virlog' with a date range that CONTAINS
#     detections (2026-09-01 to 2026-09-02) returned them correctly, so
#     ESET's date filtering works.
#   - test machine A: every date range with NO matching entries (2017 dates,
#     22-23 Sep 2026) returned error id 3 "General error executing command".
#   - test machine B: 'get logs --name warnlog' (no dates) worked, but
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
        $raw = Invoke-ErmmProcess $Arguments
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
        # (observed behaviour on test machine B, not documented by ESET).
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
# 7. Fixes and diagnosis for protection-status items
# ---------------------------------------------------------------------------
# a) Detection engine / modules not updated -> FIX with -Fix: start an update,
#    wait for update-status to report a NEW attempt, then re-read protection
#    status. Only one update may run at a time (ESET: error 4 "Task already
#    running"), which is fine - we then just wait for that one.
if ($UpdateLine) {
    if (-not $Fix) {
        Update-Finding $UpdateLine "$UpdateLine - TRMM will run an ESET update once this check runs with -Fix."
    }
    elseif (-not (Test-FixTime)) {
        Update-Finding $UpdateLine "$UpdateLine - update skipped this run (time budget); tried next run."
    }
    elseif (-not (($ugate = Reserve-FixAttempt 'update' $MaxUpdatesPerDay).Allowed)) {
        Update-Finding $UpdateLine "$UpdateLine - update NOT retried: $($ugate.Reason)"
    }
    else {
        $Info.Add("Fix attempt: $($ugate.Reason).")
        $before = Invoke-Ermm @('get', 'update-status')
        [void](Invoke-ErmmProcess @('start', 'update'))
        $deadline = (Get-Date).AddSeconds($UpdateWaitSeconds); $us = $null
        do {
            Start-Sleep -Seconds 10
            $us = Invoke-Ermm @('get', 'update-status')
        } while ((Get-Date) -lt $deadline -and (-not $us -or ($before -and $us.last_update_time -eq $before.last_update_time)))
        # Is the status item gone now?
        $stillThere = $true
        $pt = Invoke-ErmmProcess @('get', 'protection-status')
        try {
            $pj = $pt | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $pj.error) {
                $stillThere = [bool]($pj.result.statuses | Where-Object { "Protection status: [$($_.id)] $($_.description) (status=$($_.status), priority=$($_.priority))" -eq $UpdateLine })
            } elseif ($pj.error.id -eq 3) { $stillThere = $false }   # error 3 = green (see section 2)
        } catch { }
        if (-not $stillThere -and $us -and $us.last_update_result -eq 'success') {
            Clear-Finding $UpdateLine
            $Info.Add("FIXED: ran an ESET update (result success at $($us.last_update_time)); cleared: $UpdateLine")
        } else {
            Update-Finding $UpdateLine "$UpdateLine - ran an ESET update: result '$($us.last_update_result)' at '$($us.last_update_time)', status still present."
        }
    }
}

# b) LiveGrid unreachable -> DIAGNOSE (read-only, always): can this machine
#    resolve and reach ESET's LiveGrid servers on the ports ESET lists in KB332
#    (TCP 80 and TCP/UDP 53535)? This is a network/firewall/proxy problem, so the
#    script can't fix it - it says which test failed. UDP isn't testable this way.
function Test-Tcp([string]$HostName, [int]$Port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try { return ($c.ConnectAsync($HostName, $Port).Wait(3000) -and $c.Connected) }
    catch { return $false }
    finally { $c.Close() }
}
if ($LiveGridLine) {
    $tests = @()
    foreach ($h in @('h1-c01.eset.com', 'a.c.eset.com')) {
        try { [void][System.Net.Dns]::GetHostAddresses($h); $tests += "DNS $h ok" }
        catch { $tests += "DNS $h FAILED" }
    }
    foreach ($t in @(@('h1-c01.eset.com', 53535), @('h1-c01.eset.com', 80), @('a.c.eset.com', 80))) {
        $ok = Test-Tcp $t[0] $t[1]
        $tests += "TCP $($t[0]):$($t[1]) $(if ($ok) { 'open' } else { 'BLOCKED' })"
    }
    $hint = if ($tests -match 'FAILED|BLOCKED') { "Allow outbound to ESET LiveGrid (KB332: TCP 80, TCP/UDP 53535) on the firewall/proxy." }
            else { "TCP tests passed - may be UDP 53535 or an intermittent outage; recheck next run." }
    Update-Finding $LiveGridLine "$LiveGridLine - not fixable from TRMM (network). Tests: $($tests -join '; '). $hint"
}

# c) Push Notification Service unreachable -> network/proxy; ESET's KB8207 gives
#    the fix for the ESET Bridge/VA proxy, no endpoint hostnames, so report only.
if ($PushLine) {
    Update-Finding $PushLine "$PushLine - network/proxy issue, not fixable from TRMM (ESET KB8207 if traffic goes through an ESET proxy)."
}
# d) Restart required -> hand it to the Reboot Nag with ESET-specific wording (Ethan 2026-10-26:
#    "if a reboot is needed can it trigger a differently worded nag"). The nag
#    (TRMM/Reboot Nag/Invoke-RebootNag.ps1) only watches Windows' own pending-reboot flags, so we
#    leave it a request file in its folder; it then shows OUR wording with ONE postpone
#    (a reminder $RestartPostponeHours h later, then a permanent window) and deletes the request once the
#    PC has restarted. If ESET STILL asks after a restart it is a fault, not an update: we alert and stop nagging.
#    Done only when ALL of these hold, otherwise the alert stays exactly as before:
#      - -Fix is on (this writes a file on the machine, so it is a "fix");
#      - the PC is a workstation (ProductType 1) - servers are never nagged;
#      - the nag is really running here: its heartbeat.txt is under 3 hours old.
$NagRequestFile = Join-Path (Join-Path $NagDir 'requests') 'eset-restart.json'
# When we first asked this PC to restart (our own record; the nag deletes its request after a restart,
# so this is what lets us notice "restarted, but ESET still asks"). Valid only if readable.
$HandoffFile = Join-Path $StateDir 'restart-handoff.json'
$handoff = $null
if (Test-Path $HandoffFile) { try { $handoff = Get-Content $HandoffFile -Raw | ConvertFrom-Json } catch { $handoff = $null } }
if ($handoff -and -not $handoff.Epoch) { $handoff = $null }
# Last boot as unix seconds, to compare with the time we asked.
$bootEpoch = $TestBootEpoch
if (-not $bootEpoch) { try { $bootEpoch = ([DateTimeOffset](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUnixTimeSeconds() } catch { } }
# Time of the current request: an existing one (asked since the last boot) keeps its original time.
$reqEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
# $handoff    = we asked AFTER the last boot (a request still waiting for a restart).
# $handoffOld = we asked BEFORE the last boot (the PC has restarted since).
$handoffOld = $null
if ($handoff -and ([long]$handoff.Epoch) -gt $bootEpoch) { $reqEpoch = [long]$handoff.Epoch }
elseif ($handoff) { $handoffOld = $handoff; $handoff = $null }
if ($RestartLine) {
    $pt = $TestProductType
    if (-not $pt) { try { $pt = [int](Get-CimInstance Win32_OperatingSystem).ProductType } catch { $pt = 0 } }
    $hb = Join-Path $NagDir 'heartbeat.txt'
    $nagAlive = $false
    if (Test-Path $hb) {
        try {
            $hbEpoch  = [long]((Get-Content $hb -Raw).Trim())
            $nagAlive = (([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $hbEpoch) -lt 10800)
        } catch { }
    }
    if ($pt -ne 1) {
        Update-Finding $RestartLine "$RestartLine - the server needs a restart to finish ESET changes (servers are not nagged; restart at a quiet time)."
    }
    elseif (-not $nagAlive) {
        Update-Finding $RestartLine "$RestartLine - the PC needs a restart to finish ESET changes (the Reboot Nag is not running on this PC, so nobody is prompted)."
    }
    elseif (-not $Fix) {
        Update-Finding $RestartLine "$RestartLine - the PC needs a restart; with -Fix the Reboot Nag will be asked to prompt the user."
    }
    elseif ($handoffOld) {
        # We asked for a restart, the PC HAS restarted since, and ESET still asks for one. So this is
        # not a pending update - something is wrong (Ethan 2026-10-26: "it may be due to an issue").
        # Asking the user to restart again would just loop, so do not nag: raise the alert instead.
        # A short grace period after boot avoids alerting while ESET is still starting up.
        $minsSinceBoot = [math]::Round(([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $bootEpoch) / 60)
        if ($minsSinceBoot -lt $PostRestartGraceMinutes) {
            Clear-Finding $RestartLine
            $Info.Add("ESET still reports a restart is needed, but the PC only restarted $minsSinceBoot min ago - waiting up to $PostRestartGraceMinutes min before treating it as a fault.")
        } else {
            Update-Finding $RestartLine "$RestartLine - ESET STILL asks for a restart $minsSinceBoot min after the PC restarted (it was asked to restart earlier). Another restart is unlikely to help: this looks like a fault, not a pending update. Check the ESET product/logs on this PC. The user is not being nagged again."
        }
    }
    else {
        # Wording shown to the user (this is the text Ethan asked to be different from the
        # Windows-update wording). {DAY} is replaced by the nag with the day number.
        # Ethan 2026-10-26: ESET restarts get ONE postpone (a reminder 4 hours later), after that the
        # window stays until the PC restarts; and the restart may be needed because of a PROBLEM,
        # not just an update, so the wording must not say "to finish an update".
        $request = [ordered]@{
            Source           = 'ESET'
            Epoch            = $reqEpoch
            Title            = 'Security software restart required'
            PostponeOnce     = $true            # nag: one postpone, then permanent (see Invoke-RebootNag header)
            PostponeHours    = $RestartPostponeHours
            Message          = "Your computer's security software (ESET) needs a restart to complete an update or fix a problem.`r`n`r`nPlease save your work and restart as soon as you can.`r`nThis can be postponed once, for $RestartPostponeHours hours."
            PermanentMessage = "Your computer's security software (ESET) still needs a restart.`r`n`r`nThis can no longer be postponed.`r`nPlease save your work and restart as soon as possible."
            ShutdownComment  = 'Restarting for security software (ESET).'
        }
        try {
            $reqDir = Split-Path $NagRequestFile
            if (-not (Test-Path $reqDir)) { New-Item -ItemType Directory -Path $reqDir -Force | Out-Null }
            [System.IO.File]::WriteAllText($NagRequestFile, ($request | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
            # Remember when we first asked, so we can tell later whether the PC restarted since.
            # Written only for a NEW request; an existing one keeps its original time.
            if (-not $handoff) {
                if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
                [System.IO.File]::WriteAllText($HandoffFile, (@{ Epoch = $reqEpoch } | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
            }
            $hoursAsked = [math]::Round(([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $reqEpoch) / 3600, 1)
            if ($hoursAsked -lt $RestartAlertAfterHours) {
                Clear-Finding $RestartLine
                $Info.Add("ESET needs a restart - handed to the Reboot Nag with ESET wording (one postpone of $RestartPostponeHours h, then the window stays); asked $hoursAsked h ago, alert after $RestartAlertAfterHours h.")
            } else {
                Update-Finding $RestartLine "$RestartLine - the user has been asked to restart for $hoursAsked h (one postpone, then a permanent window) and the PC still has not restarted."
            }
        } catch {
            Update-Finding $RestartLine "$RestartLine - the PC needs a restart; could not leave the nag request ($($_.Exception.Message))."
        }
    }
}
elseif (Test-Path $NagRequestFile) {
    # ESET no longer asks for a restart (cleared without one): withdraw our request so the PC
    # isn't nagged for nothing. Only our own file (Source ESET) is removed.
    try { if ((Get-Content $NagRequestFile -Raw | ConvertFrom-Json).Source -eq 'ESET') { Remove-Item $NagRequestFile -Force } } catch { }
}
# ESET no longer asks for a restart: forget when we asked, so the next restart request starts fresh.
if (-not $RestartLine -and (Test-Path $HandoffFile)) { Remove-Item $HandoffFile -Force -ErrorAction SilentlyContinue }
# e) Protection module disabled/paused -> settings change; do it with an ESET
#    PROTECT policy (ermm 'set configuration' needs an exported config file).
if ($ModuleLine) {
    Update-Finding $ModuleLine "$ModuleLine - re-enable it with an ESET PROTECT policy for this customer."
}

# ---------------------------------------------------------------------------
# Output summary and exit code.
# Critical beats warning beats OK. Output is kept plain text so it reads well
# in RMM check history and in any ticket it generates.
# ---------------------------------------------------------------------------
# Mute step (see the MUTE BY LICENCE TYPE note at the top): move every finding
# except the $KeepAlways threat ones into $Muted, so they print but don't alert.
$Muted = @()
if ($MuteThisClient) {
    $keptC  = @($Critical | Where-Object { $_ -match $KeepAlways })
    $keptW  = @($Warning  | Where-Object { $_ -match $KeepAlways })
    $Muted  = @($Critical | Where-Object { $_ -notmatch $KeepAlways } | ForEach-Object { "was CRIT: $_" }) +
              @($Warning  | Where-Object { $_ -notmatch $KeepAlways } | ForEach-Object { "was WARN: $_" })
    $Critical.Clear(); foreach ($t in $keptC) { $Critical.Add($t) }
    $Warning.Clear();  foreach ($t in $keptW) { $Warning.Add($t) }
}

if ($Critical.Count -gt 0) {
    Write-Output "CRITICAL: $($Critical.Count) critical, $($Warning.Count) warning finding(s) on $env:COMPUTERNAME"
    $Critical | ForEach-Object { Write-Output "  [CRIT] $_" }
    $Warning  | ForEach-Object { Write-Output "  [WARN] $_" }
    $Info     | ForEach-Object { Write-Output "  [INFO] $_" }
    $Muted    | ForEach-Object { Write-Output "  [MUTED] $_" }
    Stop-Check 2
}
elseif ($Warning.Count -gt 0) {
    Write-Output "WARNING: $($Warning.Count) finding(s) on $env:COMPUTERNAME"
    $Warning | ForEach-Object { Write-Output "  [WARN] $_" }
    $Info    | ForEach-Object { Write-Output "  [INFO] $_" }
    $Muted   | ForEach-Object { Write-Output "  [MUTED] $_" }
    Stop-Check 1
}
else {
    if ($Muted.Count -gt 0) {
        Write-Output "OK (muted): $($Muted.Count) ESET finding(s) not alerted on $env:COMPUTERNAME - alerting is muted for $ClientLicType clients."
    } else {
        Write-Output "OK: ESET healthy on $env:COMPUTERNAME"
    }
    $Info  | ForEach-Object { Write-Output "  [INFO] $_" }
    $Muted | ForEach-Object { Write-Output "  [MUTED] $_" }
    Stop-Check 0
}
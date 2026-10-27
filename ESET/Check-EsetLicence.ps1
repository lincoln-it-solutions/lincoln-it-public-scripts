<#
.SYNOPSIS
    TRMM script check: is this machine's ESET product activated with the licence
    its client should be on? MSP -> alert to activate in the ESET PROTECT portal.
    EBA/NFR -> TRMM activates it with the key (only with -Apply).

.DESCRIPTION
    Reads two TRMM CLIENT custom fields, passed in as environment variables
    (set these in the TRMM script's Environment vars, NOT as arguments, so the
    activation key isn't shown in the script's argument list):
        ESET_LICENCE_TYPE={{client.ESET Licence Type}}     MSP / EBA / NFR
        ESET_LICENCE={{client.ESET Licence}}               "<public ID> | <key>"
                                                           (MSP may be just "<public ID>")

    Compares them with what the machine reports via ESET's own RMM tool:
        ermm.exe get license-info   -> type, public_id, seat_name, expiration_state
        https://help.eset.com/ees/13/en-US/rmm_json_commands_license.html
    ("type":"MSP" and a top-level "public_id" confirmed live on MSP seats at two
    clients, 2026-10-25.)

    What happens when the machine is NOT on the expected licence:
      MSP      ESET's MSP portal does not show full activation keys, so TRMM
               cannot activate these. The check alerts with "activate it in the
               ESET PROTECT portal" (Product Activation task with the customer's
               licence - ESET's documented MSP method:
               https://help.eset.com/msp_getting_started/en-INT/protect_automated_activation.html).
      EBA/NFR  TRMM activates it itself (Ethan, 2026-10-26), but ONLY when the
               script is run with -Apply:
                 ermm.exe start activation --key <key>
                 https://help.eset.com/ees/13/en-US/rmm_json_commands_start_activation.html
               then waits for ermm.exe get activation-status ("success" /
               "running" / "failure"):
                 https://help.eset.com/ees/13/en-US/rmm_json_commands_activation_status.html
               and re-reads license-info. The key is only proven right if the
               machine then reports the public ID from the field.
               Without -Apply it only reports what it would do.

    Exit codes (real ones, via SetShouldExit - see Stop-Check), matching the
    ESET monitor's alert setup (Ethan 2026-10-25: real criticals = Error,
    warnings = Warning, "RMM not answering" = Info):
      0  OK: on the expected licence; or ESET not installed / unmanaged (not ours)
      1  Warning: on a different licence; client fields missing/invalid;
                  EBA/NFR activation needed but -Apply not set
      2  Error:   not activated at all; activation attempted and failed; or the
                  key activated a DIFFERENT licence than the field's public ID
      3  Info:    ESET RMM (ermm.exe) not answering, so the licence can't be read

.PARAMETER Apply
    EBA/NFR only: actually run the activation. Without it the check reports only.

.NOTES
    Not run against a real machine with -Apply yet - pilot on one EBA machine first.
    Ethan's scripting rule: comments explain what is done and why.
#>

param(
    # EBA/NFR: really activate. Off by default so adding the check changes nothing.
    [switch]$Apply,

    # Seconds any single ermm.exe call may run before it is stopped
    # (same safeguard and default as Monitor-ESET.ps1).
    [int]$ErmmTimeoutSeconds = 30,

    # After starting an activation, how long to wait for it to finish.
    [int]$ActivationWaitSeconds = 90,

    # TEST HOOKS ONLY (used to test this script off-Windows with a fake ermm).
    # Leave empty in TRMM: the script then finds ermm.exe and checks the
    # Windows uninstall entries itself.
    [string]$ErmmPath = '',
    [switch]$SkipInstallChecks
)

# ---------------------------------------------------------------------------
# Exit code helper.
# WHY: the TRMM Windows agent runs scripts without -File, so a plain "exit 2"
# reaches TRMM as 1. SetShouldExit passes the real code through (tested on
# Steve-Win11 2026-10-20; same helper as Monitor-ESET.ps1).
# ---------------------------------------------------------------------------
function Stop-Check([int]$Code) {
    $host.SetShouldExit($Code)
    exit $Code
}

# Hide all but the last 4 characters of a key in anything we print.
function Hide-Key([string]$Key) {
    if (-not $Key) { return '(none)' }
    if ($Key.Length -le 4) { return '****' }
    return ('****-****-****-****-' + $Key.Substring($Key.Length - 4))
}

# Licence types whose key is optional because they're activated in the ESET
# PROTECT portal, not by TRMM (Ethan, 2026-10-26: MSP only).
$KeyOptionalTypes = @('MSP')

# What ermm reports as "type" for each dropdown option, all confirmed live:
# MSP -> "MSP", NFR -> "NFR" (Steve-Win11), EBA -> "PAID" (full census
# 2026-10-26: every EBA machine at 13 clients reported "PAID").
$ExpectedErmmType = @{ 'MSP' = 'MSP'; 'NFR' = 'NFR'; 'EBA' = 'PAID' }

# ---------------------------------------------------------------------------
# 1. Is ESET installed and managed by us? Same rules as Monitor-ESET.ps1 so
#    both checks agree on what is "ours":
#    - no ESET product          -> OK, nothing to check
#    - no ESET Management Agent -> unmanaged (e.g. client's own licence) -> OK
# ---------------------------------------------------------------------------
$ProductFolders = @(
    "$env:ProgramFiles\ESET\ESET Security",
    "$env:ProgramFiles\ESET\ESET Server Security",
    "$env:ProgramFiles\ESET\ESET File Security"
)

if ($ErmmPath) {
    $Ermm = $ErmmPath
} else {
    $Ermm = $ProductFolders | ForEach-Object { Join-Path $_ 'ermm.exe' } |
            Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $SkipInstallChecks) {
    # Read each uninstall entry on its own. WHY: on one client PC (2026-10-26)
    # one malformed entry made a single wildcard Get-ItemProperty call throw
    # "Specified cast is not valid" and return NOTHING, so the ESET Management
    # Agent wasn't seen and the machine was wrongly skipped as "unmanaged".
    # Per-key try/catch means one bad entry only loses that one entry.
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
    $MgmtAgent = $EsetInstalls | Where-Object { $_.DisplayName -match '^ESET (Management|Remote Administrator) Agent' } |
                 Select-Object -First 1

    if (-not $Ermm) {
        Write-Output "OK: no ESET business product with ermm.exe on $env:COMPUTERNAME - licence not checked."
        Stop-Check 0
    }
    if (-not $MgmtAgent) {
        Write-Output "OK: ESET is unmanaged on $env:COMPUTERNAME (no ESET Management Agent) - licence not checked."
        Stop-Check 0
    }
}

# ---------------------------------------------------------------------------
# 2. Read and validate the client fields (same rules as eset_licence_fields.py).
#    A missing or broken field is a Warning on every machine of that client,
#    so a half-filled client can't go unnoticed.
# ---------------------------------------------------------------------------
$LicType = ("$env:ESET_LICENCE_TYPE").Trim().ToUpper()
$LicRaw  = ("$env:ESET_LICENCE").Trim()

# TRMM leaves an unfilled custom field as an empty string. Treat a literal,
# unresolved placeholder the same way, in case the variable wasn't substituted.
if ($LicType -match '^\{\{') { $LicType = '' }
if ($LicRaw  -match '^\{\{') { $LicRaw  = '' }

# The 'ESET Licence' field's default is an EXAMPLE showing the format
# (XXX-XXX-XXX | XXXX-XXXX-XXXX-XXXX-XXXX). TRMM passes a field's default to
# scripts when the client has no value (tacticalrmm/utils.py get_db_value), so
# the example means "not filled in" - never a real licence.
$ExampleLicence = $false
if ($LicRaw.Split('|')[0].Trim().ToUpper() -eq 'XXX-XXX-XXX') { $LicRaw = ''; $ExampleLicence = $true }

if (-not $LicType) {
    Write-Output "WARNING: client field 'ESET Licence Type' is not set for this client - can't check the ESET licence on $env:COMPUTERNAME."
    Write-Output "Set it in TRMM (Clients > Edit) to MSP, EBA or NFR."
    Stop-Check 1
}
if (@('MSP', 'EBA', 'NFR') -notcontains $LicType) {
    Write-Output "WARNING: client field 'ESET Licence Type' is '$LicType' - must be MSP, EBA or NFR."
    Stop-Check 1
}
if (-not $LicRaw) {
    $why = if ($ExampleLicence) { "still holds the example value, not a real licence" } else { "is empty" }
    Write-Output "WARNING: client field 'ESET Licence' $why for this $LicType client - can't check the ESET licence on $env:COMPUTERNAME."
    Write-Output "Fill it in TRMM (Clients > Edit) as '<public ID> | <activation key>' - MSP clients can give just the public ID."
    Stop-Check 1
}

$parts = @($LicRaw.Split('|') | ForEach-Object { $_.Trim().ToUpper() })
if ($parts.Count -eq 1) { $parts += '' }
if ($parts.Count -ne 2) {
    Write-Output "WARNING: client field 'ESET Licence' must be '<public ID> | <activation key>' (one '|')."
    Stop-Check 1
}
$WantId  = $parts[0]
$WantKey = $parts[1]
if ($WantId -notmatch '^[A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{3}$') {
    Write-Output "WARNING: public ID '$WantId' in client field 'ESET Licence' is not in the form XXX-XXX-XXX."
    Stop-Check 1
}
if ($WantKey -and $WantKey -notmatch '^[A-Z0-9]{4}(-[A-Z0-9]{4}){4}$') {
    Write-Output "WARNING: the activation key in client field 'ESET Licence' is not in the form XXXX-XXXX-XXXX-XXXX-XXXX."
    Stop-Check 1
}
$KeyRequired = ($KeyOptionalTypes -notcontains $LicType)

# ---------------------------------------------------------------------------
# 3. Helper: run ermm.exe with a hard time limit and return the parsed JSON.
#    Same approach as Monitor-ESET.ps1 (a hung ermm call must not hang the
#    whole check). Returns @{ ok; result; error; raw }.
# ---------------------------------------------------------------------------
function Invoke-Ermm([string[]]$Arguments) {
    $argString = ($Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Ermm
    $psi.Arguments = $argString
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    try {
        [void]$proc.Start()
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($ErmmTimeoutSeconds * 1000)) {
            try { $proc.Kill() } catch { }
            return @{ ok = $false; error = "did not answer within $ErmmTimeoutSeconds s" }
        }
        [void]$outTask.Wait(5000); [void]$errTask.Wait(1000)
        $raw = ($outTask.Result + $errTask.Result).Trim()
    } catch {
        return @{ ok = $false; error = "could not start: $($_.Exception.Message)" }
    } finally {
        $proc.Dispose()
    }
    try {
        $json = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return @{ ok = $false; error = 'gave non-JSON output'; raw = $raw }
    }
    if ($json.error) {
        # e.g. error 6 = ESET RMM disabled in the product's advanced settings.
        return @{ ok = $false; error = "returned error: $($json.error | ConvertTo-Json -Compress)"; raw = $raw }
    }
    return @{ ok = $true; result = $json.result; raw = $raw }
}

# Read the licence as the machine sees it right now.
function Get-MachineLicence {
    $r = Invoke-Ermm @('get', 'license-info')
    if (-not $r.ok) { return $r }
    return @{
        ok        = $true
        public_id = ("$($r.result.public_id)").Trim().ToUpper()
        type      = ("$($r.result.type)").Trim().ToUpper()
        seat      = "$($r.result.seat_name)"
        state     = "$($r.result.expiration_state)"
    }
}

# Does what the machine reports match the client fields?
function Test-Match($m) {
    if ($m.public_id -ne $WantId) { return $false }
    $expType = $ExpectedErmmType[$LicType]
    if ($expType -and $m.type -ne $expType) { return $false }
    return $true
}

function Describe($m) {
    if (-not $m.public_id) { return 'NOT ACTIVATED (no licence public ID reported)' }
    return "licence $($m.public_id) (type $($m.type), seat '$($m.seat)', expiry state '$($m.state)')"
}

# ---------------------------------------------------------------------------
# 4. Compare.
# ---------------------------------------------------------------------------
$m = Get-MachineLicence
if (-not $m.ok) {
    Write-Output "INFO: can't read the ESET licence on $env:COMPUTERNAME - ermm get license-info $($m.error)."
    if ($m.raw) { Write-Output "  ermm output: $($m.raw)" }
    Stop-Check 3
}

$expected = "$LicType licence $WantId"
if (Test-Match $m) {
    Write-Output "OK: $env:COMPUTERNAME is on the expected $expected - $(Describe $m)."
    Stop-Check 0
}

$notActivated = -not $m.public_id
$problem = "$env:COMPUTERNAME should be on the $expected but is $(Describe $m)"

# --- MSP: TRMM can't activate (no key available). Alert to use the portal. ---
if ($LicType -eq 'MSP') {
    $level = if ($notActivated) { 'ERROR' } else { 'WARNING' }
    Write-Output "${level}: $problem."
    Write-Output "ACTION: activate it in the ESET PROTECT portal - run a Product Activation task on $env:COMPUTERNAME with this customer's MSP licence $WantId."
    Write-Output "  (MSP licences are activated from the portal; TRMM has no key for them.)"
    if ($notActivated) { Stop-Check 2 } else { Stop-Check 1 }
}

# --- EBA / NFR: TRMM activates with the key. ---
if (-not $WantKey) {
    # Field rules say EBA/NFR need a key; say so plainly rather than guess.
    Write-Output "WARNING: $problem."
    Write-Output "Can't activate: client field 'ESET Licence' has no activation key, which $LicType licences need."
    Stop-Check 1
}

if (-not $Apply) {
    $level = if ($notActivated) { 'ERROR' } else { 'WARNING' }
    Write-Output "${level}: $problem."
    Write-Output "Would activate with key $(Hide-Key $WantKey) - not done because the check runs without -Apply."
    if ($notActivated) { Stop-Check 2 } else { Stop-Check 1 }
}

Write-Output "$problem - activating with key $(Hide-Key $WantKey)..."
$start = Invoke-Ermm @('start', 'activation', '--key', $WantKey)
if (-not $start.ok) {
    Write-Output "ERROR: ermm start activation $($start.error)."
    Stop-Check 2
}

# Wait for the activation to finish ("running" -> "success"/"failure").
$deadline = (Get-Date).AddSeconds($ActivationWaitSeconds)
$status = ''
do {
    Start-Sleep -Seconds 5
    $st = Invoke-Ermm @('get', 'activation-status')
    if ($st.ok) { $status = "$($st.result.status)".ToLower() }
} while ($status -eq 'running' -and (Get-Date) -lt $deadline)

$after = Get-MachineLicence
if ($after.ok -and (Test-Match $after)) {
    Write-Output "OK: activated - $env:COMPUTERNAME is now on the expected $expected ($(Describe $after))."
    Stop-Check 0
}
if ($status -eq 'failure') {
    Write-Output "ERROR: activation with key $(Hide-Key $WantKey) failed (ermm activation-status: failure). Machine is $(if ($after.ok) { Describe $after } else { 'unreadable' })."
    Stop-Check 2
}
if ($status -eq 'running') {
    Write-Output "WARNING: activation still running after $ActivationWaitSeconds s - the next check run will confirm."
    Stop-Check 1
}
if ($after.ok -and $after.public_id -and $after.public_id -ne $WantId) {
    # The key worked but belongs to another licence: the field's key and public ID don't match.
    Write-Output "ERROR: the key in client field 'ESET Licence' activated licence $($after.public_id), not $WantId - the key and public ID in the field don't belong together. Fix the field."
    Stop-Check 2
}
Write-Output "ERROR: after activation $env:COMPUTERNAME is $(if ($after.ok) { Describe $after } else { 'unreadable' }) (activation-status '$status')."
Stop-Check 2

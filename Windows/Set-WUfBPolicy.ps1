<#
.SYNOPSIS
    Puts a Windows workstation's patching under Windows Update for Business
    (WUfB) local policy instead of Tactical RMM's built-in patching.

.DESCRIPTION
    WHY THIS EXISTS
    The TRMM agent writes AUOptions = 1 under
    HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU when it is
    installed, which stops Windows installing updates by itself so that TRMM's
    patch policy can do it (rmmagent source: agent/install.go calls
    PatchMgmnt(true); agent/agent_windows.go writes the value). The TRMM server
    never sends that setting again afterwards (no "patchmgmt" call exists in the
    tacticalrmm server code), so it only happens at agent install. That is why
    this script is meant to run as a RECURRING task: every newly installed agent
    switches Windows' own updating off again until this script puts it back.

    WHAT IT SETS (all under HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate)
      DeferQualityUpdates              = 1
      DeferQualityUpdatesPeriodInDays  = -QualityDeferralDays (default 14, Microsoft allows 0-35)
      TargetReleaseVersion             = 1
      ProductVersion                   = "Windows 11"  (or "Windows 10" on Windows 10)
      TargetReleaseVersionInfo         = -TargetFeatureVersion (default 26H2) on Windows 11,
                                         -Windows10Version (default 22H2) on Windows 10
                                         so Windows 10 is NEVER offered Windows 11 by this script
      ExcludeWUDriversInQualityUpdate  = 1, only if -ExcludeDrivers is passed (otherwise left alone)
    and under ...\WindowsUpdate\AU
      NoAutoUpdate                     = 0   (automatic updates on)
      AUOptions                        = 4   (download automatically and schedule the install),
                                             replacing TRMM's AUOptions = 1
      ScheduledInstallDay              = 0   (every day; required for AUOptions 4)
      ScheduledInstallTime             = -ScheduledInstallHour (default 12); required for AUOptions 4
      NoAutoRebootWithLoggedOnUsers    = 1   (a logged-on user decides when to restart; restarts
                                             are left to Invoke-RebootNag.ps1, no Windows deadline)

    WHAT IT DOES NOT DO
      - It does not set any restart deadline (Ethan's choice 2026-10-25: reboot nag only).
      - It does not delete any other policy values. Anything else it finds under
        the WindowsUpdate keys is listed in the output so you can see it.
      - It does nothing on Windows Server (scope chosen 2026-10-25: workstations only).
      - It does not overwrite settings on a device that has Intune (MDM) Update
        policies applied, unless -Force is passed, because MDM policy and these
        local registry policies would then disagree.

    MODES
      Default (no -Apply): REPORT ONLY. Compares the device with the wanted
      values, prints every difference and changes nothing.
      -Apply: writes the wanted values, then reads them back to confirm.

    EXIT CODES (passed to TRMM with Stop-Check, see below)
      0 = device already matches (or was changed with -Apply and verified), or out of scope (server)
      1 = report only: differences found, nothing changed
      2 = error (not admin, write failed, read-back mismatch)
      3 = skipped: Intune Update policy present and -Force not passed (Info)

.PARAMETER Apply
    Write the settings. Without it the script only reports.

.PARAMETER QualityDeferralDays
    Days to hold back monthly quality updates after release. Default 14
    (Ethan's choice 2026-10-25). Microsoft's allowed range is 0-35.

.PARAMETER TargetFeatureVersion
    Windows 11 feature version to stay on. Default 26H2 (Ethan's choice 2026-10-25).
    A device on an older version WILL be offered this version.

.PARAMETER Windows10Version
    Version Windows 10 devices are held on. Default 22H2 (the last Windows 10 release).

.PARAMETER ScheduledInstallHour
    Hour (0-23) for the AUOptions 4 install schedule. Default 12. This is MY
    choice, not Ethan's: midday was picked because workstations are more likely
    to be switched on then than overnight. Change it if you prefer another hour.

.PARAMETER ExcludeDrivers
    Also stop drivers coming down with quality updates. Off by default, so the
    device keeps whatever driver behaviour it has now.

.PARAMETER Force
    Apply even when Intune Update policies are present.

.NOTES
    Sources:
      WUfB deferral and driver values, ranges 0-35 / 0-365, "applies to" list:
        https://learn.microsoft.com/en-us/windows/deployment/update/waas-configure-wufb
      TargetReleaseVersion + ProductVersion (must be set together), registry key,
      and AllowAutoUpdate behaviour descriptions (Policy CSP - Update):
        https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update
      Value NAMES TargetReleaseVersion (DWORD 1) / ProductVersion (string) /
      TargetReleaseVersionInfo (string): the Microsoft CSP page gives the key but
      not the value names; the names here are from N-able's guide (third party):
        https://www.n-able.com/blog/how-to-stop-windows-11-update-in-the-registry-and-more
      NoAutoUpdate, AUOptions 2-5, ScheduledInstallDay/Time, NoAutoRebootWithLoggedOnUsers:
        https://learn.microsoft.com/zh-tw/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd939844(v=ws.10)
        (Microsoft's documented AUOptions range is 2-5, so TRMM's value 1 is outside it.)
      TRMM agent behaviour: https://github.com/amidaware/rmmagent (agent/install.go, agent/agent_windows.go)

    NOT VERIFIED: written without running on Windows (only a PowerShell syntax
    parse was done). The Intune detection path
    HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update is from my own
    knowledge, not a fetched Microsoft page. Run report-only on one test VM
    first and read the output.
#>

[CmdletBinding()]
param(
    [switch]$Apply,
    [ValidateRange(0, 35)][int]$QualityDeferralDays = 14,
    [ValidatePattern('^\d{2}H\d$')][string]$TargetFeatureVersion = '26H2',
    [ValidatePattern('^\d{2}H\d$')][string]$Windows10Version = '22H2',
    [ValidateRange(0, 23)][int]$ScheduledInstallHour = 12,
    [switch]$ExcludeDrivers,
    [switch]$Force
)

# Stop on unexpected errors so nothing fails silently.
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Exit code helper.
# WHY: the TRMM Windows agent runs scripts without -File, so a plain "exit 2"
# reaches TRMM as 1. SetShouldExit passes the real code through (same helper
# as Monitor-ESET.ps1 and the backup monitors, tested on Steve-Win11 2026-10-20).
# ---------------------------------------------------------------------------
function Stop-Check([int]$Code) {
    $host.SetShouldExit($Code)
    exit $Code
}

$WuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$AuKey = "$WuKey\AU"

try {
    # Opt-out: TRMM checkbox custom field "Exclude From Patching" on the Client or
    # Agent, passed as env vars WU_EXCLUDE_CLIENT / WU_EXCLUDE_AGENT. TRMM sends a
    # checkbox to PowerShell as the text "$True"/"$False" (tacticalrmm utils.py
    # format_shell_bool); a missing field means the env var is absent = not excluded.
    foreach ($exclVar in 'WU_EXCLUDE_CLIENT', 'WU_EXCLUDE_AGENT') {
        if ("$([Environment]::GetEnvironmentVariable($exclVar))" -match '^\$?true$|^1$') {
            Write-Output "EXCLUDED from patching ($exclVar is ticked). Nothing checked or changed."
            Stop-Check 0
        }
    }
    # 1. Must be admin to write HKLM policy keys (TRMM runs as SYSTEM, which is fine).
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Output 'ERROR: not running as administrator.'; Stop-Check 2 }

    # 2. Scope: workstations only. Win32_OperatingSystem.ProductType 1 = workstation,
    #    2 = domain controller, 3 = server.
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.ProductType -ne 1) {
        Write-Output "Out of scope: this is a server OS ($($os.Caption)). Nothing checked or changed."
        Stop-Check 0
    }

    # 3. Windows 11 vs Windows 10. Windows 11 builds start at 22000; Caption is
    #    not used because it is localised.
    $build = [int]$os.BuildNumber
    if ($build -ge 22000) { $product = 'Windows 11'; $target = $TargetFeatureVersion }
    else                  { $product = 'Windows 10'; $target = $Windows10Version }
    Write-Output "Device: $($os.Caption) build $build -> holding on $product $target"

    # 4. Intune check. If MDM Update policies are applied, local policy values could
    #    disagree with them, so stop unless told otherwise.
    $mdmKey = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
    $mdmValues = @()
    if (Test-Path $mdmKey) {
        $mdmValues = @((Get-Item $mdmKey).Property | Where-Object { $_ -notlike '*_ProviderSet' -and $_ -notlike '*_WinningProvider' })
    }
    if ($mdmValues.Count -gt 0 -and -not $Force) {
        Write-Output "SKIPPED: Intune Update policies are applied on this device ($($mdmValues -join ', ')). Pass -Force to apply anyway."
        Stop-Check 3
    }

    # 5. The wanted values: key, name, type, value. One list drives both the
    #    report and the write, so they can never disagree.
    $wanted = @(
        @{ Key = $WuKey; Name = 'DeferQualityUpdates';             Type = 'DWord';  Value = 1 }
        @{ Key = $WuKey; Name = 'DeferQualityUpdatesPeriodInDays'; Type = 'DWord';  Value = $QualityDeferralDays }
        @{ Key = $WuKey; Name = 'TargetReleaseVersion';            Type = 'DWord';  Value = 1 }
        @{ Key = $WuKey; Name = 'ProductVersion';                  Type = 'String'; Value = $product }
        @{ Key = $WuKey; Name = 'TargetReleaseVersionInfo';        Type = 'String'; Value = $target }
        @{ Key = $AuKey; Name = 'NoAutoUpdate';                    Type = 'DWord';  Value = 0 }
        @{ Key = $AuKey; Name = 'AUOptions';                       Type = 'DWord';  Value = 4 }
        @{ Key = $AuKey; Name = 'ScheduledInstallDay';             Type = 'DWord';  Value = 0 }
        @{ Key = $AuKey; Name = 'ScheduledInstallTime';            Type = 'DWord';  Value = $ScheduledInstallHour }
        @{ Key = $AuKey; Name = 'NoAutoRebootWithLoggedOnUsers';   Type = 'DWord';  Value = 1 }
    )
    if ($ExcludeDrivers) {
        $wanted += @{ Key = $WuKey; Name = 'ExcludeWUDriversInQualityUpdate'; Type = 'DWord'; Value = 1 }
    }

    # Helper: reads one value, $null if the key or value is missing.
    function Get-PolicyValue($Key, $Name) {
        if (-not (Test-Path $Key)) { return $null }
        $p = Get-ItemProperty -Path $Key -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $p) { return $null }
        return $p.$Name
    }

    # Helper: lists every wanted value that does not match the device.
    function Get-Differences {
        foreach ($w in $wanted) {
            $current = Get-PolicyValue $w.Key $w.Name
            if ("$current" -ne "$($w.Value)") {
                [pscustomobject]@{ Setting = "$($w.Key.Replace('HKLM:\SOFTWARE\Policies\Microsoft\Windows\',''))\$($w.Name)"
                                   Current = $(if ($null -eq $current) { '<not set>' } else { $current })
                                   Wanted  = $w.Value; Item = $w }
            }
        }
    }

    # 6. Report anything else under the keys, so unknown policy (GPO, old tools,
    #    restart deadlines) is visible. Nothing here is changed.
    $managed = $wanted | ForEach-Object { $_.Name }
    foreach ($k in $WuKey, $AuKey) {
        if (Test-Path $k) {
            $others = (Get-Item $k).Property | Where-Object { $managed -notcontains $_ }
            foreach ($o in $others) { Write-Output "  Other value (left alone): $($k.Replace('HKLM:\SOFTWARE\Policies\Microsoft\Windows\',''))\$o = $(Get-PolicyValue $k $o)" }
        }
    }

    $diffs = @(Get-Differences)
    if ($diffs.Count -eq 0) { Write-Output 'OK: device already matches the wanted settings.'; Stop-Check 0 }

    Write-Output "Differences ($($diffs.Count)):"
    $diffs | ForEach-Object { Write-Output ("  {0}: {1} -> {2}" -f $_.Setting, $_.Current, $_.Wanted) }

    # 7. Report-only mode stops here.
    if (-not $Apply) { Write-Output 'REPORT ONLY: nothing changed (run with -Apply to write).'; Stop-Check 1 }

    # 8. Write only the values that differ, creating keys as needed.
    foreach ($d in $diffs) {
        if (-not (Test-Path $d.Item.Key)) { New-Item -Path $d.Item.Key -Force | Out-Null }
        New-ItemProperty -Path $d.Item.Key -Name $d.Item.Name -PropertyType $d.Item.Type -Value $d.Item.Value -Force | Out-Null
    }

    # 9. Read back to prove the writes landed.
    $left = @(Get-Differences)
    if ($left.Count -gt 0) {
        Write-Output "ERROR: $($left.Count) value(s) still differ after writing:"
        $left | ForEach-Object { Write-Output ("  {0}: {1} (wanted {2})" -f $_.Setting, $_.Current, $_.Wanted) }
        Stop-Check 2
    }
    Write-Output "APPLIED: $($diffs.Count) value(s) written and verified. A domain GPO that sets the same values would overwrite these at its next refresh."
    Stop-Check 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Stop-Check 2
}

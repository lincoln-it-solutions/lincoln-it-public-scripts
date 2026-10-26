<#
.SYNOPSIS
    Server version of Set-WUfBPolicy.ps1: lets Windows Update DOWNLOAD updates on
    a server but never install them or restart by itself. Installing is done by
    Invoke-ServerPatching.ps1 (TRMM task, 03:00, in the server type's patching week).

.DESCRIPTION
    WHY "DOWNLOAD ONLY"
    Ethan 2026-10-25: WUfB for servers, but NO automatic restart. Microsoft
    describes the scheduled-install mode as "Auto install and restart at a
    specified time" (Policy CSP AllowAutoUpdate), so it cannot be used without
    restarts. AUOptions = 3 is documented as "Automatically download and notify
    of installation": Windows fetches the updates in advance (so the 03:00-05:00
    window is spent installing, not downloading) and does nothing else.

    WHAT IT SETS (HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU)
      NoAutoUpdate                  = 0   (automatic updates on)
      AUOptions                     = 3   (download automatically, notify to install)
                                          replaces TRMM's AUOptions = 1 set at agent install
      NoAutoRebootWithLoggedOnUsers = 1   (extra safety; restarts stay manual)

    NO DEFERRAL: Ethan chose "the patching week is the delay", so no
    DeferQualityUpdates values are written. If any are found they are listed
    (not removed), because they would hold updates back on top of the week.

    The same TRMM AUOptions=1 issue as workstations applies (rmmagent
    agent/install.go sets it at agent install only), so run this as a recurring task.

    EXIT CODES (Stop-Check)
      0 = matches (or applied and verified), or not a server
      1 = report only: differences found, nothing changed
      2 = error

.PARAMETER Apply
    Write the settings. Without it the script only reports.

.NOTES
    Sources:
      AUOptions 2-5 meanings, NoAutoUpdate, NoAutoRebootWithLoggedOnUsers:
        https://learn.microsoft.com/zh-tw/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd939844(v=ws.10)
      AllowAutoUpdate "Auto install and restart at a specified time":
        https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update
      WUfB applies to Windows Server 2016/2019/2022, quality updates only:
        https://learn.microsoft.com/en-us/windows/deployment/update/waas-configure-wufb
    NOT VERIFIED: not run on Windows (syntax parse only). Server 2025 is not
    in the list on Microsoft's page above.
#>

[CmdletBinding()]
param([switch]$Apply)

$ErrorActionPreference = 'Stop'

# Exit code helper: plain "exit 2" reaches TRMM as 1, SetShouldExit passes the
# real code (same helper as Monitor-ESET.ps1, tested on Steve-Win11 2026-10-20).
function Stop-Check([int]$Code) {
    $host.SetShouldExit($Code)
    exit $Code
}

$WuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$AuKey = "$WuKey\AU"

try {
    # Opt-out: TRMM checkbox custom field "Exclude From Patching" on the Client, Site
    # or Agent (site level added 2026-10-25), passed as env vars WU_EXCLUDE_CLIENT /
    # WU_EXCLUDE_SITE / WU_EXCLUDE_AGENT. TRMM sends a
    # checkbox to PowerShell as the text "$True"/"$False" (tacticalrmm utils.py
    # format_shell_bool); a missing field means the env var is absent = not excluded.
    foreach ($exclVar in 'WU_EXCLUDE_CLIENT', 'WU_EXCLUDE_SITE', 'WU_EXCLUDE_AGENT') {
        if ("$([Environment]::GetEnvironmentVariable($exclVar))" -match '^\$?true$|^1$') {
            Write-Output "EXCLUDED from patching ($exclVar is ticked). Nothing checked or changed."
            Stop-Check 0
        }
    }
    # Admin needed for HKLM policy keys (TRMM runs as SYSTEM).
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Output 'ERROR: not running as administrator.'; Stop-Check 2 }

    # Scope: servers only. ProductType 1 = workstation (handled by Set-WUfBPolicy.ps1),
    # 2 = domain controller, 3 = member server.
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.ProductType -eq 1) { Write-Output "Out of scope: workstation ($($os.Caption)); use Set-WUfBPolicy.ps1."; Stop-Check 0 }
    Write-Output "Server: $($os.Caption) build $($os.BuildNumber)"

    # One list drives both the report and the write.
    $wanted = @(
        @{ Key = $AuKey; Name = 'NoAutoUpdate';                  Type = 'DWord'; Value = 0 }
        @{ Key = $AuKey; Name = 'AUOptions';                     Type = 'DWord'; Value = 3 }
        @{ Key = $AuKey; Name = 'NoAutoRebootWithLoggedOnUsers'; Type = 'DWord'; Value = 1 }
    )

    # Reads one value, $null if the key or value is missing.
    function Get-PolicyValue($Key, $Name) {
        if (-not (Test-Path $Key)) { return $null }
        $p = Get-ItemProperty -Path $Key -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $p) { return $null }
        return $p.$Name
    }

    # Lists wanted values that don't match.
    function Get-Differences {
        foreach ($w in $wanted) {
            $current = Get-PolicyValue $w.Key $w.Name
            if ("$current" -ne "$($w.Value)") {
                [pscustomobject]@{ Setting = "AU\$($w.Name)"; Current = $(if ($null -eq $current) { '<not set>' } else { $current }); Wanted = $w.Value; Item = $w }
            }
        }
    }

    # Show (never change) anything else under the keys, e.g. deferrals or old GPO values.
    $managed = $wanted | ForEach-Object { $_.Name }
    foreach ($k in $WuKey, $AuKey) {
        if (Test-Path $k) {
            foreach ($o in (Get-Item $k).Property | Where-Object { $managed -notcontains $_ }) {
                $note = if ($o -like 'DeferQualityUpdates*') { '  <- holds updates back on top of the patching week' } else { '' }
                Write-Output "  Other value (left alone): $($k.Replace('HKLM:\SOFTWARE\Policies\Microsoft\Windows\',''))\$o = $(Get-PolicyValue $k $o)$note"
            }
        }
    }

    $diffs = @(Get-Differences)
    if ($diffs.Count -eq 0) { Write-Output 'OK: server already set to download-only.'; Stop-Check 0 }

    Write-Output "Differences ($($diffs.Count)):"
    $diffs | ForEach-Object { Write-Output ("  {0}: {1} -> {2}" -f $_.Setting, $_.Current, $_.Wanted) }
    if (-not $Apply) { Write-Output 'REPORT ONLY: nothing changed (run with -Apply to write).'; Stop-Check 1 }

    # Write only what differs, then read back to prove it landed.
    foreach ($d in $diffs) {
        if (-not (Test-Path $d.Item.Key)) { New-Item -Path $d.Item.Key -Force | Out-Null }
        New-ItemProperty -Path $d.Item.Key -Name $d.Item.Name -PropertyType $d.Item.Type -Value $d.Item.Value -Force | Out-Null
    }
    $left = @(Get-Differences)
    if ($left.Count -gt 0) {
        $left | ForEach-Object { Write-Output ("ERROR: {0} is {1}, wanted {2}" -f $_.Setting, $_.Current, $_.Wanted) }
        Stop-Check 2
    }
    Write-Output "APPLIED: $($diffs.Count) value(s) written and verified."
    Stop-Check 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Stop-Check 2
}

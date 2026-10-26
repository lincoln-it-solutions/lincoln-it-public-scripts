<#
.SYNOPSIS
    Uninstalls already-installed Windows updates that are on the blocked KB list
    AND flagged "|remove". Workstations only. Report-only unless -Apply.

.DESCRIPTION
    THE LIST
    Same Global Keystore list as Check-WindowsPatchStatus.ps1 ("wu_blocked_kbs",
    passed in as WU_BLOCKED_KBS={{global.wu_blocked_kbs}}). Only entries ending
    in "|remove" are uninstalled:
        KB5012345=broke printing          -> blocked (hidden) only
        KB5012345=broke printing|remove   -> blocked AND removed where installed

    WHY DISM, NOT WUSA
    Microsoft: "Running Windows Update Standalone Installer (wusa.exe) with the
    /uninstall switch on the combined package will not work because the combined
    package contains the SSU", and "To remove the LCU after installing the combined
    SSU and LCU package, use the DISM/Remove-Package command line option with the
    LCU package name". Servicing stack updates (SSUs) cannot be removed at all.
    This script uses Remove-WindowsPackage (the PowerShell form of
    DISM /Online /Remove-Package) for every KB, so there is one method only.

    HOW A KB IS MATCHED TO A PACKAGE
    DISM package names do not contain the KB number (e.g.
    Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.3165.1.8), so the script
    reads each installed update package's details and looks for the KB number in
    its Description. ASSUMPTION, NOT VERIFIED: that LCU packages carry the KB in
    their Description (e.g. "Fix for KB5012345"). If no package or more than one
    package matches, the script does NOT guess: it reports the KB as needing
    manual removal and exits 2.

    WHAT HAPPENS, IN ORDER, PER FLAGGED KB
      1. Is it installed? (Get-HotFix / Win32_QuickFixEngineering). No -> skip.
      2. Find exactly one matching update package (see above).
      3. Refuse if the package is a servicing stack update (cannot be removed).
      4. -Apply: Remove-WindowsPackage -Online -NoRestart. Never restarts the PC;
         Invoke-RebootNag.ps1 handles the restart.
    After removal, Windows Update will offer the KB again. Because the KB is
    still on the block list, Check-WindowsPatchStatus.ps1 -Apply hides it at its
    next run. Run that check soon after this script, or the KB may reinstall.

    EXIT CODES (passed to TRMM with Stop-Check)
      0 = nothing to remove (or out of scope: server)
      1 = report only: flagged KB(s) installed and would be removed
      2 = error: removal failed, KB could not be matched to one package, or SSU
      3 = removed, restart needed to finish (Info)

.PARAMETER Apply
    Actually uninstall. Without it, report only.

.NOTES
    Sources:
      Microsoft's KB5015811 wording on wusa and DISM, quoted in Microsoft Q&A:
        https://learn.microsoft.com/en-us/answers/a/931514
      Get-WindowsPackage / Remove-WindowsPackage -Online -NoRestart usage, and the
      warning that removing packages can make Windows unstable (third party):
        https://woshub.com/uninstall-windows-update-cmd-powershell/

    NOT VERIFIED: written without running on Windows (syntax parse only).
    Test on a VM: install a KB, flag it, run report-only, then -Apply.
#>

[CmdletBinding()]
param(
    [switch]$Apply,
    [string]$BlockedKbs = ''
)

$ErrorActionPreference = 'Stop'

# Exit code helper: plain "exit 2" reaches TRMM as 1, SetShouldExit passes the
# real code (same helper as Monitor-ESET.ps1, tested on Steve-Win11 2026-10-20).
function Stop-Check([int]$Code) {
    $host.SetShouldExit($Code)
    exit $Code
}

$errors = 0; $wouldRemove = 0; $removed = 0; $restart = $false

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
    # --- Admin needed for DISM (TRMM runs as SYSTEM, which is fine).
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Output 'ERROR: not running as administrator.'; Stop-Check 2 }

    # --- Scope: workstations only (ProductType 1), same as the other patching scripts.
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.ProductType -ne 1) { Write-Output "Out of scope: server OS ($($os.Caption))."; Stop-Check 0 }

    # --- Parse the list; keep only entries flagged "|remove". Same format rules as
    #     Check-WindowsPatchStatus.ps1 (TRMM scripts can't share code, so duplicated).
    if (-not $BlockedKbs) { $BlockedKbs = $env:WU_BLOCKED_KBS }
    $toRemove = @()
    foreach ($line in ("$BlockedKbs" -split '[;\r\n]+')) {
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        $kb, $reason = $line -split '=', 2
        $kb = $kb.Trim().ToUpper()
        if ($kb -notmatch '^KB\d{6,8}$') { Write-Output "WARNING: bad list entry '$line' ignored."; continue }
        if ("$reason" -match '\|\s*remove\s*$') { $toRemove += $kb }
    }
    if ($toRemove.Count -eq 0) { Write-Output 'Nothing flagged for removal in the list.'; Stop-Check 0 }
    Write-Output "Flagged for removal: $($toRemove -join ', ')"

    # --- Only the KBs actually installed here need any work.
    $installed = @($toRemove | Where-Object { Get-HotFix -Id $_ -ErrorAction SilentlyContinue })
    if ($installed.Count -eq 0) { Write-Output 'None of the flagged KBs are installed on this device.'; Stop-Check 0 }

    # --- Read details of installed update packages once (language packs, features
    #     and on-demand packages are skipped; they are not Windows Update fixes).
    $skipTypes = 'LanguagePack', 'FeaturePack', 'OnDemandPack', 'Foundation', 'Product'
    $packages = Get-WindowsPackage -Online |
        Where-Object { $_.PackageState -eq 'Installed' -and $skipTypes -notcontains "$($_.ReleaseType)" } |
        ForEach-Object { Get-WindowsPackage -Online -PackageName $_.PackageName }

    foreach ($kb in $installed) {
        $match = @($packages | Where-Object { "$($_.Description)" -match "\b$kb\b" })
        if ($match.Count -ne 1) {
            Write-Output "ERROR: $kb is installed but $($match.Count) package(s) matched it; not guessing. Remove manually (DISM /Online /Get-Packages)."
            $errors++; continue
        }
        $pkg = $match[0]
        if ($pkg.PackageName -match 'ServicingStack') {
            Write-Output "ERROR: $kb is a servicing stack update ($($pkg.PackageName)); Microsoft says these cannot be uninstalled."
            $errors++; continue
        }

        if (-not $Apply) {
            Write-Output "REPORT ONLY: would remove $kb -> $($pkg.PackageName)"
            $wouldRemove++; continue
        }

        Write-Output "Removing $kb -> $($pkg.PackageName) ..."
        try {
            $r = Remove-WindowsPackage -Online -PackageName $pkg.PackageName -NoRestart
            $removed++
            if ($r.RestartNeeded) { $restart = $true }
            Write-Output "  removed (restart needed: $($r.RestartNeeded))"
        } catch {
            Write-Output "  ERROR removing $kb : $($_.Exception.Message)"
            $errors++
        }
    }
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Stop-Check 2
}

# --- Exit code: errors win, then report-only, then restart needed.
if ($errors -gt 0)     { Stop-Check 2 }
if ($wouldRemove -gt 0) { Stop-Check 1 }
if ($removed -gt 0 -and $restart) { Write-Output 'Restart needed to finish (reboot nag will prompt). Run the patch status check with -Apply so the KB is hidden before it reinstalls.'; Stop-Check 3 }
Write-Output 'Done.'
Stop-Check 0

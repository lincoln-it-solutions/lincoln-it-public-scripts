<#
.SYNOPSIS
    TRMM script: remove HP Wolf Security / HP Sure Click (the Bromium vSentry
    isolation engine) silently, then clear the Bromium data under ProgramData
    that is filling the disk.

.DESCRIPTION
    Run as SYSTEM from TRMM. Report-only by default; add -Apply to change anything.

    Phase 1 - uninstall (in HP's order, stops at the first failure):
        1. HP Wolf Security
        2. HP Sure Click                  (older Bromium-based name; same engine)
        3. HP Wolf Security - Console
        4. HP Security Update Service
      Order source: HP's "How to uninstall HP Wolf Pro Security" KB, as referenced by
        https://www.powershellgallery.com/packages/Remove-HPWolf/1.0.0/Content/Remove-HPWolf.ps1
        https://h30434.www3.hp.com/t5/Desktop-Operating-Systems-and-Recovery/HP-Wolf-Security-Business-doesn-t-work-properly-since/m-p/9541307
      Out of order, the Console / Update Service uninstall errors, and HP Security
      Update Service re-applies Wolf if it is left behind:
        https://h30434.www3.hp.com/t5/Notebook-Software-and-How-To-Questions/Uninstall-Wolf-Security-Please-uninstall-other-versions/m-p/8528904
      "HP Sure Click" placement (2nd) is ours, not HP's - it is the pre-Wolf
      product name and is only removed if it is present.

      Products are found from the Uninstall registry keys, NOT Win32_Product,
      because querying Win32_Product makes Windows Installer run a consistency
      check / repair on every installed MSI:
        https://learn.microsoft.com/en-us/troubleshoot/windows-server/admin-development/windows-installer-reconfigured-all-applications
      Each MSI is removed with msiexec /x {ProductCode} /qn /norestart and a
      verbose log in C:\ProgramData\LincolnIT\Logs\HPWolf.

    Phase 2 - cleanup (only once every product above is gone):
        Deletes C:\ProgramData\Bromium (vSentry Stage2 *.save / *.lvl images are what
        grows to tens of GB):
          https://h30434.www3.hp.com/t5/Notebook-Software-and-How-To-Questions/HP-Wolf-Bromium-folder-clean-up/m-p/9170862
          https://h30434.www3.hp.com/t5/Desktop-Software-and-How-To-Questions/HP-Wolf-Security-Appdata-300-GB/m-p/9496965
        Files stay locked by the Bromium drivers until a reboot, so the normal run is:
          run with -Apply -> reboot -> run with -Apply again.

    Not done (deliberately):
      - EXE-based uninstallers are reported, not run: no documented silent switch.
      - Hidden ~BROMIUM folders in user data are left alone (scattered through
        users' own folders; deleting there is a separate decision).
      - Old vSentry version entries are only removed with -ClearStaleVersions (see below).

    "Uninstall of active HP Wolf Security not supported while other versions are installed"
    (msiexec 1603): HP's CheckForParallelUpgrade custom action looks at each engine-version
    subkey under HKLM\SOFTWARE\Bromium\vSentry (e.g. 4.4.12.453) and counts it as installed
    only if it has a "Version" SUBKEY; it refuses to remove the live version while any
    other version is counted. Evidence, ULSULAPTOP045 2026-11-20:
      - msiexec log: "Found other version installed: 4.4.12.453", "Trying to remove active
        vSentry version while other versions installed, failing uninstall"; and for
        4.3.4.610 "unable to access key ...\4.3.4.610\Version: 2" -> skipped, not counted;
      - registry probe (Get-HPWolfRegistryProbe.ps1): 4.3.4.610 has only a State subkey,
        4.4.12.453 has State + Version, 4.4.34.927 (live) has State + Version + more;
        there is NO CurrentVersion value or key anywhere under HKLM\SOFTWARE\Bromium.
    The live version is therefore taken as the DisplayVersion of the installed
    "HP Wolf Security" MSI (the log shows HP's check treating that same version as itself:
    "Found same version+buildnumber installed: 4.4.34.927").
    Order of fixes:
      1. Reboot and run -Apply again (a pending HP upgrade may finish and drop the old entry).
      2. Still failing: run -Apply -ClearStaleVersions. For each version subkey that is
         NOT the live version and HAS a Version subkey, the whole version key is exported
         to the log folder with reg.exe, then ONLY its Version subkey is deleted, so HP's
         check skips it the same way it already skips 4.3.4.610. Removing old version
         entries is the fix reported working on 3 of 3 machines in
         https://h30434.www3.hp.com/t5/Notebook-Software-and-How-To-Questions/Uninstall-Wolf-Security-Please-uninstall-other-versions/m-p/8609071
         If the live version can't be determined, nothing is deleted.

    Exit codes:
      0  Nothing installed and nothing left to clean (or report-only run)
      1  An uninstall failed (see log path in output) or a non-MSI uninstaller found
      2  Products removed / cleanup partly blocked - reboot, then run -Apply again

.PARAMETER Apply
    Actually uninstall and delete. Without it, only reports what it would do.

.PARAMETER ClearStaleVersions
    With -Apply: back up and delete old vSentry version registry entries before
    uninstalling (fix for the "other versions are installed" 1603). Off by default.

.NOTES
    Ethan's scripting rule: comments explain what is done and why.
    Windows PowerShell 5.1 compatible (TRMM default shell).
    Suggested TRMM timeout: 1800 seconds (each MSI removal can take minutes).
#>

param(
    # Off by default so running it just reports.
    [switch]$Apply,

    # Off by default: only touch HP's registry when the stale-version error has been seen.
    [switch]$ClearStaleVersions
)

$ErrorActionPreference = 'Stop'

# Product display names in the order they must be removed (see .DESCRIPTION).
$ProductOrder = @(
    'HP Wolf Security',
    'HP Sure Click',
    'HP Wolf Security - Console',
    'HP Security Update Service'
)

# Where the Bromium engine keeps its data and settings.
$BromiumData = Join-Path $env:ProgramData 'Bromium'
$BromiumReg  = 'HKLM:\SOFTWARE\Bromium\vSentry'

# Per-run msiexec logs, kept outside the Bromium folder so cleanup doesn't remove them.
$LogDir = Join-Path $env:ProgramData 'LincolnIT\Logs\HPWolf'

# msiexec results that mean "removed" (0), "removed, reboot needed" (3010/1641)
# or "not installed any more" (1605).
$MsiOk     = @(0, 1605)
$MsiReboot = @(3010, 1641)

function Get-UninstallEntry {
    # Read both the 64-bit and 32-bit Uninstall keys and return the entry whose
    # DisplayName matches exactly. Exact match so e.g. "HP Wolf Security" does not
    # also pick up "HP Wolf Security - Console".
    param([string]$Name)
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty -Path $roots -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $Name }
}

function Get-StaleVsentryVersion {
    # Return ONLY objects (no messages - anything this function writes becomes part of its
    # result) for each vSentry version subkey that HP's uninstaller would count as "another
    # version installed": named like 4.4.12.453, NOT the live version, and HAS a Version
    # subkey (see .DESCRIPTION for the evidence). Both registry views are checked because
    # HP's custom action runs in a 32-bit process; on ULSULAPTOP045 only the native view existed.
    param([string]$LiveVersion)
    if (-not $LiveVersion) { return }   # unknown live version -> never return anything
    foreach ($root in 'HKLM:\SOFTWARE\Bromium\vSentry', 'HKLM:\SOFTWARE\WOW6432Node\Bromium\vSentry') {
        if (-not (Test-Path $root)) { continue }
        foreach ($k in Get-ChildItem -Path $root -ErrorAction SilentlyContinue) {
            if ($k.PSChildName -match '^\d+(\.\d+){3}$' -and
                $k.PSChildName -ne $LiveVersion -and
                (Test-Path (Join-Path $k.PSPath 'Version'))) {
                [pscustomobject]@{
                    Root        = $root
                    Version     = $k.PSChildName
                    Live        = $LiveVersion
                    RegPath     = $k.Name                         # HKEY_LOCAL_MACHINE\... form, for reg.exe export
                    VersionKey  = Join-Path $k.PSPath 'Version'   # the only thing that gets deleted
                }
            }
        }
    }
}

function Get-FolderSizeGB {
    # Sum file sizes so the output shows how much space Bromium is holding.
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    $bytes = (Get-ChildItem -Path $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
              Measure-Object -Property Length -Sum).Sum
    [math]::Round(($bytes / 1GB), 2)
}

# ---- Current state ---------------------------------------------------------
$freeBefore = [math]::Round((Get-PSDrive -Name C).Free / 1GB, 2)
Write-Output "Mode: $(if ($Apply) { 'APPLY' } else { 'REPORT ONLY (add -Apply to change anything)' })"
Write-Output "C: free: $freeBefore GB"
Write-Output "$BromiumData size: $(Get-FolderSizeGB $BromiumData) GB"

# List vSentry version entries - useful if the uninstall fails with the
# "other versions are installed" error (see .DESCRIPTION).
# Live engine version = DisplayVersion of the installed "HP Wolf Security" MSI (see .DESCRIPTION).
$liveVersion = @(Get-UninstallEntry 'HP Wolf Security' | ForEach-Object { $_.DisplayVersion }) | Select-Object -First 1
if (Test-Path $BromiumReg) {
    $versions = (Get-ChildItem $BromiumReg -ErrorAction SilentlyContinue).PSChildName -join ', '
    Write-Output "Registry $BromiumReg subkeys: $versions (live version: $(if ($liveVersion) { $liveVersion } else { 'unknown - HP Wolf Security MSI not found' }))"
}
$stale = @(Get-StaleVsentryVersion -LiveVersion $liveVersion)
if ($stale.Count) {
    Write-Output "Old vSentry versions HP counts as installed (block the uninstall): $(($stale | ForEach-Object { $_.Version }) -join ', ')"
}

# Build the list of what is actually installed, still in removal order.
$found = foreach ($name in $ProductOrder) {
    foreach ($entry in @(Get-UninstallEntry $name)) {
        if ($entry) {
            [pscustomobject]@{
                Name      = $entry.DisplayName
                Version   = $entry.DisplayVersion
                # MSI product code = the registry key name, e.g. {GUID}
                Code      = $entry.PSChildName
                Uninstall = $entry.UninstallString
            }
        }
    }
}

if ($found) {
    Write-Output ''
    Write-Output 'Installed (removal order):'
    $found | ForEach-Object { Write-Output "  $($_.Name) $($_.Version)  $($_.Code)" }
} else {
    Write-Output 'No HP Wolf / Sure Click products installed.'
}

if (-not $Apply) {
    # Report-only: stop here without changing anything.
    exit 0
}

# ---- Phase 1: uninstall in order ------------------------------------------
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$rebootNeeded = $false

# ---- Optional: clear stale vSentry version entries (see .DESCRIPTION) ------
if ($ClearStaleVersions -and $found -and $stale.Count) {
    foreach ($s in $stale) {
        # Back up first so the entry can be restored with: reg import <file>
        $backup = Join-Path $LogDir ("vSentry_{0}_{1}_{2:yyyyMMdd-HHmmss}.reg" -f `
            $s.Version, ($(if ($s.Root -match 'WOW6432Node') { 'wow64' } else { 'native' })), (Get-Date))
        & "$env:SystemRoot\System32\reg.exe" export $s.RegPath $backup /y | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $backup)) {
            # No backup = no delete.
            Write-Output "FAIL: could not back up $($s.RegPath) (reg export exit $LASTEXITCODE) - nothing deleted."
            exit 1
        }
        # Remove only the Version subkey: that is what makes HP's check count this version.
        Remove-Item -Path $s.VersionKey -Recurse -Force
        Write-Output "Removed $($s.Version)\Version under $($s.Root) (live: $($s.Live)). Backup of the whole $($s.Version) key: $backup"
    }
}

foreach ($p in $found) {
    # Only MSI uninstalls are run. An EXE uninstaller has no documented silent
    # switch, so guessing one could hang the TRMM run waiting on a hidden prompt.
    if ($p.Code -notmatch '^\{[0-9A-Fa-f\-]{36}\}$' -or $p.Uninstall -notmatch 'msiexec') {
        Write-Output "FAIL: $($p.Name) is not an MSI uninstall ($($p.Uninstall)) - remove by hand."
        exit 1
    }

    $log = Join-Path $LogDir ("{0}_{1:yyyyMMdd-HHmmss}.log" -f ($p.Name -replace '[^A-Za-z0-9]', ''), (Get-Date))
    Write-Output "Removing $($p.Name) $($p.Version) ..."

    # /x = uninstall, /qn = no UI, /norestart = we decide when to reboot,
    # /l*v = verbose log so a failure can be diagnosed afterwards.
    $proc = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
        -ArgumentList "/x $($p.Code) /qn /norestart /l*v `"$log`"" `
        -Wait -PassThru
    $rc = $proc.ExitCode

    if ($MsiOk -contains $rc) {
        Write-Output "  OK (exit $rc)"
    } elseif ($MsiReboot -contains $rc) {
        Write-Output "  OK, reboot required (exit $rc)"
        $rebootNeeded = $true
    } else {
        # Order matters, so don't carry on to the next product after a failure.
        # 1612 = install source unavailable (cached MSI missing) - seen on the
        # Console in the field; needs the matching-version MSI from HP.
        Write-Output "FAIL: $($p.Name) msiexec exit $rc. Log: $log"
        # Point at the known fix when the log shows HP's stale-version refusal.
        if ((Test-Path $log) -and (Select-String -Path $log -SimpleMatch 'while other versions are installed' -Quiet)) {
            Write-Output 'Cause: old vSentry version entries. Reboot and run -Apply again; if it still fails, run -Apply -ClearStaleVersions.'
        }
        exit 1
    }
}

# ---- Phase 2: clean up Bromium data ---------------------------------------
# Re-check: only delete the data once nothing that uses it is installed.
$stillThere = $ProductOrder | Where-Object { Get-UninstallEntry $_ }
if ($stillThere) {
    Write-Output "Still installed: $($stillThere -join ', ') - Bromium folder left alone."
    exit 2
}

$cleanupBlocked = $false
if (Test-Path $BromiumData) {
    Write-Output "Deleting $BromiumData ..."
    try {
        Remove-Item -Path $BromiumData -Recurse -Force -ErrorAction Stop
        Write-Output '  Deleted.'
    } catch {
        # Expected on the first pass: the Bromium drivers keep files open until reboot.
        Write-Output "  Some files are locked ($($_.Exception.Message.Split([Environment]::NewLine)[0]))"
        $cleanupBlocked = $true
    }
}

$freeAfter = [math]::Round((Get-PSDrive -Name C).Free / 1GB, 2)
Write-Output "C: free now: $freeAfter GB (was $freeBefore GB)"
Write-Output "$BromiumData remaining: $(Get-FolderSizeGB $BromiumData) GB"

if ($rebootNeeded -or $cleanupBlocked) {
    Write-Output 'Reboot, then run this script again with -Apply to finish the cleanup.'
    exit 2
}

Write-Output 'Done: HP Wolf Security removed and Bromium data cleared.'
exit 0

<#
.SYNOPSIS
    Downloads and installs the Windows 11 26H2 feature update on a device
    that is already running Windows 11 24H2 or later. Does NOT reboot unless
    you ask it to.

.DESCRIPTION
    WHY THIS WORKS THIS WAY
    Microsoft delivers 26H2 as a small "enablement package" for devices
    already on Windows 11 24H2 or 25H2 (24H2/25H2/26H2 share one servicing
    branch, so the new features are already on the disk in a dormant state
    and the package switches them on with one restart). Devices on 23H2 or
    older do NOT get this path and need a full ISO / Installation Assistant
    upgrade, so this script refuses to run on them instead of guessing.

    WHAT THE SCRIPT DOES, IN ORDER
      1. Checks it is elevated, the OS is Windows 11, and the installed
         version is 24H2 or newer. Exits 0 if already on 26H2 or later.
      2. Checks for a pending reboot and for free disk space. Aborts if
         either is a problem, because Microsoft requires the latest
         cumulative update to be fully installed first.
      3. (Optional, -PinTargetVersion) writes the Windows Update policy
         values that tell Windows Update to offer 26H2 rather than a
         newer release. They are put back to their old state at the end
         unless -KeepPin is used.
      4. Searches Windows Update (the same service Settings uses, through the
         built-in Windows Update Agent COM API) for the 26H2 feature
         update, downloads it and installs it.
      5. If 26H2 is NOT offered, it installs any pending cumulative
         updates instead (Microsoft's stated prerequisite) and tells you to
         reboot and run it again.
      6. If a local .msu is supplied with -PackagePath, and Windows Update
         does not offer the update, it is verified against -PackageSha256
         and installed with wusa.exe.
      7. Reboots only if -Reboot is passed. Otherwise exits 3010.

    EXIT CODES (so TRMM / any RMM can act on them)
      0     Already on 26H2 or later, or installed and no reboot needed
      3010  Installed or staged, reboot required (standard "reboot required")
      2     26H2 not offered by Windows Update and no -PackagePath given
      3     Pre-check failed (not admin, not Win11, older than 24H2,
            pending reboot, low disk space)
      5     Timed out waiting for the download/install (see -TimeoutMinutes)
      4     Download or install failed

.PARAMETER Reboot
    Restart the PC 60 seconds after a successful install. Off by default so
    nothing reboots a user's machine unexpectedly.

.PARAMETER PinTargetVersion
    Sets the Windows Update policy TargetReleaseVersion to 26H2 for the
    duration of the run. Off by default because it changes policy values.
    Skipped automatically if a TargetReleaseVersion policy already exists.

.PARAMETER KeepPin
    With -PinTargetVersion, leave the policy values in place afterwards.

.PARAMETER PackagePath
    Optional local path to the 26H2 enablement package (.msu), used only
    if Windows Update does not offer the update. Requires -PackageSha256.

.PARAMETER PackageSha256
    SHA-256 hash you expect for -PackagePath. The install is refused if the
    file does not match.

.PARAMETER MinFreeGB
    Minimum free space on the system drive. The default of 10 is my own
    choice, NOT a Microsoft figure for the enablement package; change it
    if you want something different.

.PARAMETER IncludePendingFileRename
    Also treat PendingFileRenameOperations as "reboot pending". Off by default
    because many installers set it and it causes false positives (the same
    choice Invoke-RebootNag.ps1 makes).

.PARAMETER TimeoutMinutes
    How long the script waits for the download plus install before giving up
    and exiting with code 5. Default 45, my own choice so the script ends
    before TRMM's 60-minute script timeout and leaves a clear log instead of a
    bare "timed out". Windows may carry on installing in the background after
    the script exits; a reboot or a later -CheckOnly run shows the result.

.PARAMETER LogPath
    Folder for the transcript log.

.NOTES
    Sources:
      Microsoft KB5054156 (25H2 enablement package): prerequisite is 24H2
        with the 29 Aug 2025 preview update KB5064081 or later; restart
        required. https://support.microsoft.com/en-us/help/5054156
      Microsoft KB5121794 (26H2 enablement package): prerequisite is 24H2 or
        25H2 with the 22 Sep 2026 preview KB5124010 or a later cumulative
        update; restart required.
        https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/kb5121794-feature-update-to-windows-11-version-26h2
      Microsoft Learn, What's new in 26H2: delivered as an enablement package
        to 25H2 / 24H2. https://learn.microsoft.com/en-us/windows/whats-new/whats-new-windows-11-version-26h2

    NOT VERIFIED: this was written without being able to run PowerShell, so
    it has not been executed on a Windows device. Test on one machine first.
    Also unverified: the exact title Windows Update gives the feature update
    (the script matches on "Windows 11, version 26H2"), and the
    ProductVersion value "Windows 11" used by -PinTargetVersion.
    Microsoft rolls 26H2 out gradually with safeguard holds, so a device can
    legitimately not be offered it yet.
#>

[CmdletBinding()]
param(
    [switch]$Reboot,
    [switch]$IncludePendingFileRename,
    [switch]$PinTargetVersion,
    [switch]$KeepPin,
    [string]$PackagePath,
    [string]$PackageSha256,
    [int]$MinFreeGB = 10,
    [int]$TimeoutMinutes = 45,
    [string]$LogPath = (Join-Path $env:ProgramData 'LincolnIT\Win11FeatureUpdate')
)

# Stop on any unexpected error so a failure is never silently ignored.
$ErrorActionPreference = 'Stop'

# The feature update this script installs. Everything below keys off this.
$TargetVersion = '26H2'

# Exit codes (documented in the header).
$EXIT_OK = 0; $EXIT_REBOOT = 3010; $EXIT_NOT_OFFERED = 2; $EXIT_PRECHECK = 3; $EXIT_FAILED = 4; $EXIT_TIMEOUT = 5

# ---------------------------------------------------------------- logging
# A transcript gives a record of what happened when the script runs unattended.
if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
$logFile = Join-Path $LogPath ("Install-Win11-$TargetVersion-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $logFile -Force | Out-Null

# Helper: turns "25H2" into a sortable number (2025.2) so versions can be
# compared with -ge instead of comparing strings. Format is YYH1 / YYH2.
function ConvertTo-VersionNumber([string]$Text) {
    if ($Text -match '^(\d{2})H([12])$') { return ([int]$Matches[1] * 10 + [int]$Matches[2]) }
    return $null
}

# Helper: ends the script cleanly, always stopping the transcript first.
function Exit-Script([int]$Code, [string]$Message) {
    Write-Output $Message
    Stop-Transcript | Out-Null
    exit $Code
}

# Helper: returns the reasons a reboot is pending (empty = none). Uses the same two
# markers as Invoke-RebootNag.ps1: component servicing and Windows Update. The
# PendingFileRenameOperations marker is deliberately NOT used by default because
# many installers leave it set, which causes false "reboot pending" results.
function Get-PendingRebootReasons {
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'ComponentBasedServicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'WindowsUpdate' }
    if ($IncludePendingFileRename) {
        $pfro = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($pfro -and $pfro.PendingFileRenameOperations) { $reasons += 'PendingFileRenameOperations' }
    }
    return $reasons
}

# Helper: runs the Windows Update download + install in a separate PowerShell job
# (child process) and waits for it here, so the script can print a heartbeat every
# minute and enforce -TimeoutMinutes. If the deadline passes, the job is killed and
# the script exits with code 5 instead of hanging until TRMM's own timeout
# (that hang happened on ULSULAPTOP31 on 2026-10-19: "timed out after 3603 seconds",
# no output after "Installing..."). The job re-finds the updates by their
# UpdateID + RevisionNumber because COM update objects cannot be passed between processes.
# NOTE: an earlier version used the async BeginDownload/BeginInstall calls with $null
# callbacks; that failed on ULSULAPTOP31 with "Object reference not set to an instance
# of an object", so this version only uses the synchronous calls that already ran there.
function Invoke-WuInstall($Updates) {
    $ids = @(foreach ($u in $Updates) { '{0}|{1}' -f $u.Identity.UpdateID, $u.Identity.RevisionNumber })
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $started  = Get-Date

    $job = Start-Job -ArgumentList (, $ids) -ScriptBlock {
        param($ids)
        $ErrorActionPreference = 'Stop'
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $coll     = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($pair in $ids) {
            $id, $rev = $pair -split '\|'
            foreach ($u in $searcher.Search("UpdateID='$id' and RevisionNumber=$rev").Updates) {
                if (-not $u.EulaAccepted) { $u.AcceptEula() }   # the API will not download with an unaccepted EULA
                [void]$coll.Add($u)
            }
        }
        if ($coll.Count -ne $ids.Count) { throw "Worker found $($coll.Count) of $($ids.Count) selected update(s) when searching again." }

        "Downloading $($coll.Count) update(s)..."
        $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll
        $d = $dl.Download()
        # ResultCode 2 = succeeded, 3 = succeeded with errors; anything else is a failure.
        if ($d.ResultCode -notin 2, 3) { throw "Download failed, result code $($d.ResultCode)." }

        'Installing...'
        $inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll
        $inst.AllowSourcePrompts = $false   # never prompt: this may run as SYSTEM
        $res = $inst.Install()

        # Per-update results are in the same order as the collection.
        for ($i = 0; $i -lt $coll.Count; $i++) {
            $r = $res.GetUpdateResult($i)
            [pscustomobject]@{ Kind = 'update'; Title = $coll.Item($i).Title; ResultCode = [int]$r.ResultCode; HResult = [int]$r.HResult }
        }
        [pscustomobject]@{ Kind = 'summary'; ResultCode = [int]$res.ResultCode; RebootRequired = [bool]$res.RebootRequired }
    }

    $state = @{ Results = @(); Summary = $null }; $lastBeat = Get-Date
    # Collects the worker's output: strings are progress messages, objects are results.
    $drain = {
        foreach ($o in @(Receive-Job $job)) {
            if ($o -is [string]) { Write-Output "  [worker] $o" }
            elseif ($o.Kind -eq 'update')  { $state.Results += $o }
            elseif ($o.Kind -eq 'summary') { $state.Summary = $o }
        }
    }
    while ($job.State -eq 'Running' -or $job.State -eq 'NotStarted') {
        & $drain
        if ((Get-Date) -gt $deadline) {
            Stop-Job $job; Remove-Job $job -Force
            Exit-Script $EXIT_TIMEOUT "Timed out after $TimeoutMinutes minutes. Windows may still be installing in the background; reboot or run -CheckOnly later. See the log: $logFile"
        }
        if (((Get-Date) - $lastBeat).TotalSeconds -ge 60) {
            Write-Output ("  still working... {0:N0} min elapsed  [{1:HH:mm:ss}]" -f ((Get-Date) - $started).TotalMinutes, (Get-Date))
            $lastBeat = Get-Date
        }
        Start-Sleep -Seconds 5
    }
    & $drain
    if ($job.State -eq 'Failed') {
        $reason = $job.ChildJobs[0].JobStateInfo.Reason.Message
        Remove-Job $job -Force
        throw "Update worker failed: $reason"
    }
    Remove-Job $job -Force
    if (-not $state.Summary) { throw 'Update worker finished without returning a result.' }
    return [pscustomobject]@{ Results = $state.Results; Summary = $state.Summary }
}

# Helper: install a collection of updates through the worker job above and return
# an object with RebootRequired. Throws if any update did not install.
function Install-WuUpdates($Session, $Updates) {
    Write-Output "Downloading and installing $(@($Updates).Count) update(s)... (will give up after $TimeoutMinutes minutes in total)"
    $r = Invoke-WuInstall $Updates
    # ResultCode: 2 = succeeded, 3 = succeeded with errors. Anything else is a failure.
    foreach ($u in $r.Results) {
        Write-Output ("  result {0} (HRESULT 0x{1:X})  {2}" -f $u.ResultCode, $u.HResult, $u.Title)
        if ($u.ResultCode -notin 2, 3) { throw "Install failed for '$($u.Title)', result code $($u.ResultCode)." }
    }
    return [pscustomobject]@{ RebootRequired = $r.Summary.RebootRequired }
}

# ------------------------------------------------------------- pre-checks
try {
    # 1. Elevation: installing updates needs admin rights (TRMM runs as SYSTEM, which is fine).
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Exit-Script $EXIT_PRECHECK 'Not running as administrator.' }

    # 2. Read the installed version from the registry. DisplayVersion is what
    #    winver shows (e.g. "24H2"). Build >= 22000 means Windows 11
    #    (the ProductName value still says "Windows 10" on Windows 11, so it is not used).
    $cv      = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build   = [int]$cv.CurrentBuildNumber
    $current = [string]$cv.DisplayVersion
    Write-Output "Detected: build $build.$($cv.UBR), DisplayVersion '$current'."
    if ($build -lt 22000) { Exit-Script $EXIT_PRECHECK 'This is not Windows 11. Nothing done.' }

    $curNum = ConvertTo-VersionNumber $current
    $tgtNum = ConvertTo-VersionNumber $TargetVersion
    if ($null -eq $curNum) { Exit-Script $EXIT_PRECHECK "Could not read a version like '24H2' from the registry (got '$current'). Nothing done." }

    # 3. Already there (or newer): nothing to do.
    if ($curNum -ge $tgtNum) { Exit-Script $EXIT_OK "Already on $current, which is $TargetVersion or newer. Nothing to do." }

    # 4. Enablement package only applies to 24H2 or newer.
    if ($curNum -lt (ConvertTo-VersionNumber '24H2')) {
        Exit-Script $EXIT_PRECHECK "Device is on $current. The enablement package only applies to 24H2 or newer; this device needs a full ISO / Installation Assistant upgrade. Nothing done."
    }

    # 5. A pending reboot may mean the latest cumulative update (Microsoft's prerequisite) is not fully installed.
    $pending = Get-PendingRebootReasons
    if ($pending.Count -gt 0) { Exit-Script $EXIT_PRECHECK "A reboot is already pending ($($pending -join ', ')). Reboot, then run this again." }

    # 6. Free space on the system drive.
    $sysDrive = Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))
    $freeGB   = [math]::Round($sysDrive.Free / 1GB, 1)
    if ($freeGB -lt $MinFreeGB) { Exit-Script $EXIT_PRECHECK "Only $freeGB GB free on $env:SystemDrive (minimum set to $MinFreeGB GB)." }

    # ------------------------------------------- optional: pin target version
    # These values come from the Windows Update for Business "target release"
    # policy. Existing values are remembered so they can be restored.
    $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $pinned = $false
    if ($PinTargetVersion) {
        $existing = Get-ItemProperty $polKey -Name TargetReleaseVersion -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Output 'A TargetReleaseVersion policy already exists; leaving it untouched and not pinning.'
        } else {
            if (-not (Test-Path $polKey)) { New-Item -Path $polKey -Force | Out-Null }
            New-ItemProperty $polKey -Name ProductVersion           -Value 'Windows 11'   -PropertyType String -Force | Out-Null
            New-ItemProperty $polKey -Name TargetReleaseVersion     -Value 1              -PropertyType DWord  -Force | Out-Null
            New-ItemProperty $polKey -Name TargetReleaseVersionInfo -Value $TargetVersion -PropertyType String -Force | Out-Null
            $pinned = $true
            Write-Output "Pinned Windows Update to $TargetVersion for this run."
        }
    }

    try {
        # ------------------------------------------- search Windows Update
        # Uses the built-in COM API; it follows whatever update source the
        # device is configured for (Microsoft Update, WSUS, etc.).
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        Write-Output 'Searching Windows Update...'
        $found = $searcher.Search("IsInstalled=0 and Type='Software'").Updates

        # Match the feature update by title, e.g. "Feature update to Windows 11, version 25H2".
        $feature = @($found | Where-Object { $_.Title -match [regex]::Escape("Windows 11, version $TargetVersion") })

        if ($feature.Count -gt 0) {
            Write-Output "Offered: $($feature[0].Title)"
            $res = Install-WuUpdates $session $feature
            $rebootNeeded = $res.RebootRequired
        }
        elseif ($PackagePath) {
            # ---------------------------------- fallback: local .msu package
            if (-not $PackageSha256) { Exit-Script $EXIT_PRECHECK '-PackagePath needs -PackageSha256 so the file can be verified.' }
            if (-not (Test-Path $PackagePath)) { Exit-Script $EXIT_PRECHECK "Package not found: $PackagePath" }
            $actual = (Get-FileHash -Path $PackagePath -Algorithm SHA256).Hash
            if ($actual -ne $PackageSha256.Trim().ToUpper()) { Exit-Script $EXIT_FAILED "Hash mismatch. Expected $PackageSha256, got $actual. Not installing." }
            Write-Output 'Hash verified. Installing package with wusa.exe...'
            # /quiet = no UI, /norestart = we decide about rebooting.
            $p = Start-Process wusa.exe -ArgumentList "`"$PackagePath`"", '/quiet', '/norestart' -Wait -PassThru
            # 3010 = reboot required, 2359302 (0x240006) = already installed.
            switch ($p.ExitCode) {
                0       { $rebootNeeded = $false }
                3010    { $rebootNeeded = $true }
                2359302 { Exit-Script $EXIT_OK 'wusa reports this package is already installed.' }
                default { throw "wusa.exe exited with code $($p.ExitCode)." }
            }
        }
        else {
            # ---------------------------------- not offered: do the prerequisite
            # Microsoft requires the latest cumulative update first, so install any that are pending.
            $cu = @($found | Where-Object { $_.Title -match 'Cumulative Update for Windows 11' })
            if ($cu.Count -gt 0) {
                Write-Output "$TargetVersion not offered yet. Installing $($cu.Count) pending cumulative update(s) (the prerequisite)."
                $res = Install-WuUpdates $session $cu
                Exit-Script $EXIT_REBOOT 'Cumulative update installed. Reboot, then run this script again to get the feature update.'
            }
            Exit-Script $EXIT_NOT_OFFERED "Windows Update is not offering $TargetVersion to this device. Possible reasons: gradual rollout, a safeguard hold, WSUS/policy not approving it. Use -PackagePath/-PackageSha256 if you want to force the enablement package."
        }
    }
    finally {
        # Put the pin back how it was, unless asked to keep it.
        if ($pinned -and -not $KeepPin) {
            foreach ($n in 'ProductVersion', 'TargetReleaseVersion', 'TargetReleaseVersionInfo') {
                Remove-ItemProperty $polKey -Name $n -ErrorAction SilentlyContinue
            }
            Write-Output 'Removed the temporary target-version policy values.'
        }
    }

    # ------------------------------------------------------------ result
    # The version number only changes after the restart, so this reports state, not the new version.
    if ($rebootNeeded) {
        if ($Reboot) {
            Write-Output 'Installed. Restarting in 60 seconds.'
            Stop-Transcript | Out-Null
            shutdown.exe /r /t 60 /c "Windows 11 $TargetVersion update: restarting to finish."
            exit $EXIT_REBOOT
        }
        Exit-Script $EXIT_REBOOT "Installed. Restart required to finish moving to $TargetVersion."
    }
    Exit-Script $EXIT_OK "Install completed, no restart reported."
}
catch {
    Exit-Script $EXIT_FAILED "FAILED: $($_.Exception.Message)"
}

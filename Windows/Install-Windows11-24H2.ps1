<#
.SYNOPSIS
    Downloads and installs the Windows 11 24H2 feature update on a Windows 11
    device that is OLDER than 24H2 (22H2 or 23H2). Does NOT reboot unless you
    ask it to.

.DESCRIPTION
    WHY THIS IS NOT JUST THE 25H2/26H2 SCRIPT WITH THE NUMBER CHANGED
    The 25H2 and 26H2 scripts (Install-Windows11-25H2.ps1 / -26H2.ps1) install a
    small "enablement package" and refuse to run on anything older than 24H2.
    24H2 itself is different: Microsoft describes it as a full OS swap, not an
    enablement package, so a 22H2/23H2 device has to take the whole feature
    update. That means a bigger download, much more free disk space, a longer
    install and a long restart. This script is for those older devices; once a
    device is on 24H2 it can use the 25H2/26H2 scripts (or the WUfB policy).

    24H2 for Home and Pro editions reached end of updates on 13 Oct 2026
    (Enterprise/Education: 12 Oct 2027), so treat 24H2 as a stepping stone and
    move the device on to 25H2/26H2 straight afterwards.

    WHAT THE SCRIPT DOES, IN ORDER
      1. Checks it is elevated, the OS is Windows 11 and the installed version
         is 22H2 or 23H2. Exits 0 if the device is already on 24H2 or newer.
         Exits 3 for 21H2 (see NOTES: no documented path from 21H2).
      2. Pre-checks: on 64-bit Intel/AMD, the CPU must report SSE4.2 (24H2 will
         not boot without it); no reboot pending; enough free disk space.
      3. (Optional, -PinTargetVersion) writes the Windows Update policy values
         that tell Windows Update to offer 24H2. If a target-version policy is
         already there (for example the 26H2 pin from Set-WUfBPolicy.ps1) it is
         remembered, replaced for this run, and PUT BACK at the end.
      4. Searches Windows Update (built-in Windows Update Agent COM API) for the
         24H2 feature update, downloads it and installs it.
      5. If 24H2 is NOT offered, it installs any pending monthly cumulative
         update (Microsoft's stated prerequisite) and tells you to reboot and
         run it again.
      6. Reboots only if -Reboot is passed. Otherwise exits 3010.

    -CheckOnly answers "would Windows Update offer 24H2 on this device?"
    without downloading or installing anything. Use it on one device first.

    EXIT CODES (so TRMM / any RMM can act on them)
      0     Already on 24H2 or later, or installed and no reboot needed
      3010  Installed or staged, reboot required (standard "reboot required")
      2     24H2 not offered by Windows Update
      3     Pre-check failed (not admin, not Win11, older than 22H2, CPU
            without SSE4.2, pending reboot, low disk space). With -CheckOnly:
            24H2 is offered but something above would block the install
      4     Download or install failed
      5     Timed out waiting for the download/install (see -TimeoutMinutes)
      6     -CheckOnly only: Windows Update offers 24H2 and nothing blocks it

.PARAMETER CheckOnly
    Report whether 24H2 is offered and whether pre-checks pass. Downloads and
    installs nothing. With -PinTargetVersion the policy is still changed for
    the duration of the run and put back, because the answer depends on it.

.PARAMETER Reboot
    Restart the PC 60 seconds after a successful install. Off by default
    because a full upgrade makes the PC unavailable for a long time after the
    restart; schedule it out of hours (Schedule-OneOffReboot.ps1) instead.

.PARAMETER PinTargetVersion
    Sets the Windows Update policy TargetReleaseVersion to 24H2 for the
    duration of the run. Off by default because it changes policy values.
    UNLIKE the 25H2/26H2 scripts, an existing target-version policy is
    overridden for the run (and restored) rather than left alone, because a
    device pinned to 26H2 would otherwise never be offered 24H2.

.PARAMETER KeepPin
    With -PinTargetVersion, leave the 24H2 policy values in place afterwards
    instead of restoring the previous ones.

.PARAMETER MinFreeGB
    Minimum free space on the system drive. The default of 25 is my own
    choice, NOT a Microsoft figure. Sources disagree: Microsoft's support page
    says feature updates typically need 6-11 GB or more, while community
    answers for 24H2 say 20 GB minimum and some say 40 GB. Change it if you
    want something different.

.PARAMETER IncludePendingFileRename
    Also treat PendingFileRenameOperations as "reboot pending". Off by default
    because many installers set it and it causes false positives (the same
    choice Invoke-RebootNag.ps1 makes).

.PARAMETER TimeoutMinutes
    How long the script waits for the download plus install before giving up
    and exiting with code 5. Default 90, my own choice (a full feature update
    takes longer than the 45 minutes the enablement-package scripts use). Set
    the TRMM script timeout above this (TRMM's own default of 3600 s is too
    short) so the script ends with a clear log instead of a bare "timed out".
    Windows may carry on installing in the background after the script exits;
    a reboot or a later -CheckOnly run shows the result.

.PARAMETER LogPath
    Folder for the transcript log.

.NOTES
    Sources:
      Microsoft Learn, What's new in Windows 11 24H2: "a full OS swap so it
        isn't available as an enablement package"; devices must be on 22H2 or
        23H2 with the May 2024 non-security preview update, or later.
        https://learn.microsoft.com/windows/whats-new/whats-new-windows-11-version-24h2
      24H2 Home/Pro end of updates 13 Oct 2026, Enterprise/Education 12 Oct 2027:
        Microsoft message-center text as quoted by BleepingComputer and TechRepublic.
      SSE4.2 / POPCNT requirement: press reports (Tom's Hardware, gHacks) that
        24H2 will not boot on CPUs without it. I did not find a Microsoft page
        stating it. The test uses IsProcessorFeaturePresent(38) =
        PF_SSE4_2_INSTRUCTIONS_AVAILABLE, documented on Microsoft Learn.
      Free space: Microsoft support KB 555622 (6-11 GB typical for feature
        updates); community answers 20-40 GB for 24H2. See -MinFreeGB.

    NOT VERIFIED: this was written without being able to run PowerShell on a
    Windows device, so it has not been executed there. Test on one machine with
    -CheckOnly first. Also unverified:
      - the exact title Windows Update gives the feature update (the script
        matches on "Windows 11, version 24H2");
      - whether Windows Update still offers 24H2 now that 24H2 Home/Pro is out
        of support (if not, the script exits 2 and the device needs an ISO or
        the Installation Assistant, which this script does not do);
      - that the registry target-version policy behaves like Microsoft's
        Intune feature-update policy, which "offers only one feature update at
        a time and always selects the latest applicable version" (assumed);
      - ProductVersion value "Windows 11" used by -PinTargetVersion (same as
        Set-WUfBPolicy.ps1);
      - 21H2: Microsoft's documented path starts at 22H2/23H2, so 21H2 is
        refused rather than guessed.
    Not checked: edition, system language, TPM/Secure Boot, or whether the
    device is managed by Intune/MDM update policy (Set-WUfBPolicy.ps1 checks that).
    If the daily WUfB policy task (-Apply) runs during this script it rewrites
    the 26H2 pin; the restore at the end then puts back the same value.
#>

[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$Reboot,
    [switch]$IncludePendingFileRename,
    [switch]$PinTargetVersion,
    [switch]$KeepPin,
    [int]$MinFreeGB = 25,
    [int]$TimeoutMinutes = 90,
    [string]$LogPath = (Join-Path $env:ProgramData 'LincolnIT\Win11FeatureUpdate')
)

# Stop on any unexpected error so a failure is never silently ignored.
$ErrorActionPreference = 'Stop'

# The feature update this script installs. Everything below keys off this.
$TargetVersion = '24H2'

# Exit codes (documented in the header).
$EXIT_OK = 0; $EXIT_REBOOT = 3010; $EXIT_NOT_OFFERED = 2; $EXIT_PRECHECK = 3; $EXIT_FAILED = 4; $EXIT_TIMEOUT = 5; $EXIT_OFFERED = 6

# The Windows Update policy key and the three values that pin the target version.
$polKey   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$pinNames = @('ProductVersion', 'TargetReleaseVersion', 'TargetReleaseVersionInfo')

# State for the temporary pin: what the values were before this run, and whether
# this run changed them. Restore-TargetVersionPolicy uses these.
$script:PinChanged = $false
$script:SavedPin   = @{}
$script:Problems   = @()   # -CheckOnly: pre-check problems that would block an install

# ---------------------------------------------------------------- logging
# A transcript gives a record of what happened when the script runs unattended.
if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
$logFile = Join-Path $LogPath ("Install-Win11-$TargetVersion-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $logFile -Force | Out-Null

# Helper: turns "23H2" into a sortable number (232) so versions can be compared with
# -ge instead of comparing strings. Format is YYH1 / YYH2.
function ConvertTo-VersionNumber([string]$Text) {
    if ($Text -match '^(\d{2})H([12])$') { return ([int]$Matches[1] * 10 + [int]$Matches[2]) }
    return $null
}

# Helper: puts the Windows Update target-version policy back how it was before this
# run (only if this run changed it and -KeepPin was not given). Values that did not
# exist before are removed; values that did are rewritten with their old type.
# Exit-Script calls this, so every way of ending the script restores the policy.
function Restore-TargetVersionPolicy {
    if (-not $script:PinChanged -or $KeepPin) { return }
    foreach ($n in $pinNames) {
        if ($script:SavedPin.ContainsKey($n)) {
            New-ItemProperty -Path $polKey -Name $n -Value $script:SavedPin[$n].Value -PropertyType $script:SavedPin[$n].Kind -Force | Out-Null
        } else {
            Remove-ItemProperty -Path $polKey -Name $n -ErrorAction SilentlyContinue
        }
    }
    $script:PinChanged = $false
    Write-Output 'Put the Windows Update target-version policy back as it was before this run.'
}

# Helper: ends the script cleanly. Always restores the temporary pin and stops the
# transcript first.
function Exit-Script([int]$Code, [string]$Message) {
    Write-Output $Message
    Restore-TargetVersionPolicy
    Stop-Transcript | Out-Null
    exit $Code
}

# Helper: a pre-check problem. A normal run stops here (exit 3). With -CheckOnly the
# problem is only reported, so one run can still answer "is 24H2 offered?".
function Add-PrecheckProblem([string]$Message) {
    if ($CheckOnly) { Write-Output "WOULD BLOCK INSTALL: $Message"; $script:Problems += $Message }
    else { Exit-Script $EXIT_PRECHECK $Message }
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
    #    winver shows (e.g. "23H2"). Build >= 22000 means Windows 11
    #    (the ProductName value still says "Windows 10" on Windows 11, so it is not used).
    $cv      = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build   = [int]$cv.CurrentBuildNumber
    $current = [string]$cv.DisplayVersion
    Write-Output "Detected: build $build.$($cv.UBR), DisplayVersion '$current'."
    if ($build -lt 22000) { Exit-Script $EXIT_PRECHECK 'This is not Windows 11. Nothing done.' }

    $curNum = ConvertTo-VersionNumber $current
    $tgtNum = ConvertTo-VersionNumber $TargetVersion
    if ($null -eq $curNum) { Exit-Script $EXIT_PRECHECK "Could not read a version like '23H2' from the registry (got '$current'). Nothing done." }

    # 3. Already there (or newer): nothing to do. This also covers 25H2/26H2 devices,
    #    so the script never tries to move a device backwards.
    if ($curNum -ge $tgtNum) { Exit-Script $EXIT_OK "Already on $current, which is $TargetVersion or newer. Nothing to do. (Use the 25H2/26H2 scripts to move on.)" }

    # 4. Microsoft's documented path to 24H2 starts from 22H2 or 23H2, so anything
    #    older (21H2) is refused instead of guessed at.
    if ($curNum -lt (ConvertTo-VersionNumber '22H2')) {
        Exit-Script $EXIT_PRECHECK "Device is on $current. Microsoft documents the update to 24H2 from 22H2 or 23H2 only; this device needs an ISO / Installation Assistant upgrade, which this script does not do. Nothing done."
    }

    # 5. CPU: 24H2 needs SSE4.2 (press reports: it will not boot without it). Only tested
    #    on 64-bit Intel/AMD; Arm64 does not have SSE, so it is skipped there.
    #    IsProcessorFeaturePresent(38) = PF_SSE4_2_INSTRUCTIONS_AVAILABLE (Microsoft Learn).
    #    If the test itself cannot run, that is reported and the script carries on.
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    Write-Output "OS architecture: $arch."
    if ($arch -eq 'X64') {
        try {
            if (-not ('LincolnIT.CpuFeature' -as [type])) {
                Add-Type -Namespace 'LincolnIT' -Name 'CpuFeature' -MemberDefinition '[DllImport("kernel32.dll")] public static extern bool IsProcessorFeaturePresent(uint ProcessorFeature);'
            }
            $hasSse42 = [LincolnIT.CpuFeature]::IsProcessorFeaturePresent(38)
        } catch {
            $hasSse42 = $null
            Write-Output "Could not test the CPU for SSE4.2 ($($_.Exception.Message)); carrying on."
        }
        if ($hasSse42 -eq $true)  { Write-Output 'CPU reports SSE4.2 (needed by 24H2).' }
        if ($hasSse42 -eq $false) { Add-PrecheckProblem 'CPU does not report SSE4.2, which 24H2 needs to boot. Do not upgrade this device.' }
    }

    # 6. A pending reboot may mean the latest cumulative update (Microsoft's prerequisite) is not fully installed.
    $pending = @(Get-PendingRebootReasons)
    if ($pending.Count -gt 0) { Add-PrecheckProblem "A reboot is already pending ($($pending -join ', ')). Reboot, then run this again." }

    # 7. Free space on the system drive.
    $sysDrive = Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))
    $freeGB   = [math]::Round($sysDrive.Free / 1GB, 1)
    Write-Output "Free space on $($env:SystemDrive): $freeGB GB (minimum set to $MinFreeGB GB)."
    if ($freeGB -lt $MinFreeGB) { Add-PrecheckProblem "Only $freeGB GB free on $env:SystemDrive (minimum set to $MinFreeGB GB)." }

    # ------------------------------------------- target-version policy
    # Read what is there now. A pin to a DIFFERENT version (the 26H2 pin from
    # Set-WUfBPolicy.ps1, for example) matters: Windows Update offers one feature
    # update at a time, so a 26H2 pin means 24H2 is never offered.
    $existing       = Get-ItemProperty $polKey -ErrorAction SilentlyContinue
    $existingOn     = if ($existing) { $existing.TargetReleaseVersion } else { $null }
    $existingTarget = if ($existing) { $existing.TargetReleaseVersionInfo } else { $null }
    if ($existingOn -eq 1 -and $existingTarget) { Write-Output "Existing Windows Update policy pins the target feature version to $existingTarget." }
    else { Write-Output 'No target-version policy is set on this device.' }

    if ($PinTargetVersion) {
        $alreadyPinned = ($existingOn -eq 1 -and $existingTarget -eq $TargetVersion -and $existing.ProductVersion -eq 'Windows 11')
        if ($alreadyPinned) {
            Write-Output "Policy already pins $TargetVersion; nothing to change."
        } else {
            if ($existingOn -eq 1) { Write-Output "Overriding the existing pin ($existingTarget) for this run only; it is put back afterwards." }
            if (-not (Test-Path $polKey)) { New-Item -Path $polKey -Force | Out-Null }
            # Remember the old values and their registry types so they can be restored exactly.
            $key = Get-Item $polKey
            foreach ($n in $pinNames) {
                if ($key.GetValueNames() -contains $n) {
                    $script:SavedPin[$n] = @{ Value = $key.GetValue($n); Kind = [string]$key.GetValueKind($n) }
                }
            }
            New-ItemProperty $polKey -Name ProductVersion           -Value 'Windows 11'   -PropertyType String -Force | Out-Null
            New-ItemProperty $polKey -Name TargetReleaseVersion     -Value 1              -PropertyType DWord  -Force | Out-Null
            New-ItemProperty $polKey -Name TargetReleaseVersionInfo -Value $TargetVersion -PropertyType String -Force | Out-Null
            $script:PinChanged = $true
            Write-Output "Pinned Windows Update to $TargetVersion for this run."
        }
    }

    # ------------------------------------------- search Windows Update
    # Uses the built-in COM API; it follows whatever update source the
    # device is configured for (Microsoft Update, WSUS, etc.).
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    Write-Output 'Searching Windows Update...'
    $found = $searcher.Search("IsInstalled=0 and Type='Software'").Updates

    # Match the feature update by title, e.g. "Feature update to Windows 11, version 24H2".
    $feature = @($found | Where-Object { $_.Title -match [regex]::Escape("Windows 11, version $TargetVersion") })

    if ($feature.Count -gt 0) {
        Write-Output "Offered: $($feature[0].Title)"
        if ($CheckOnly) {
            if ($script:Problems.Count -gt 0) { Exit-Script $EXIT_PRECHECK "CHECK ONLY: $TargetVersion is offered, but $($script:Problems.Count) pre-check problem(s) above would block the install. Nothing downloaded or installed." }
            Exit-Script $EXIT_OFFERED "CHECK ONLY: $TargetVersion is offered and no pre-check problems. Nothing downloaded or installed."
        }
        $res = Install-WuUpdates $session $feature
        $rebootNeeded = $res.RebootRequired
    }
    else {
        # ---------------------------------- not offered: do the prerequisite
        # Microsoft requires a recent cumulative update first. Current monthly update titles look like
        # "2026-08 Security Update (KB5121003) (26200.9168)" (the format Check-WindowsPatchStatus.ps1
        # matches); the older "Cumulative Update for Windows 11" wording is still accepted.
        # Previews and .NET updates are left out.
        $cu = @($found | Where-Object {
            ($_.Title -match '^\d{4}-\d{2} Security Update \(KB\d+\) \(\d+\.\d+\)' -or $_.Title -match 'Cumulative Update for Windows 11') -and
            $_.Title -notmatch 'Preview|\.NET' })

        if ($cu.Count -gt 0) {
            if ($CheckOnly) {
                Exit-Script $EXIT_NOT_OFFERED "CHECK ONLY: $TargetVersion is not offered yet, but $($cu.Count) pending cumulative update(s) would be installed first (the prerequisite). Nothing downloaded or installed."
            }
            Write-Output "$TargetVersion not offered yet. Installing $($cu.Count) pending cumulative update(s) (the prerequisite)."
            $res = Install-WuUpdates $session $cu
            Exit-Script $EXIT_REBOOT 'Cumulative update installed. Reboot, then run this script again to get the feature update.'
        }

        # Say why, as far as the script can tell, so the TRMM output is useful on its own.
        $pinNote = ''
        if (-not $PinTargetVersion -and $existingOn -eq 1 -and $existingTarget -and $existingTarget -ne $TargetVersion) {
            $pinNote = " A policy pins the target version to $existingTarget, and Windows Update offers one feature update at a time, so re-run with -PinTargetVersion to override it for this run."
        }
        Exit-Script $EXIT_NOT_OFFERED "Windows Update is not offering $TargetVersion to this device.$pinNote Other possible reasons: a safeguard hold, WSUS/policy not approving it, or $TargetVersion no longer being offered for this edition (24H2 Home/Pro is out of support). Nothing was installed."
    }

    # ------------------------------------------------------------ result
    # The version number only changes after the restart, so this reports state, not the new version.
    if ($rebootNeeded) {
        if ($Reboot) {
            Write-Output 'Installed. Restarting in 60 seconds. This is a full upgrade, so the PC will be busy for a long time after the restart.'
            Restore-TargetVersionPolicy
            Stop-Transcript | Out-Null
            shutdown.exe /r /t 60 /c "Windows 11 $TargetVersion upgrade: restarting to finish. The PC will be unavailable for a while."
            exit $EXIT_REBOOT
        }
        Exit-Script $EXIT_REBOOT "Installed. A restart is required to finish moving to $TargetVersion. This is a full OS upgrade, so the PC is unavailable for a long time after the restart: restart out of hours (see Schedule-OneOffReboot.ps1)."
    }
    Exit-Script $EXIT_OK "Install completed, no restart reported."
}
catch {
    Exit-Script $EXIT_FAILED "FAILED: $($_.Exception.Message)"
}

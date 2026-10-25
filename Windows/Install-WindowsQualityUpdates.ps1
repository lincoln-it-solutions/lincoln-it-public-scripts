<#
.SYNOPSIS
    Checks Windows Update for pending quality and security updates and, unless
    -CheckOnly is used, downloads and installs them. Does NOT reboot unless
    you ask it to.

.DESCRIPTION
    WHAT COUNTS AS A "QUALITY / SECURITY UPDATE" HERE
    Windows Update labels every update with one or more categories. This
    script keeps an update only if it carries one of these category names:
        Security Updates, Critical Updates, Update Rollups
    (Monthly cumulative updates, including .NET cumulative updates, are
    normally delivered under Security Updates.) It then removes anything that
    is a feature update ("Upgrades" category or a title starting "Feature
    update"), a driver, or an optional preview update (title contains
    "Preview"), unless -IncludePreview is passed. Defender definition updates
    are NOT included, because your clients use ESET.
    Every candidate and every update that was skipped is written to the log
    with its categories, so you can see exactly why each one was chosen.

    WHAT THE SCRIPT DOES, IN ORDER
      1. Checks it is running as administrator.
      2. Searches Windows Update (built-in Windows Update Agent COM API, so
         it follows whatever source the device is set to: Microsoft Update,
         WSUS, etc.) for updates that are not installed and not hidden.
      3. Filters them as described above and prints the list.
      4. -CheckOnly: stops here (exit 1 if updates are pending, 0 if none).
      5. Otherwise aborts if a reboot is already pending (a pending reboot
         can make installs fail), then downloads and installs the updates.
      6. Reports the result for each update and whether a restart is needed.
      7. Reboots only if -Reboot was passed.

    EXIT CODES (so TRMM / any RMM can act on them)
      0     No pending quality/security updates, or install finished and no
            reboot needed
      1     -CheckOnly: updates are pending
      3     Pre-check failed (not admin, or reboot already pending)
      3010  Install finished, reboot required (standard "reboot required")
      5     Timed out waiting for the download/install (see -TimeoutMinutes)
      4     Search, download or install failed (including any single update
            failing)

.PARAMETER CheckOnly
    List what is pending and change nothing.

.PARAMETER Reboot
    Restart 60 seconds after a successful install that needs one. Off by
    default so nothing restarts a user's PC unexpectedly.

.PARAMETER IncludePreview
    Also include optional preview updates (titles containing "Preview").

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
      Category names (Security Updates, Critical Updates, Update Rollups,
        Updates, Drivers, Upgrades, Definition Updates...) as listed by
        N-able's "Microsoft patch classifications" page (a third party, not
        Microsoft):
        https://documentation.n-able.com/N-central/userguide/Content/Patch-Management/Microsoft_Patch_Classifications.htm
      IUpdate.Type values (1 = software, 2 = driver), Microsoft Learn:
        https://learn.microsoft.com/en-us/windows/win32/api/wuapi/ne-wuapi-updatetype
      WUA API overview, Microsoft Learn:
        https://learn.microsoft.com/en-us/windows/win32/wua_sdk/windows-update-agent--wua--api-reference

    NOT VERIFIED: this was written without being able to run PowerShell on
    Windows, so it has not been executed on a device (only a syntax parse was
    done). Test with -CheckOnly on one machine first and read the log to
    confirm the category names match what your devices actually report.
    In particular, the monthly Windows 11 cumulative update is ASSUMED to
    carry the "Security Updates" category; if the log shows it as "Updates"
    only, it will be skipped and the filter needs changing.
#>

[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$Reboot,
    [switch]$IncludePreview,
    [switch]$IncludePendingFileRename,
    [int]$TimeoutMinutes = 45,
    [string]$LogPath = (Join-Path $env:ProgramData 'LincolnIT\WindowsUpdates')
)

# Stop on any unexpected error so a failure is never silently ignored.
$ErrorActionPreference = 'Stop'

# Exit codes (documented in the header).
$EXIT_OK = 0; $EXIT_PENDING = 1; $EXIT_PRECHECK = 3; $EXIT_REBOOT = 3010; $EXIT_FAILED = 4; $EXIT_TIMEOUT = 5

# Category names that make an update count as quality/security (see header).
$WantedCategories = @('Security Updates', 'Critical Updates', 'Update Rollups')

# ---------------------------------------------------------------- logging
# A transcript gives a record of what happened when the script runs unattended.
if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
$logFile = Join-Path $LogPath ("WindowsUpdates-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $logFile -Force | Out-Null

# Helper: ends the script cleanly, always stopping the transcript first.
function Exit-Script([int]$Code, [string]$Message) {
    Write-Output $Message
    Stop-Transcript | Out-Null
    exit $Code
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

try {
    # 1. Elevation: installing updates needs admin rights (TRMM runs as SYSTEM, which is fine).
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Exit-Script $EXIT_PRECHECK 'Not running as administrator.' }

    # 2. Search. IsHidden=0 respects updates someone has deliberately hidden.
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    Write-Output 'Searching Windows Update...'
    $all = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates
    Write-Output "Windows Update returned $($all.Count) pending update(s) in total."

    # 3. Filter. Each update's categories are read from the update itself.
    $selected = New-Object System.Collections.ArrayList
    foreach ($u in $all) {
        $cats = @($u.Categories | ForEach-Object { $_.Name })

        # Work out why an update is excluded, if it is.
        $skip = $null
        if (-not ($cats | Where-Object { $WantedCategories -contains $_ })) { $skip = 'category not security/critical/rollup' }
        elseif ($cats -contains 'Upgrades' -or $u.Title -match '^Feature update') { $skip = 'feature update' }
        elseif ($u.Type -eq 2 -or $cats -contains 'Drivers') { $skip = 'driver' }   # IUpdate.Type 2 = driver
        elseif (-not $IncludePreview -and $u.Title -match 'Preview') { $skip = 'optional preview update' }
        elseif ($u.InstallationBehavior.CanRequestUserInput) { $skip = 'may need user input' }

        if ($skip) {
            Write-Output "  SKIP  [$skip] $($u.Title)  (categories: $($cats -join ', '))"
        } else {
            Write-Output "  KEEP  $($u.Title)  (categories: $($cats -join ', '))"
            [void]$selected.Add($u)
        }
    }

    if ($selected.Count -eq 0) { Exit-Script $EXIT_OK 'No pending quality/security updates.' }

    # 4. Check-only mode: report and stop.
    if ($CheckOnly) { Exit-Script $EXIT_PENDING "$($selected.Count) quality/security update(s) pending (check only, nothing installed)." }

    # 5. A pending reboot can make installs fail, so stop and ask for a reboot first.
    $pending = Get-PendingRebootReasons
    if ($pending.Count -gt 0) { Exit-Script $EXIT_PRECHECK "A reboot is already pending ($($pending -join ', ')). Reboot, then run this again." }

    # Download and install in a worker job (see Invoke-WuInstall), with progress and a timeout.
    Write-Output "Downloading and installing $($selected.Count) update(s)... (will give up after $TimeoutMinutes minutes in total)"
    $res = Invoke-WuInstall $selected

    # 6. Per-update outcome. ResultCode: 2 = succeeded, 3 = succeeded with errors, 4 = failed, 5 = aborted.
    $failed = 0
    foreach ($r in $res.Results) {
        $ok = $r.ResultCode -in 2, 3
        if (-not $ok) { $failed++ }
        Write-Output ("  {0}  result {1} (HRESULT 0x{2:X})  {3}" -f $(if ($ok) { 'OK  ' } else { 'FAIL' }), $r.ResultCode, $r.HResult, $r.Title)
    }
    if ($failed -gt 0) { Exit-Script $EXIT_FAILED "$failed of $($res.Results.Count) update(s) failed. See the log: $logFile" }

    # 7. Restart handling.
    if ($res.Summary.RebootRequired) {
        if ($Reboot) {
            Write-Output 'Installed. Restarting in 60 seconds.'
            Stop-Transcript | Out-Null
            shutdown.exe /r /t 60 /c 'Windows updates installed: restarting to finish.'
            exit $EXIT_REBOOT
        }
        Exit-Script $EXIT_REBOOT 'Installed. Restart required to finish.'
    }
    Exit-Script $EXIT_OK 'Installed. No restart required.'
}
catch {
    Exit-Script $EXIT_FAILED "FAILED: $($_.Exception.Message)"
}

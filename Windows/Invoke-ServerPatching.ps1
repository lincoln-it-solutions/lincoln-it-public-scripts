<#
.SYNOPSIS
    TRMM task for SERVERS: runs daily at 03:00, and only in the server type's
    patching week checks for and installs quality/security updates, finishing by
    05:00. Never restarts the server.

.DESCRIPTION
    DECISIONS (Ethan, 2026-10-25)
      - WUfB for servers, no automatic restart (Set-WUfBServerPolicy.ps1 puts
        servers in download-only mode, so Windows never installs by itself).
      - Check at 03:00, patching completed by 05:00.
      - Patching week per server type, counted in weeks AFTER Patch Tuesday
        (second Tuesday of the month): week 1 = the 7 days starting the day after
        Patch Tuesday, week 2 = the next 7, and so on. Patch cycles are 4 or 5
        weeks long, so week 5 only exists in some months.
      - No WUfB deferral on servers: the patching week is the delay.
      - Server types, checked in this order (first match wins):
          dc    = domain controller (Win32_OperatingSystem ProductType 2)
          host  = Hyper-V host (the "vmms" Hyper-V Virtual Machine Management
                  service exists). VMware ESXi hosts are not Windows and have no
                  TRMM agent, so they can't be patched by this script.
          vm    = virtual machine (hardware model/manufacturer text)
          other = anything else (physical, non-hypervisor servers)
      - One script, weeks set in the Global Keystore "wu_server_patch_weeks",
        passed in as WU_SERVER_PATCH_WEEKS={{global.wu_server_patch_weeks}}.
        Ethan's order 2026-10-25: hosts, then DCs, then other servers in week 3:
            host=1;dc=2;vm=3;other=3
        A type with no entry (e.g. "other") is NOT patched; the script says so.
      - Opt-out: TRMM checkbox custom field "Exclude From Patching" on the Client,
        Site or Agent. Passed in as
            WU_EXCLUDE_CLIENT={{client.Exclude From Patching}}
            WU_EXCLUDE_SITE={{site.Exclude From Patching}}
            WU_EXCLUDE_AGENT={{agent.Exclude From Patching}}
        TRMM sends a checkbox to PowerShell as the text "$True"/"$False"
        (tacticalrmm api/tacticalrmm/tacticalrmm/utils.py format_shell_bool).

    WHAT IT DOES, IN ORDER
      1. Server only; exits if excluded.
      2. Works out the type and this server's week; exits quietly if this is
         not its week, or if the time is outside 03:00-05:00 (unless -Force).
      3. Aborts if a reboot is already pending (installs can fail on top of a
         pending reboot), so last month's restart must be done first.
      4. Searches Windows Update and keeps only Security Updates, Critical
         Updates and Update Rollups, skipping feature updates, drivers, previews
         and any KB on the blocked list (Keystore wu_blocked_kbs). Same filter as
         Install-WindowsQualityUpdates.ps1.
      5. Installs ONE update at a time, so it can stop cleanly at the deadline:
         no new update is started within -LastStartMinutes of 05:00, and the
         script stops waiting at 05:00. Windows cannot safely abort an install
         that is already running; if one is still going at 05:00 it carries on
         in the background and the script reports that.

    EXIT CODES (Stop-Check)
      0 = nothing to do: not this server's week, outside the window, excluded,
          no week set for its type, or no updates pending
      1 = report only (-Apply not given): updates are pending
      2 = error: install failed, reboot already pending, or script error
      3 = installed, restart needed (restarts are manual)
      4 = deadline reached with updates still to install

.PARAMETER Apply
    Install. Without it the script only lists what it would install.

.PARAMETER Force
    For testing: ignore the patching week and the 03:00-05:00 window. The
    deadline then becomes 2 hours from now. Still report-only without -Apply.

.PARAMETER LastStartMinutes
    Don't start another update when fewer than this many minutes remain before
    the deadline. Default 20 is MY choice (a monthly cumulative update can take
    longer than that), not Ethan's; change it if needed.

.NOTES
    Sources:
      AUOptions values (download-only mode is set by Set-WUfBServerPolicy.ps1):
        https://learn.microsoft.com/zh-tw/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd939844(v=ws.10)
      Windows Update Agent API, Microsoft Learn:
        https://learn.microsoft.com/en-us/windows/desktop/api/wuapi/nn-wuapi-iupdatesearcher
      Win32_OperatingSystem ProductType (1 workstation, 2 DC, 3 server):
        https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
      Worker-job install pattern: copied from Install-WindowsQualityUpdates.ps1
      (synchronous calls in a child job; the async calls failed on ULSULAPTOP31).

    NOT VERIFIED: not run on Windows (syntax parse only). VM detection uses
    Win32_ComputerSystem Model/Manufacturer text ("Virtual Machine", "VMware",
    "VirtualBox", "KVM", "QEMU", "Xen"); those strings are from my own
    knowledge, not a fetched page; so is using the "vmms" service to spot a
    Hyper-V host. Test with -Force (report only) on one VM and
    one DC first and check the "Type:" line.
#>

[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Force,
    [string]$WindowStart = '03:00',
    [string]$Deadline = '05:00',
    [int]$LastStartMinutes = 20,
    [string]$Weeks = '',
    [string]$BlockedKbs = ''
)

$ErrorActionPreference = 'Stop'

# Exit code helper: plain "exit 2" reaches TRMM as 1, SetShouldExit passes the
# real code (same helper as Monitor-ESET.ps1, tested on Steve-Win11 2026-10-20).
function Stop-Check([int]$Code) {
    $host.SetShouldExit($Code)
    exit $Code
}

# Opt-out custom fields. Checkbox arrives as "$True"/"$False"; a missing field
# means the env var is not set at all, which counts as "not excluded".
function Get-PatchingExclusion {
    foreach ($n in 'WU_EXCLUDE_CLIENT', 'WU_EXCLUDE_SITE', 'WU_EXCLUDE_AGENT') {
        $v = [Environment]::GetEnvironmentVariable($n)
        if ("$v" -match '^\$?true$|^1$') { return $n }
    }
    return $null
}

# Patch Tuesday = second Tuesday of the month.
function Get-PatchTuesday([int]$Year, [int]$Month) {
    $d = (Get-Date -Year $Year -Month $Month -Day 1).Date   # .Date = midnight
    while ($d.DayOfWeek -ne [DayOfWeek]::Tuesday) { $d = $d.AddDays(1) }
    return $d.AddDays(7)
}

# Week number after the most recent Patch Tuesday (week 1 starts the day after it).
function Get-PatchWeek([datetime]$Today) {
    $pt = Get-PatchTuesday $Today.Year $Today.Month
    if ($Today.Date -le $pt) { $prev = $Today.AddMonths(-1); $pt = Get-PatchTuesday $prev.Year $prev.Month }
    $days = ($Today.Date - $pt).Days
    return [pscustomobject]@{ Week = [int][math]::Floor(($days - 1) / 7) + 1; PatchTuesday = $pt }
}

try {
    # --- 1. Admin, servers only, opt-out.
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Output 'ERROR: not running as administrator.'; Stop-Check 2 }

    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.ProductType -eq 1) { Write-Output 'Out of scope: workstation.'; Stop-Check 0 }

    $excl = Get-PatchingExclusion
    if ($excl) { Write-Output "EXCLUDED from patching ($excl is ticked). Nothing done."; Stop-Check 0 }

    # --- 2. Type. ProductType 2 = domain controller (wins over VM).
    $cs = Get-CimInstance Win32_ComputerSystem
    $hw = "$($cs.Manufacturer) $($cs.Model)"
    # Hyper-V host = the Hyper-V Virtual Machine Management service (vmms) exists.
    # Order of precedence: dc, host, vm, other.
    $isHyperVHost = [bool](Get-Service -Name vmms -ErrorAction SilentlyContinue)
    if ($os.ProductType -eq 2) { $type = 'dc' }
    elseif ($isHyperVHost) { $type = 'host' }
    elseif ($hw -match 'Virtual Machine|VMware|VirtualBox|KVM|QEMU|Xen') { $type = 'vm' }
    else { $type = 'other' }
    Write-Output "Type: $type  ($($os.Caption); hardware '$hw')"

    # Week list: env var (Keystore) first, then -Weeks.
    if (-not $Weeks) { $Weeks = $env:WU_SERVER_PATCH_WEEKS }
    $weekMap = @{}
    foreach ($entry in ("$Weeks" -split '[;\r\n]+')) {
        $entry = $entry.Trim()
        if (-not $entry -or $entry.StartsWith('#')) { continue }
        $k, $v = $entry -split '=', 2
        if ("$v".Trim() -match '^[1-5]$') { $weekMap[$k.Trim().ToLower()] = [int]$v.Trim() }
        else { Write-Output "WARNING: bad week entry '$entry' ignored (expected type=1..5)." }
    }
    if (-not $weekMap.ContainsKey($type)) { Write-Output "No patching week set for type '$type' in wu_server_patch_weeks. Not patched."; Stop-Check 0 }

    $now = Get-Date
    $pw = Get-PatchWeek $now
    Write-Output ("Patch Tuesday {0:yyyy-MM-dd}; today is week {1}; '{2}' patches in week {3}." -f $pw.PatchTuesday, $pw.Week, $type, $weekMap[$type])

    # Window: today WindowStart..Deadline, unless -Force.
    $start = [datetime]::ParseExact($WindowStart, 'HH:mm', $null)
    $end   = [datetime]::ParseExact($Deadline, 'HH:mm', $null)
    $windowStart = $now.Date.Add($start.TimeOfDay)
    $windowEnd   = $now.Date.Add($end.TimeOfDay)
    if ($Force) {
        $windowEnd = $now.AddHours(2)
        Write-Output "FORCE: ignoring week and window; deadline $($windowEnd.ToString('HH:mm'))."
    } else {
        if ($pw.Week -ne $weekMap[$type]) { Write-Output 'Not this server''s patching week. Nothing done.'; Stop-Check 0 }
        if ($now -lt $windowStart -or $now -ge $windowEnd) { Write-Output "Outside the $WindowStart-$Deadline window. Nothing done."; Stop-Check 0 }
    }
    $lastStart = $windowEnd.AddMinutes(-$LastStartMinutes)

    # --- 3. Pending reboot blocks installs (restarts are manual on servers).
    $pending = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'ComponentBasedServicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'WindowsUpdate' }
    if ($pending.Count -gt 0) { Write-Output "ERROR: a restart is already pending ($($pending -join ', ')). Restart the server, then it will patch on the next run in its week."; Stop-Check 2 }

    # --- 4. Blocked KBs (same list and format as the workstation scripts).
    if (-not $BlockedKbs) { $BlockedKbs = $env:WU_BLOCKED_KBS }
    $blocked = @{}
    foreach ($line in ("$BlockedKbs" -split '[;\r\n]+')) {
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        $kb = ($line -split '=', 2)[0].Trim().ToUpper()
        if ($kb -match '^KB\d{6,8}$') { $blocked[$kb] = $true }
    }

    # Search and filter. IsHidden=0 respects updates hidden on purpose.
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    Write-Output 'Searching Windows Update...'
    $all = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates
    $wantedCats = @('Security Updates', 'Critical Updates', 'Update Rollups')
    $selected = @()
    foreach ($u in $all) {
        $cats = @($u.Categories | ForEach-Object { $_.Name })
        $kbs  = @($u.KBArticleIDs | ForEach-Object { "KB$_" })
        $skip = $null
        if (-not ($cats | Where-Object { $wantedCats -contains $_ })) { $skip = 'category not security/critical/rollup' }
        elseif ($cats -contains 'Upgrades' -or $u.Title -match '^Feature update') { $skip = 'feature update' }
        elseif ($u.Type -eq 2 -or $cats -contains 'Drivers') { $skip = 'driver' }
        elseif ($u.Title -match 'Preview') { $skip = 'optional preview' }
        elseif (@($kbs | Where-Object { $blocked.ContainsKey($_) }).Count -gt 0) { $skip = 'blocked KB (wu_blocked_kbs)' }
        elseif ($u.InstallationBehavior.CanRequestUserInput) { $skip = 'may need user input' }
        if ($skip) { Write-Output "  SKIP  [$skip] $($u.Title)" }
        else       { Write-Output "  KEEP  $($u.Title)"; $selected += [pscustomobject]@{ Id = $u.Identity.UpdateID; Rev = $u.Identity.RevisionNumber; Title = $u.Title } }
    }
    if ($selected.Count -eq 0) { Write-Output 'No pending quality/security updates.'; Stop-Check 0 }
    if (-not $Apply) { Write-Output "REPORT ONLY: $($selected.Count) update(s) would be installed."; Stop-Check 1 }

    # --- 5. Install one at a time in a child job, so the deadline can be enforced.
    $failed = 0; $done = 0; $rebootNeeded = $false; $hitDeadline = $false
    foreach ($s in $selected) {
        if ((Get-Date) -ge $lastStart) { $hitDeadline = $true; Write-Output "Deadline: not starting '$($s.Title)' (less than $LastStartMinutes min before $($windowEnd.ToString('HH:mm')))."; break }
        Write-Output ("[{0:HH:mm}] Installing: {1}" -f (Get-Date), $s.Title)

        $job = Start-Job -ArgumentList $s.Id, $s.Rev -ScriptBlock {
            param($id, $rev)
            $ErrorActionPreference = 'Stop'
            $session  = New-Object -ComObject Microsoft.Update.Session
            $coll     = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($u in $session.CreateUpdateSearcher().Search("UpdateID='$id' and RevisionNumber=$rev").Updates) {
                if (-not $u.EulaAccepted) { $u.AcceptEula() }   # downloads are refused with an unaccepted EULA
                [void]$coll.Add($u)
            }
            if ($coll.Count -ne 1) { throw "Worker found $($coll.Count) updates for $id." }
            $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll
            $d = $dl.Download()
            if ($d.ResultCode -notin 2, 3) { throw "Download failed, result code $($d.ResultCode)." }   # 2 ok, 3 ok with errors
            $inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll
            $inst.AllowSourcePrompts = $false   # never prompt: runs as SYSTEM
            $res = $inst.Install()
            $r = $res.GetUpdateResult(0)
            [pscustomobject]@{ ResultCode = [int]$r.ResultCode; HResult = [int]$r.HResult; RebootRequired = [bool]$res.RebootRequired }
        }

        # Wait, but never past the deadline.
        while ($job.State -in 'Running', 'NotStarted' -and (Get-Date) -lt $windowEnd) { Start-Sleep -Seconds 10 }
        if ($job.State -in 'Running', 'NotStarted') {
            # Leave the install alone (aborting mid-install is unsafe); just stop waiting.
            $hitDeadline = $true
            Write-Output "Deadline $($windowEnd.ToString('HH:mm')) reached while '$($s.Title)' was still installing; it continues in the background."
            break
        }
        if ($job.State -eq 'Failed') {
            $failed++; Write-Output "  FAIL  $($job.ChildJobs[0].JobStateInfo.Reason.Message)"
            Remove-Job $job -Force; continue
        }
        $r = Receive-Job $job | Select-Object -Last 1
        Remove-Job $job -Force
        if ($r.ResultCode -in 2, 3) { $done++; if ($r.RebootRequired) { $rebootNeeded = $true }; Write-Output '  OK' }
        else { $failed++; Write-Output ("  FAIL  result {0} (HRESULT 0x{1:X8})" -f $r.ResultCode, $r.HResult) }
    }

    Write-Output "Installed $done, failed $failed, of $($selected.Count)."
    if ($failed -gt 0)  { Stop-Check 2 }
    if ($hitDeadline)   { Stop-Check 4 }
    if ($rebootNeeded)  { Write-Output 'Restart needed (manual).'; Stop-Check 3 }
    Stop-Check 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Stop-Check 2
}

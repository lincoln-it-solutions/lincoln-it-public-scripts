<#
.SYNOPSIS
    TRMM script check for workstations AND servers patched by Windows Update for
    Business (Set-WUfBPolicy.ps1 / Set-WUfBServerPolicy.ps1 + Invoke-ServerPatching.ps1).
    Hides blocked KBs and reports patch health. Devices with the "Exclude From
    Patching" checkbox ticked (Client, Site or Agent) pass without being checked.
    Server differences: policy drift is checked against the server download-only
    values, and a pending restart is a Warning (restarts are manual on servers).

.DESCRIPTION
    WHAT IT CHECKS
      1. Windows Update service (wuauserv) is not Disabled                  -> Critical
      2. A non-preview cumulative update installed successfully within
         -MaxDaysSinceCU days (default 45 = 14-day deferral + a month,
         my own choice, change if needed)                                   -> Critical
      3. Installs that failed in the last -FailedLookbackDays (default 7)    -> Warning
      4. WUfB policy values match what Set-WUfBPolicy.ps1 sets               -> Warning
         (same defaults: 14 days, 26H2 / Windows 10 22H2, AUOptions 4)
      5. Blocked KBs (list below) that are already INSTALLED                 -> Warning
         (the script never uninstalls anything)
    A pending reboot is printed for information only, because
    Invoke-RebootNag.ps1 already handles restarts.

    BLOCKED KB LIST
    One shared list in the TRMM Global Keystore, key "wu_blocked_kbs", passed in
    with the script environment variable WU_BLOCKED_KBS={{global.wu_blocked_kbs}}
    (same pattern as CHOCO_PACKAGES for the Chocolatey scripts). Format, one per
    line (or separated by ;), lines starting with # ignored:
        KB5012345=reason it is blocked
        KB5012345=reason it is blocked|remove
    Adding "|remove" also tells Remove-BlockedKB.ps1 to uninstall the KB from
    devices that already have it; this check only blocks (hides).
    With -Apply, pending updates whose KB is on the list are HIDDEN, so Windows
    Update will not install them. Each KB this script hides is recorded in
    HKLM:\SOFTWARE\LincolnIT\WindowsPatching (value HiddenKBs); when a KB is
    taken off the list, the script UNHIDES it again. KBs hidden by anyone else
    are never touched.
    Without -Apply, the script only reports what it would hide or unhide.

    LIMIT TO KNOW ABOUT: an update can only be hidden once Windows Update
    offers it to the device, which with a 14-day deferral is after the
    deferral ends. The device then installs it at its next automatic run, so
    hiding is a race. Run this check often (e.g. every 1-4 hours) and add a
    bad KB to the list as early as possible.

    EXIT CODES (passed to TRMM with Stop-Check)
      0 = OK, or out of scope (server)
      1 = Warning
      2 = Critical
    In TRMM set the check's warning return codes to [1]; 2 then counts as Error.

.PARAMETER Apply
    Actually hide/unhide KBs from the blocked list. Without it, report only.

.NOTES
    Sources:
      Windows Update Agent API (IUpdateSearcher, IUpdate.IsHidden, QueryHistory),
      Microsoft Learn:
        https://learn.microsoft.com/en-us/windows/desktop/api/wuapi/nn-wuapi-iupdatesearcher
        https://learn.microsoft.com/windows/win32/wua_sdk/windows-update-agent-object-model
      Reboot markers and ResultCode meanings: same as Install-WindowsQualityUpdates.ps1
      in this repo.

    LIVE NOTES (first run 2026-10-26 on WWS / Lincoln IT):
      - Cumulative update title match fixed: current monthly OS update titles look like
        "2026-08 Security Update (KB5121003) (26200.9168)" (confirmed from TRMM's own
        update scan of Steve-Win11 and WWS-LT02). The older "Cumulative Update for
        Windows" form is still accepted; previews and .NET updates are excluded.
      - Store app (e.g. "9WZDNCRFHWKN-...") and Defender definition install failures
        (0x80240034) are no longer reported as failed installs.
#>

[CmdletBinding()]
param(
    [switch]$Apply,
    [int]$MaxDaysSinceCU = 45,
    [int]$FailedLookbackDays = 7,
    [int]$QualityDeferralDays = 14,
    [string]$TargetFeatureVersion = '26H2',
    [string]$Windows10Version = '22H2',
    [string]$BlockedKbs = ''
)

$ErrorActionPreference = 'Stop'

# Exit code helper: plain "exit 2" reaches TRMM as 1, SetShouldExit passes the
# real code (same helper as Monitor-ESET.ps1, tested on Steve-Win11 2026-10-20).
function Stop-Check([int]$Code) {
    $host.SetShouldExit($Code)
    exit $Code
}

# Findings are collected first so the output is one readable summary.
$Critical = New-Object System.Collections.Generic.List[string]
$Warning  = New-Object System.Collections.Generic.List[string]
$Info     = New-Object System.Collections.Generic.List[string]

try {
    # --- Scope: workstations only (ProductType 1), same as Set-WUfBPolicy.ps1.
    $os = Get-CimInstance Win32_OperatingSystem
    # Servers are in scope since 2026-10-25 (WUfB download-only + Invoke-ServerPatching.ps1);
    # ProductType 1 = workstation, 2 = DC, 3 = server.
    $isServer = $os.ProductType -ne 1

    # Opt-out: "Exclude From Patching" checkbox on Client, Site or Agent (arrives as "$True"/"$False",
    # tacticalrmm utils.py format_shell_bool). Excluded devices pass and are not changed.
    foreach ($exclVar in 'WU_EXCLUDE_CLIENT', 'WU_EXCLUDE_SITE', 'WU_EXCLUDE_AGENT') {
        if ("$([Environment]::GetEnvironmentVariable($exclVar))" -match '^\$?true$|^1$') {
            Write-Output "EXCLUDED from patching ($exclVar is ticked). Not checked."
            Stop-Check 0
        }
    }
    $build = [int]$os.BuildNumber

    # --- 1. Windows Update service must not be disabled, or nothing installs.
    $svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if (-not $svc) { $Critical.Add('Windows Update service (wuauserv) not found.') }
    elseif ($svc.StartType -eq 'Disabled') { $Critical.Add('Windows Update service (wuauserv) is Disabled.') }

    # --- Windows Update Agent session, used by checks 2, 3 and the KB list.
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()

    # --- 2 and 3. Update history. Operation 1 = installation; ResultCode
    #     2 = succeeded, 3 = succeeded with errors, 4 = failed, 5 = aborted.
    $count   = $searcher.GetTotalHistoryCount()
    $history = if ($count -gt 0) { @($searcher.QueryHistory(0, $count)) } else { @() }
    $installs = $history | Where-Object { $_.Operation -eq 1 }

    $lastCU = $installs |
        Where-Object { $_.ResultCode -in 2, 3 -and ($_.Title -match '^\d{4}-\d{2} Security Update \(KB\d+\) \(\d+\.\d+\)' -or $_.Title -match 'Cumulative Update for Windows') -and $_.Title -notmatch 'Preview|\.NET' } |
        Sort-Object Date -Descending | Select-Object -First 1
    # FALLBACK: Windows Update history can be empty of cumulative updates (seen on WWS-LT01 on
    # 2026-10-26: history held only 6 Defender/hardware entries, yet Get-HotFix listed the Oct
    # security updates and the build was current). So when history has none, use the newest
    # "Security Update" in Win32_QuickFixEngineering instead of raising a false CRITICAL.
    # LIMIT: that list can also contain .NET security updates, and InstalledOn is date-only.
    $hotfix = $null
    if (-not $lastCU) {
        $hotfix = Get-HotFix -ErrorAction SilentlyContinue |
            Where-Object { $_.Description -eq 'Security Update' -and $_.InstalledOn } |
            Sort-Object InstalledOn -Descending | Select-Object -First 1
    }
    if ($hotfix) {
        $age = [int]((Get-Date) - $hotfix.InstalledOn).TotalDays
        $Info.Add("Last security update (from installed hotfixes, Windows Update history had none): $($hotfix.HotFixID) on $($hotfix.InstalledOn.ToString('yyyy-MM-dd')) ($age days ago)")
        if ($age -gt $MaxDaysSinceCU) { $Critical.Add("Last security update is $age days old (limit $MaxDaysSinceCU).") }
    } elseif (-not $lastCU) {
        $Critical.Add('No successful cumulative update found in Windows Update history or installed hotfixes.')
    } else {
        # History dates are UTC; compare in UTC.
        $age = [int]((Get-Date).ToUniversalTime() - $lastCU.Date).TotalDays
        $Info.Add("Last cumulative update: $($lastCU.Title) on $($lastCU.Date.ToString('yyyy-MM-dd')) ($age days ago)")
        if ($age -gt $MaxDaysSinceCU) { $Critical.Add("Last cumulative update is $age days old (limit $MaxDaysSinceCU).") }
    }

    $since  = (Get-Date).ToUniversalTime().AddDays(-$FailedLookbackDays)
    # Store app updates (title starts with a 12-character Store product ID, e.g. 9WZDNCRFHWKN-) and
    # Defender definition updates are not OS patching, so their failures are not reported here.
    $failed = $installs | Where-Object { $_.ResultCode -in 4, 5 -and $_.Date -ge $since -and
        $_.Title -notmatch '^9[A-Z0-9]{11}-' -and $_.Title -notmatch 'Security Intelligence Update|Definition Update' }
    foreach ($f in $failed) {
        $Warning.Add(("Install failed {0:yyyy-MM-dd}: {1} (HRESULT 0x{2:X8})" -f $f.Date, $f.Title, $f.HResult))
    }

    # --- 4. Policy drift against what Set-WUfBPolicy.ps1 (workstations) or
    #     Set-WUfBServerPolicy.ps1 (servers) writes.
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    if ($isServer) {
        $policyScript = 'Set-WUfBServerPolicy.ps1'
        $expect = @(@("$wu\AU", 'NoAutoUpdate', 0), @("$wu\AU", 'AUOptions', 3), @("$wu\AU", 'NoAutoRebootWithLoggedOnUsers', 1))
    } else {
        $policyScript = 'Set-WUfBPolicy.ps1'
        if ($build -ge 22000) { $product = 'Windows 11'; $target = $TargetFeatureVersion } else { $product = 'Windows 10'; $target = $Windows10Version }
        $expect = @(
            @($wu, 'DeferQualityUpdates', 1), @($wu, 'DeferQualityUpdatesPeriodInDays', $QualityDeferralDays),
            @($wu, 'TargetReleaseVersion', 1), @($wu, 'ProductVersion', $product), @($wu, 'TargetReleaseVersionInfo', $target),
            @("$wu\AU", 'NoAutoUpdate', 0), @("$wu\AU", 'AUOptions', 4), @("$wu\AU", 'NoAutoRebootWithLoggedOnUsers', 1)
        )
    }
    foreach ($e in $expect) {
        $v = (Get-ItemProperty -Path $e[0] -Name $e[1] -ErrorAction SilentlyContinue).($e[1])
        if ("$v" -ne "$($e[2])") {
            $Warning.Add("Policy drift: $($e[1]) is '$(if ($null -eq $v) { 'not set' } else { $v })', expected '$($e[2])' (run $policyScript -Apply).")
        }
    }

    # --- 5. Blocked KB list. Env var first (avoids TRMM argument quoting issues,
    #     same reason as choco-adopt.ps1), then the -BlockedKbs argument.
    if (-not $BlockedKbs) { $BlockedKbs = $env:WU_BLOCKED_KBS }
    $blocked = @{}
    foreach ($line in ("$BlockedKbs" -split '[;\r\n]+')) {
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        $kb, $reason = $line -split '=', 2
        $kb = $kb.Trim().ToUpper()
        if ($kb -notmatch '^KB\d{6,8}$') { $Warning.Add("Blocked KB list: bad entry '$line' (expected KB1234567=reason)."); continue }
        # A trailing "|remove" is for Remove-BlockedKB.ps1; keep it as a flag here
        # only so the warning below can say removal is requested.
        $blocked[$kb] = "$reason".Trim()
    }

    # KBs this script hid on earlier runs (so they can be unhidden later).
    $stateKey = 'HKLM:\SOFTWARE\LincolnIT\WindowsPatching'
    $hiddenByUs = @((Get-ItemProperty -Path $stateKey -Name HiddenKBs -ErrorAction SilentlyContinue).HiddenKBs | Where-Object { $_ })

    # Blocked but already installed: report only, never uninstall.
    $warnedKb = @{}
    foreach ($h in $installs | Where-Object { $_.ResultCode -in 2, 3 }) {
        foreach ($kb in $blocked.Keys) {
            if ($h.Title -match "\b$kb\b") {
                # History keeps old entries after an uninstall, so confirm it is still
                # installed via Win32_QuickFixEngineering before warning.
                if ($warnedKb.ContainsKey($kb)) { continue }   # history can list the same KB more than once
                if (-not (Get-HotFix -Id $kb -ErrorAction SilentlyContinue)) { continue }
                $warnedKb[$kb] = $true
                $how = if ($blocked[$kb] -match '\|\s*remove\s*$') { 'removal requested, run Remove-BlockedKB.ps1' } else { 'add |remove to its list entry to uninstall it' }
                $Warning.Add("Blocked $kb is already installed ($how): $($h.Title)")
            }
        }
    }

    # Search includes hidden updates so ones we hid earlier can be found again.
    $pending = @($searcher.Search("IsInstalled=0 and Type='Software'").Updates)
    $nowHidden = New-Object System.Collections.Generic.List[string]
    foreach ($kb in $hiddenByUs) { $nowHidden.Add($kb) }

    foreach ($u in $pending) {
        $kbs = @($u.KBArticleIDs | ForEach-Object { "KB$_" })
        $isBlocked = @($kbs | Where-Object { $blocked.ContainsKey($_) })
        $wasOurs   = @($kbs | Where-Object { $hiddenByUs -contains $_ })

        if ($isBlocked.Count -gt 0 -and -not $u.IsHidden) {
            # Blocked and not hidden yet: hide it.
            if ($Apply) { $u.IsHidden = $true; $isBlocked | ForEach-Object { if (-not $nowHidden.Contains($_)) { $nowHidden.Add($_) } } ; $Info.Add("Hidden: $($u.Title)") }
            else        { $Warning.Add("Would hide (report only): $($u.Title)") }
        }
        elseif ($isBlocked.Count -eq 0 -and $wasOurs.Count -gt 0 -and $u.IsHidden) {
            # We hid it before and it is no longer on the list: unhide it.
            if ($Apply) { $u.IsHidden = $false; $wasOurs | ForEach-Object { [void]$nowHidden.Remove($_) }; $Info.Add("Unhidden (removed from block list): $($u.Title)") }
            else        { $Info.Add("Would unhide (report only): $($u.Title)") }
        }
    }

    # Save which KBs we are responsible for hiding.
    if ($Apply) {
        if (-not (Test-Path $stateKey)) { New-Item -Path $stateKey -Force | Out-Null }
        New-ItemProperty -Path $stateKey -Name HiddenKBs -PropertyType MultiString -Value ([string[]]$nowHidden) -Force | Out-Null
    }

    # --- Pending reboot: information only (Invoke-RebootNag.ps1 handles it).
    # --- Pending reboot. Workstations: info only (the reboot nag handles it).
    #     Servers: Warning, because restarts are manual and a pending restart stops
    #     Invoke-ServerPatching.ps1 installing next cycle.
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        if ($isServer) { $Warning.Add('Server restart pending to finish updates (restarts are manual; patching is blocked until it is done).') }
        else { $Info.Add('Reboot pending for Windows Update (handled by the reboot nag).') }
    }
}
catch {
    $Critical.Add("Script error: $($_.Exception.Message)")
}

# --- Summary and exit code.
foreach ($c in $Critical) { Write-Output "CRITICAL: $c" }
foreach ($w in $Warning)  { Write-Output "WARNING:  $w" }
foreach ($i in $Info)     { Write-Output "INFO:     $i" }
if ($Critical.Count -gt 0) { Stop-Check 2 }
if ($Warning.Count -gt 0)  { Stop-Check 1 }
Write-Output 'OK: patching healthy.'
Stop-Check 0

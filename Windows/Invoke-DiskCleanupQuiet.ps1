<#
.SYNOPSIS
    Quiet C: drive cleanup for TRMM. Same cleanup targets as TRMM's built-in
    "Disk - Cleanup C: drive" (script id 11), but prints a short summary
    instead of one line per deleted file, and has a cooldown.

.DESCRIPTION
    Why this exists (2026-10-21): the built-in script runs every Remove-Item
    with -Verbose and starts a transcript, so each run printed ~1.4 MB of
    output. It is the action of the "Disk Cleanup" task on the Workstation
    Baselines policy, which runs ON CHECK FAILURE of the C: disk space check.
    A machine that stays under the warning threshold re-runs it on every
    check (~34 times a day on RichardEdwards-Win11), and TRMM stores every
    run's output in agent history. One agent reached ~2.5 GB of history, and
    its History tab (an unpaged API response, ~1.08 GB) broke the TRMM UI.

    What it cleans (unchanged from the built-in script):
      - C:\Windows\SoftwareDistribution\* (Windows Update service stopped first)
      - C:\Windows\Temp\*, C:\Windows\minidump\*, C:\Windows\Prefetch\*
      - C:\Windows\logs\CBS\*.log, C:\Windows\memory.dmp
      - IIS logs older than 60 days (if IIS present)
      - C:\csback\* older than DaysToDelete
      - C:\Config.Msi, C:\Intel, C:\PerfLogs
      - Windows Error Reporting (machine and per-user)
      - Per-user: Temp, Temporary Internet Files, IECompatCache,
        IECompatUaCache, IEDownloadHistory, INetCache, INetCookies,
        Terminal Server Client cache
      - Recycle bin
      - Shrinks the SCCM client cache to 1 GB if SCCM is installed

    What changed versus the built-in script:
      - No -Verbose and no transcript: output is a few summary lines.
      - Cooldown: skips (exit 0) if it already ran within CooldownHours, so
        an on-check-failure task cannot run it dozens of times a day.
      - Windows Update service is restarted in a finally block, so it is not
        left stopped if something throws part-way through.

.PARAMETER DaysToDelete
    Age in days for the age-filtered folders (csback). Default 7, same as built-in.

.PARAMETER CooldownHours
    Minimum hours between real runs on one machine. Default 24. Pass 0 to force.

.NOTES
    Runs as SYSTEM from TRMM. Last-run time is kept in
    C:\ProgramData\LincolnIT\DiskCleanup\last-run.txt.
#>

param(
    # Same default as the built-in script.
    [int]$DaysToDelete = 7,

    # 24h cooldown so a failing disk check cannot loop this script.
    [int]$CooldownHours = 24
)

# Errors from locked or in-use files are expected during cleanup; don't print them.
$ErrorActionPreference = 'SilentlyContinue'

# --- Cooldown check -----------------------------------------------------------
# Store the last-run time in ProgramData so it survives reboots and the cleanup itself
# (the built-in script clears TEMP, so a marker there would be deleted).
$stateDir  = 'C:\ProgramData\LincolnIT\DiskCleanup'
$stateFile = Join-Path $stateDir 'last-run.txt'
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null

if ($CooldownHours -gt 0 -and (Test-Path $stateFile)) {
    # Parse the stored round-trip timestamp; if it is unreadable, treat it as "never run".
    # $last must start as a [datetime], not $null: Windows PowerShell 5.1 can't match
    # TryParse's out-parameter overload to an untyped [ref]$null (found in testing 2026-10-21).
    $last = [datetime]::MinValue
    $parsed = [datetime]::TryParse(([string](Get-Content $stateFile -Raw)).Trim(), [ref]$last)
    if ($parsed -and ((Get-Date) - $last).TotalHours -lt $CooldownHours) {
        # Exit 0 so TRMM doesn't treat a skipped run as a failure.
        Write-Output ("Skipped: last cleanup ran {0:yyyy-MM-dd HH:mm} (cooldown {1}h)." -f $last, $CooldownHours)
        exit 0
    }
}

# --- Helpers ------------------------------------------------------------------
# Free space on C: in GB, read before and after so the summary shows what was freed.
function Get-CFreeGB {
    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    [math]::Round($d.FreeSpace / 1GB, 2)
}

# Delete everything matching a path (wildcards allowed), with no output.
function Remove-Quiet([string]$Path) {
    Remove-Item -Path $Path -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
}

# Delete items under a path older than N days (by creation time), with no output.
function Remove-OlderThan([string]$Path, [int]$Days) {
    $cutoff = (Get-Date).AddDays(-$Days)
    Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -lt $cutoff } |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
}

$start  = Get-Date
$before = Get-CFreeGB
$disk   = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$sizeGB = [math]::Round($disk.Size / 1GB, 1)

try {
    # --- Windows Update cache ---------------------------------------------------
    # Stop wuauserv first, otherwise SoftwareDistribution files are locked.
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    # Shrink the SCCM cache to 1 GB if the SCCM client exists (same as built-in).
    $cache = Get-CimInstance -Namespace root\ccm\SoftMgmtAgent -ClassName CacheConfig -ErrorAction SilentlyContinue
    if ($cache) {
        Set-CimInstance -InputObject $cache -Property @{ Size = 1024 } -ErrorAction SilentlyContinue | Out-Null
        Restart-Service ccmexec -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }

    Remove-Quiet 'C:\Windows\SoftwareDistribution\*'

    # --- System locations ---------------------------------------------------------
    Remove-Quiet "$env:windir\Temp\*"
    Remove-Quiet "$env:windir\minidump\*"
    Remove-Quiet "$env:windir\Prefetch\*"
    Remove-Quiet 'C:\Windows\logs\CBS\*.log'
    Remove-Quiet "$env:windir\memory.dmp"
    Remove-Quiet 'C:\Config.Msi'
    Remove-Quiet 'C:\Intel'
    Remove-Quiet 'C:\PerfLogs'
    Remove-Quiet 'C:\ProgramData\Microsoft\Windows\WER\*'

    # csback only loses files older than DaysToDelete, as in the built-in script.
    Remove-OlderThan 'C:\csback\*' $DaysToDelete

    # IIS logs older than 60 days (the built-in script hard-codes 60 here, not DaysToDelete).
    if (Test-Path 'C:\inetpub\logs\LogFiles\') { Remove-OlderThan 'C:\inetpub\logs\LogFiles\*' 60 }

    # --- Per-user locations -------------------------------------------------------
    # Same per-user folders as the built-in script, for every profile under C:\Users.
    $userPaths = @(
        'AppData\Local\Temp\*',
        'AppData\Local\Microsoft\Windows\WER\*',
        'AppData\Local\Microsoft\Windows\Temporary Internet Files\*',
        'AppData\Local\Microsoft\Windows\IECompatCache\*',
        'AppData\Local\Microsoft\Windows\IECompatUaCache\*',
        'AppData\Local\Microsoft\Windows\IEDownloadHistory\*',
        'AppData\Local\Microsoft\Windows\INetCache\*',
        'AppData\Local\Microsoft\Windows\INetCookies\*',
        'AppData\Local\Microsoft\Terminal Server Client\Cache\*'
    )
    foreach ($p in $userPaths) { Remove-Quiet (Join-Path 'C:\Users\*' $p) }

    # --- Recycle bin --------------------------------------------------------------
    # Clear-RecycleBin exists on PowerShell 5+, which all supported Windows versions have.
    Clear-RecycleBin -DriveLetter C -Force -ErrorAction SilentlyContinue
    Remove-Quiet 'C:\$Recycle.Bin'
}
finally {
    # Always bring Windows Update back, even if something above failed.
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
}

# --- Record the run and print a short summary --------------------------------------
# Round-trip ("o") format so the cooldown parse above reads it back exactly.
(Get-Date).ToString('o') | Set-Content -Path $stateFile -Force

$after   = Get-CFreeGB
$freed   = [math]::Round($after - $before, 2)
$pctFree = if ($sizeGB -gt 0) { [math]::Round(($after / $sizeGB) * 100, 1) } else { 0 }
$secs    = [math]::Round(((Get-Date) - $start).TotalSeconds, 0)

Write-Output ("Disk cleanup on {0} finished in {1}s" -f $env:COMPUTERNAME, $secs)
Write-Output ("C: free before: {0} GB | after: {1} GB ({2}% of {3} GB) | freed: {4} GB" -f $before, $after, $pctFree, $sizeGB, $freed)
exit 0

<#
.SYNOPSIS
    Schedules ONE restart of this machine at a set time (default: the next 01:00).

.DESCRIPTION
    Written 2026-10-26 so a machine can be rebooted overnight without anyone being
    logged in to do it (first use: one client PC with an ESET LiveGrid warning,
    up since 22 Oct). Run it from TRMM (Run Script, or the test endpoint).

    What it does and why:
      1. Works out the restart time. -At "yyyy-MM-dd HH:mm" (local machine time),
         or if not given, the next 01:00. Refuses a time in the past.
      2. Registers a Windows scheduled task running as SYSTEM that runs
         "shutdown.exe /r /t <WarnSeconds>". The warning delay means anyone who IS
         at the machine gets a message and can cancel it with: shutdown /a
      3. The task runs ONCE and does NOT run late: StartWhenAvailable is off and
         the trigger ends an hour after the set time. Why: if the PC is switched
         off at 01:00 it must not restart itself at 08:30 in front of the user.
      4. The task deletes itself an hour after it expires (DeleteExpiredTaskAfter),
         so nothing is left behind. -Remove cancels it early.
      5. Prints the task's NextRunTime read back from Windows, as proof.

.PARAMETER At        Restart time, local machine time, e.g. "2026-10-27 01:00".
.PARAMETER Reason    Message shown in the shutdown warning.
.PARAMETER WarnSeconds  Warning countdown before the restart (default 120).
.PARAMETER DryRun    Show what would be created; create nothing.
.PARAMETER Remove    Delete the scheduled restart task instead.
#>
[CmdletBinding()]
param(
    [datetime]$At,
    [string]$Reason = 'Scheduled overnight maintenance restart (Lincoln IT Solutions)',
    [int]$WarnSeconds = 120,
    [string]$TaskName = 'LincolnIT-OneOffReboot',
    [switch]$DryRun,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

# -Remove: delete the task if it exists and stop.
if ($Remove) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Output "REMOVED scheduled restart task '$TaskName' on $env:COMPUTERNAME."
    } else {
        Write-Output "Nothing to remove: no task '$TaskName' on $env:COMPUTERNAME."
    }
    exit 0
}

# 1. Restart time: given, or the next 01:00.
if (-not $PSBoundParameters.ContainsKey('At')) {
    $At = (Get-Date).Date.AddHours(1)
    if ($At -le (Get-Date)) { $At = $At.AddDays(1) }
}
if ($At -le (Get-Date)) { throw "Restart time $At is in the past (machine time is $(Get-Date -Format 's'))." }

# 2. Action: shutdown.exe /r with a warning countdown and a visible reason.
$action = New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument "/r /t $WarnSeconds /c `"$Reason`""

# 3. Trigger: once. EndBoundary = 1 h after, so a missed run is never made up later.
$trigger = New-ScheduledTaskTrigger -Once -At $At
$trigger.EndBoundary = $At.AddHours(1).ToString('s')
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable:$false -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DeleteExpiredTaskAfter (New-TimeSpan -Hours 1)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

Write-Output "$env:COMPUTERNAME  machine time now: $(Get-Date -Format 's')"
Write-Output "Plan: restart at $($At.ToString('s')) (warning $WarnSeconds s), task '$TaskName', runs as SYSTEM, once, not made up if missed."
if ($DryRun) { Write-Output 'DRY RUN - nothing created.'; exit 0 }

# 4. Register (replaces a previous task of the same name) and read it back.
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
$info = Get-ScheduledTaskInfo -TaskName $TaskName
$task = Get-ScheduledTask -TaskName $TaskName
Write-Output "SCHEDULED: '$TaskName' state=$($task.State) NextRunTime=$($info.NextRunTime.ToString('s'))"
Write-Output "Action: $($task.Actions[0].Execute) $($task.Actions[0].Arguments)"

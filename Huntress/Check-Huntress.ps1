<#
.SYNOPSIS
    TRMM script check: is Huntress actually installed, registered and running?
    Replaces checks that only looked for C:\Program Files\Huntress.

.DESCRIPTION
    Install/running checks only - does NOT look at Huntress alerts, incidents or the
    agent's health status.

      1. Services     - HuntressAgent + HuntressUpdater must exist AND be Running.
                        HuntressRio (EDR) must also be Running on OS kernel 6.2+ (Win8/2012+).
                        Service names + the 6.2 rule come from Huntress's own install script
                        (huntresslabs/deployment-scripts, InstallHuntress.powershellv2.ps1).
      2. Registration - HKLM\SOFTWARE\Huntress Labs\Huntress must hold a non-zero AgentId.
                        Huntress's install script treats a missing / zero AgentId as
                        "the agent did not register" (installed but not linked to the portal).

    Exit codes (TRMM: any non-zero = failing; add 2 to the check's "Warning return codes"
    so it alerts as Warning instead of Error - confirmed in TRMM source checks/models.py):
      0 = installed, registered, all services running
      1 = FAIL (not installed / leftover folders only / service stopped / not registered)
      2 = WARN (Rio not present yet on an install less than NewInstallGraceHours old)

GENERIC / PER-CLIENT BEHAVIOUR (added 2026-10-27)
      One copy of this check runs on every workstation/server baseline. TRMM passes the client's
      'Huntress Active' field in as the HUNTRESS_ACTIVE environment variable:
        - Active = Yes : the install/registration tests below apply (fail if not installed).
        - anything else (No / blank / not set) : nothing is expected. Passes (exit 0) when
          Huntress is NOT present, FAILS (exit 1) when any Huntress service, registry key or
          install folder IS present - so Huntress left on a client you have not marked Active
          is reported rather than silently ignored.
      The failing result is what triggers the 'Huntress - Install (generic)' task, which itself
      does nothing unless Active = Yes.

.PARAMETER NewInstallGraceHours
    Huntress states Rio (EDR) can take up to 24h to appear after a fresh install. If Rio is
    missing and HuntressAgent.exe is younger than this, return WARN instead of FAIL.
#>
param(
    [int]$NewInstallGraceHours = 24
)

# Collect every problem rather than stopping at the first, so the TRMM check output
# shows the full picture in one run.
$failures = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

# TRMM docs: set PowerShell exit codes via $host.SetShouldExit(); exit stops the script.
function Complete-Check([int]$code) {
    $host.SetShouldExit($code)
    exit $code
}

# ---------------------------------------------------------------------------
# 0. IS HUNTRESS WANTED FOR THIS CLIENT?
# ---------------------------------------------------------------------------
# TRMM leaves an environment variable out when the client field is empty, and an un-substituted
# {{placeholder}} can come through as text - treat both as "not set" so only an explicit Yes counts.
$active = [Environment]::GetEnvironmentVariable('HUNTRESS_ACTIVE')
if ([string]::IsNullOrWhiteSpace($active) -or $active.Trim().StartsWith('{{')) { $active = '' }
$active = $active.Trim().Trim("'").Trim('"')

if ($active -ne 'Yes') {
    # Not an Active client: Huntress should NOT be here. Look for any trace of it - a service,
    # the registration key, or the install folder - so a half-removed install is caught too.
    $shown  = if ($active) { $active } else { 'not set' }
    $found  = New-Object System.Collections.Generic.List[string]

    foreach ($name in 'HuntressAgent', 'HuntressUpdater', 'HuntressRio') {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) { $found.Add("service $name") }
    }
    # 64-bit registry view explicitly (same reason as the registration test further down)
    $v = if ([Environment]::Is64BitOperatingSystem) { [Microsoft.Win32.RegistryView]::Registry64 } else { [Microsoft.Win32.RegistryView]::Registry32 }
    $k = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $v).OpenSubKey('SOFTWARE\Huntress Labs')
    if ($k) { $found.Add('registry key HKLM\SOFTWARE\Huntress Labs'); $k.Close() }
    if (Test-Path (Join-Path $env:ProgramFiles 'Huntress')) { $found.Add("folder $env:ProgramFiles\Huntress") }

    if ($found.Count -gt 0) {
        Write-Output "FAIL Huntress is present ($($found -join '; ')) but this client's 'Huntress Active' is '$shown'. Either set the client to Yes in TRMM or remove Huntress from this machine."
        Complete-Check 1
    }
    Write-Output "OK   Huntress Active is '$shown' for this client and Huntress is not installed - nothing expected."
    Complete-Check 0
}

# From here on the client is Active = Yes, so Huntress must be installed, registered and running.

# ---------------------------------------------------------------------------
# 1. SERVICES
# ---------------------------------------------------------------------------
# Kernel version decides whether Rio is expected. Huntress's installer skips the Rio
# check below 6.2 because legacy OSes can't run Huntress EDR.
$osVersion   = [Environment]::OSVersion.Version
$rioExpected = ($osVersion -ge [Version]'6.2')

$required = @('HuntressAgent', 'HuntressUpdater')
if ($rioExpected) { $required += 'HuntressRio' }

foreach ($name in $required) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue

    if (-not $svc) {
        # Rio missing on a brand-new install is expected for up to 24h, so downgrade
        # to WARN inside the grace window.
        if ($name -eq 'HuntressRio') {
            $agentExe = Join-Path $env:ProgramFiles 'Huntress\HuntressAgent.exe'
            if ((Test-Path $agentExe) -and
                ((Get-Item $agentExe).CreationTime -gt (Get-Date).AddHours(-$NewInstallGraceHours))) {
                $warnings.Add("HuntressRio not present yet - agent installed < $NewInstallGraceHours h ago (Huntress says EDR can take up to 24h).")
                continue
            }
        }
        $failures.Add("Service '$name' is NOT installed.")
        continue
    }

    if ($svc.Status -ne 'Running') {
        $failures.Add("Service '$name' exists but is $($svc.Status) (StartType: $($svc.StartType)).")
    }
    else {
        Write-Output "OK   Service '$name' running."
    }
}

# ---------------------------------------------------------------------------
# 2. REGISTRATION (registry)
# ---------------------------------------------------------------------------
# Open the 64-bit registry view explicitly. Huntress's own script warns it can't verify
# these keys from 32-bit PowerShell on a 64-bit host (WOW64 redirection), so we don't
# rely on whichever bitness TRMM happens to launch.
try {
    $view = if ([Environment]::Is64BitOperatingSystem) { [Microsoft.Win32.RegistryView]::Registry64 } else { [Microsoft.Win32.RegistryView]::Registry32 }
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
    $key  = $hklm.OpenSubKey('SOFTWARE\Huntress Labs\Huntress')

    if (-not $key) {
        $failures.Add("Registry key HKLM\SOFTWARE\Huntress Labs\Huntress missing - agent never registered or was removed.")
    }
    else {
        $agentId = $key.GetValue('AgentId')

        # Huntress's installer: AgentId of 0 / missing = "The agent did not register".
        if ($null -eq $agentId -or "$agentId" -eq '0' -or "$agentId" -eq '') {
            $failures.Add("AgentId is missing/0 - agent is NOT registered with the Huntress portal.")
        }
        else {
            Write-Output "OK   Registered. AgentId=$agentId"
        }
        $key.Close()
    }
}
catch {
    $failures.Add("Could not read Huntress registry: $($_.Exception.Message)")
}

# ---------------------------------------------------------------------------
# RESULT
# ---------------------------------------------------------------------------
# Call out the "folder exists but nothing running" case that was passing the old
# checks, so it's obvious in the alert text.
if ($failures.Count -gt 0 -and (Test-Path (Join-Path $env:ProgramFiles 'Huntress'))) {
    $failures.Add("NOTE: '$env:ProgramFiles\Huntress' folder exists - likely a broken / partially removed install.")
}

foreach ($f in $failures) { Write-Output "FAIL $f" }
foreach ($w in $warnings) { Write-Output "WARN $w" }

if ($failures.Count -gt 0) { Complete-Check 1 }
if ($warnings.Count -gt 0) { Complete-Check 2 }
Write-Output "Huntress installed and running."
Complete-Check 0
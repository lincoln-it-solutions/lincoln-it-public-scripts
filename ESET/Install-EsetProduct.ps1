<#
.SYNOPSIS
    BACKUP installer for the ESET security product (Endpoint Security / Server Security) on
    machines that already have the ESET Management Agent but no ESET product. Runs the install
    DETACHED so the TRMM run returns at once; Monitor-ESET.ps1 tracks the outcome.

.DESCRIPTION
    WHY THIS EXISTS
      The per-client "ESET ... Agent Installer" scripts install the ESET Management Agent; the
      ESET PROTECT console is then meant to push the security product. The 2026-10-26 audit
      found 25 machines with the agent and NO product (Monitor-ESET.ps1 warns about them).
      This script is the backup: it installs the product itself, driven by the client's TRMM
      custom fields, so it only touches clients we have deliberately set up for ESET.

    WHY DETACHED (2026-10-27)
      The first real run (EMMAGPC) installed and activated ESET correctly, but the TRMM
      test-endpoint call never returned although the script had finished. Cause unproven (a guess:
      installing ESET's network drivers disturbs the agent connection, losing the reply). So the
      run you start now does only the quick part, then hands the slow part to a one-off Windows
      scheduled task running as SYSTEM and returns in seconds:
        LAUNCHER (this script as TRMM runs it): checks the gates, writes a job file, copies this
                 script next to it, registers and starts the task, prints "STARTED", exits 0.
        WORKER   (same file, -Worker, run by the task): downloads, checks the ESET signature,
                 runs msiexec, activates, verifies, records the outcome, removes the task.
      The outcome is written to  <StateDir>\product-install-status.json  and Monitor-ESET.ps1
      reads it (same folder), so the monitor shows "installing", "failed: <reason>" or
      "installed by the backup installer ..." for that PC.

    WHEN THE LAUNCHER ACTS (every one must be true, otherwise it exits without changing anything)
      1. The ESET Management Agent is installed (uninstall entry "ESET Management Agent" /
         "ESET Remote Administrator Agent"). Without it the machine would be unmanaged, which
         Monitor-ESET.ps1 deliberately does not monitor. The agent needs a per-client
         certificate/config that is not in the custom fields, so this script never installs it.
      2. No ESET security product is present (no product folder / ESET product uninstall entry).
      3. Client field "ESET Licence Type" is MSP, EBA or NFR (env ESET_LICENCE_TYPE). A client
         with the field blank has not been set up for ESET, so nothing is installed.
      4. Client checkbox "ESET Product Not Required" is NOT ticked (env ESET_PRODUCT_NOT_REQUIRED).
      5. No install is already in progress (our task, or any Windows Installer run), and fewer than
         -MaxAttemptsPerDay attempts in the last 24 h, the last one >= -MinHoursBetween ago.
      6. -Apply was passed. Without -Apply it only reports what it WOULD do (and checks that the
         download link answers).

    WHICH PRODUCT
      Windows Server (Win32_OperatingSystem.ProductType 2 or 3) -> ESET Server Security;
      otherwise ESET Endpoint Security. Download URLs are the ones ESET publishes:
        Endpoint (KB8288): .../ees/windows/v13/13.1.2036.0/ees_nt64_full.msi
        Server   (KB8400): .../efs/windows/latest/efsw_nt64_full.msi
      ESET lists no 32-bit 13.x build, so a 32-bit OS is refused. Override with -EndpointUrl / -ServerUrl.

    HOW THE WORKER INSTALLS (ESET command-line installation doc, help.eset.com/ees/13/en-US/installation_command_line.html)
      msiexec /i <pkg> /qn REBOOT=ReallySuppress /l*v <log> [ADDLOCAL=<list>] [ACTIVATION_DATA=key:<key>]
      - ACTIVATION_DATA=key:... activates during install; used only for EBA / NFR when client field
        "ESET Licence" holds "<public ID> | <key>". MSP: NO key (EMA 2 shows no full keys) - activate in
        the ESET PROTECT portal.
      - REBOOT=ReallySuppress: never restarts the PC. 3010 is recorded as "restart needed".
      - Default features include the RMM component (ermm.exe was present after the 2026-10-27 run).

    SAFETY
      - The download must have a VALID Authenticode signature whose subject contains "ESET",
        otherwise it is deleted and nothing is run.
      - The key travels in a job file whose permissions are restricted to SYSTEM and Administrators;
        the worker deletes that file as soon as it has read it. The key is never printed in full and
        the MSI log is scrubbed of it; the log is kept only when the install fails.
      - Visible to the user: a successful install adds the ESET product (tray icon) on that PC.
      - Windows PowerShell 5.1 compatible (what TRMM runs).

    TRMM SET-UP WHEN READY (not done)
      Script arguments:  -Apply
      Environment variables (same as the monitor check):
        ESET_LICENCE_TYPE={{client.ESET Licence Type}}
        ESET_LICENCE={{client.ESET Licence}}
        ESET_PRODUCT_NOT_REQUIRED={{client.ESET Product Not Required}}
      The launcher finishes in seconds, so the default action timeout is plenty.

    EXIT CODES (launcher)
      0 = nothing to do / report-only / install started / waiting
      1 = needs attention (agent missing, unsupported OS, could not start the install, attempt limit hit)
    The worker's result is in product-install-status.json, not in an exit code anyone sees.

.PARAMETER Apply
    Actually start the install. Without it, report only.
.PARAMETER EndpointUrl
    MSI for workstations. Default is ESET's published 13.1.2036.0 64-bit full MSI (KB8288).
.PARAMETER ServerUrl
    MSI for Windows Server. Default is ESET's published "latest" Server Security MSI (KB8400).
.PARAMETER AddLocal
    Optional ADDLOCAL feature list passed to the MSI.
.PARAMETER MaxAttemptsPerDay
    Install attempts allowed in any 24 h on one machine (default 2).
.PARAMETER MinHoursBetween
    Minimum hours between attempts (default 4).
.PARAMETER InstallTimeoutMinutes
    How long the worker waits for msiexec (default 20).
.PARAMETER StateDir
    Where job/status/attempt files go. Default is the monitor's folder, so the monitor can read the status.
.PARAMETER Worker
    Internal: run the slow part. Started by the scheduled task, never by hand or TRMM.
.PARAMETER JobFile
    Internal: the job file the launcher wrote (with -Worker).
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [string]$EndpointUrl = 'https://download.eset.com/com/eset/apps/business/ees/windows/v13/13.1.2036.0/ees_nt64_full.msi',
    [string]$ServerUrl   = 'https://download.eset.com/com/eset/apps/business/efs/windows/latest/efsw_nt64_full.msi',
    [string]$AddLocal = '',
    [int]$MaxAttemptsPerDay = 2,
    [int]$MinHoursBetween = 4,
    [int]$InstallTimeoutMinutes = 20,
    [string]$StateDir = 'C:\ProgramData\LincolnIT\ESETMonitor',
    [switch]$Worker,
    [string]$JobFile
)

$ErrorActionPreference = 'Stop'
$TaskName   = 'LincolnIT ESET Product Install'
$StatusFile = Join-Path $StateDir 'product-install-status.json'
$ProductFolders = @("$env:ProgramFiles\ESET\ESET Security", "$env:ProgramFiles\ESET\ESET Server Security", "$env:ProgramFiles\ESET\ESET File Security")

function Hide-Key([string]$Key) {
    # Never show a whole activation key: keep only the last block.
    if (-not $Key) { return '' }
    $p = $Key.Split('-')
    return ('XXXX-XXXX-XXXX-XXXX-' + $p[$p.Count - 1])
}

function Set-Status([hashtable]$Fields) {
    # Merge fields into the status file. The monitor reads this file, so it is always written
    # whole and always has state + updatedUtc. Best effort: a failure to write must not stop an install.
    try {
        if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
        $cur = @{}
        if (Test-Path $StatusFile) {
            $o = Get-Content $StatusFile -Raw | ConvertFrom-Json
            foreach ($p in $o.PSObject.Properties) { $cur[$p.Name] = $p.Value }
        }
        foreach ($k in $Fields.Keys) { $cur[$k] = $Fields[$k] }
        $cur['updatedUtc']   = (Get-Date).ToUniversalTime().ToString('o')           # for people
        $cur['updatedEpoch'] = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()          # for code (no time-zone parsing)
        ($cur | ConvertTo-Json) | Set-Content -Path $StatusFile -Encoding UTF8
    } catch { }
}

# ==========================================================================================
# WORKER: the slow part, run by the scheduled task as SYSTEM (no one waits for it)
# ==========================================================================================
if ($Worker) {
    $job = Get-Content $JobFile -Raw | ConvertFrom-Json
    # Delete the job file at once: it holds the activation key.
    Remove-Item $JobFile -Force -ErrorAction SilentlyContinue
    $key = $job.key
    $pkg = $null; $log = Join-Path $StateDir 'product-install.log'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # --- download and verify ---
        Set-Status @{ state = 'downloading'; message = "downloading $($job.productName)" }
        $pkg = Join-Path $StateDir ([IO.Path]::GetFileName(([uri]$job.url).AbsolutePath))
        Invoke-WebRequest -Uri $job.url -OutFile $pkg -UseBasicParsing -TimeoutSec 900
        $sig = Get-AuthenticodeSignature -FilePath $pkg
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'ESET') {
            throw "downloaded file is not a validly signed ESET package (status $($sig.Status), signer '$($sig.SignerCertificate.Subject)') - deleted, nothing was run"
        }

        # --- wait for any other Windows Installer run to finish (e.g. the PROTECT console installing) ---
        $waited = 0
        while ($waited -lt 600) {
            $m = $null
            if ([System.Threading.Mutex]::TryOpenExisting('Global\_MSIExecute', [ref]$m)) { $m.Dispose(); Start-Sleep -Seconds 15; $waited += 15 } else { break }
        }
        # An ESET product may have arrived by that route while we waited: then there is nothing to do.
        if ($ProductFolders | Where-Object { Test-Path $_ }) {
            Set-Status @{ state = 'installed'; message = 'an ESET product appeared (installed by another route) while waiting - backup install not needed'; viaBackup = $false }
            return
        }

        # --- install ---
        Set-Status @{ state = 'installing'; message = "running msiexec for $($job.productName)" }
        $msiArgs = @('/i', "`"$pkg`"", '/qn', 'REBOOT=ReallySuppress', '/l*v', "`"$log`"")
        if ($job.addLocal) { $msiArgs += "ADDLOCAL=$($job.addLocal)" }
        if ($key)          { $msiArgs += "ACTIVATION_DATA=key:$key" }
        $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -PassThru -WindowStyle Hidden
        if (-not $proc.WaitForExit($job.timeoutMinutes * 60 * 1000)) {
            throw "msiexec still running after $($job.timeoutMinutes) minutes - left running; check again later"
        }
        $code = $proc.ExitCode
        # The verbose MSI log records every property including the key - mask it either way.
        if ($key -and (Test-Path $log)) { (Get-Content $log -Raw) -replace [regex]::Escape($key), (Hide-Key $key) | Set-Content -Path $log -Encoding UTF8 }

        # --- verify from the machine, not just the installer's exit code ---
        # Windows Installer: 0 = success, 3010 = success but a restart is needed (standard MSI codes).
        if ($code -ne 0 -and $code -ne 3010) { throw "msiexec exit code $code - $($job.productName) was NOT installed (log kept at $log, key masked)" }
        $ermm = $null
        for ($i = 0; $i -lt 12 -and -not $ermm; $i++) {
            $ermm = $ProductFolders | ForEach-Object { Join-Path $_ 'ermm.exe' } | Where-Object { Test-Path $_ } | Select-Object -First 1
            if (-not $ermm) { Start-Sleep -Seconds 5 }
        }
        # What licence did the product end up on? ermm answers "disabled" (error 6) until the PROTECT
        # policy enabling RMM reaches the PC - on Clare-PC (2026-10-27) that took longer than a minute
        # but was done within ~3 min. The worker is detached, so it can afford to wait up to ~6 min.
        $licType = ''; $licId = ''
        if ($ermm) {
            for ($i = 0; $i -lt 24 -and -not $licId; $i++) {
                try {
                    $j = Start-Job -ScriptBlock { param($e) & $e get license-info 2>$null } -ArgumentList $ermm
                    if (Wait-Job $j -Timeout 20) {
                        $r = (Receive-Job $j) -join "`n" | ConvertFrom-Json
                        if ($r.result.public_id) { $licType = "$($r.result.type)"; $licId = "$($r.result.public_id)" }
                    }
                    Remove-Job $j -Force -ErrorAction SilentlyContinue
                } catch { }
                if (-not $licId) { Start-Sleep -Seconds 15 }
            }
        }
        $msg = "$($job.productName) installed (msiexec exit $code)"
        if ($code -eq 3010) { $msg += '; a restart is needed to finish (not forced)' }
        if (-not $ermm)  { $msg += '; WARNING ermm.exe not found afterwards' }
        if ($licId)      { $msg += "; licence $licType $licId" } elseif ($key) { $msg += '; WARNING activation key was passed but no licence was reported within ~6 min (RMM may still be disabled by policy) - the monitor will show the real state' } else { $msg += '; not activated (no key - MSP, or none in the client field)' }
        Set-Status @{ state = 'installed'; viaBackup = $true; product = $job.productName; msiexecExit = $code; restartNeeded = ($code -eq 3010); ermmFound = [bool]$ermm; licenceType = $licType; licencePublicId = $licId; message = $msg }
        Remove-Item $log -Force -ErrorAction SilentlyContinue   # success: no need to keep it
    } catch {
        Set-Status @{ state = 'failed'; viaBackup = $true; message = "$($_.Exception.Message)" }
    } finally {
        if ($pkg) { Remove-Item $pkg -Force -ErrorAction SilentlyContinue }
        # Tidy up: the one-off task and this script's own copy. (Deleting a running script file is fine.)
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $StateDir 'Install-EsetProduct.worker.ps1') -Force -ErrorAction SilentlyContinue
    }
    return
}

# ==========================================================================================
# LAUNCHER: quick checks, then start the worker and return
# ==========================================================================================
function Stop-Run([int]$Code, [string]$Message) {
    # One exit point so every path prints its reason first (TRMM shows the output).
    Write-Output $Message
    $host.SetShouldExit($Code)
    exit $Code
}

# --- 1. Inputs from the client's custom fields (environment variables set by TRMM) ---
$LicType = "$env:ESET_LICENCE_TYPE".Trim().ToUpper()
$LicRaw  = "$env:ESET_LICENCE".Trim()
# TRMM hands a ticked checkbox to PowerShell as the text "$True" (seen live 2026-10-26).
$NotRequired = ("$env:ESET_PRODUCT_NOT_REQUIRED".Trim() -match '^\$?(true|1|yes)$')

# --- 2. What is installed now? Same detection as Monitor-ESET.ps1 (each uninstall key read on its
#        own, because one malformed key made a single wildcard read return nothing on one PC) ---
$roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
           'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
$esetEntries = @(
    foreach ($root in $roots) {
        foreach ($k in (Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
            try {
                $p = Get-ItemProperty -Path $k.PSPath -ErrorAction Stop
                if ($p.DisplayName -match 'ESET' -or $p.Publisher -match 'ESET') { $p }
            } catch { }   # unreadable entry: skip just this one
        }
    }
)
$agent = $esetEntries | Where-Object { $_.DisplayName -match '^ESET (Management|Remote Administrator) Agent' } | Select-Object -First 1
$folderHit = $ProductFolders | Where-Object { Test-Path $_ } | Select-Object -First 1
# An ESET entry that is not the agent also counts as "a product" - this catches a home product such
# as NOD32, which we must never install over.
$otherEntry = $esetEntries | Where-Object { $_.DisplayName -notmatch '^ESET (Management|Remote Administrator) Agent' -and $_.DisplayName -match '^ESET' } | Select-Object -First 1

# Previous outcome (written by an earlier worker), shown for the record.
$prev = $null
if (Test-Path $StatusFile) { try { $prev = Get-Content $StatusFile -Raw | ConvertFrom-Json } catch { } }

# --- 3. Gates: leave the machine alone unless every condition in the header holds ---
if ($folderHit -or $otherEntry) {
    $what = if ($otherEntry) { "$($otherEntry.DisplayName) $($otherEntry.DisplayVersion)" } else { $folderHit }
    $extra = if ($prev -and $prev.state -eq 'installed') { " Last backup install result: $($prev.message)." } else { '' }
    Stop-Run 0 "OK: an ESET product is already present on $env:COMPUTERNAME ($what) - nothing to install.$extra"
}
if ($LicType -notin 'MSP', 'EBA', 'NFR') {
    Stop-Run 0 "SKIP: client field 'ESET Licence Type' is '$LicType' (needs MSP, EBA or NFR) - this client is not set up for ESET, so nothing is installed."
}
if ($NotRequired) {
    Stop-Run 0 "SKIP: 'ESET Product Not Required' is ticked for this client - nothing to install."
}
if (-not $agent) {
    Stop-Run 1 "ATTENTION: $env:COMPUTERNAME has no ESET Management Agent and no ESET product, and the client is $LicType. This script does not install the agent (it needs the client's own certificate/config) - run the client's ESET Agent Installer script first."
}
if (-not [Environment]::Is64BitOperatingSystem) {
    Stop-Run 1 "ATTENTION: $env:COMPUTERNAME is a 32-bit Windows. ESET lists no 32-bit 13.x installer (KB8288), so nothing was installed."
}

# --- 4. Choose the product and work out activation ---
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$isServer = ($os.ProductType -ne 1)           # 1 = workstation, 2 = domain controller, 3 = server
$productName = if ($isServer) { 'ESET Server Security' } else { 'ESET Endpoint Security' }
$url = if ($isServer) { $ServerUrl } else { $EndpointUrl }

# "ESET Licence" is '<public ID> | <key>' for EBA/NFR and just the public ID for MSP
# (same convention Monitor-ESET.ps1 reads).
$key = $null
if ($LicType -in 'EBA', 'NFR') {
    $parts = $LicRaw -split '\s*\|\s*'
    if ($parts.Count -eq 2 -and $parts[1] -match '^[A-Z0-9]{4}(-[A-Z0-9]{4}){4}$') { $key = $parts[1] }
}
$activationNote =
    if ($LicType -eq 'MSP') { 'MSP: installed WITHOUT a key - activate it in the ESET PROTECT portal (Product Activation task); EMA 2 shows no full keys.' }
    elseif ($key)           { "will activate during install with key $(Hide-Key $key)." }
    else                    { "WARNING: $LicType client but field 'ESET Licence' has no valid '<public ID> | <key>' - it will install UNACTIVATED; the monitor will then alert 'not activated'." }

Write-Output "$env:COMPUTERNAME ($($os.Caption)): ESET Management Agent $($agent.DisplayVersion) present, no ESET product. Client licence type $LicType."
Write-Output "  Would install: $productName from $url"
Write-Output "  Activation: $activationNote"
if ($prev) { Write-Output "  Last recorded backup install: $($prev.state) at $($prev.updatedUtc) - $($prev.message)" }

# --- 5. Report-only mode stops here, after proving the download link answers (HEAD request: no
#        file is downloaded, nothing is changed) ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not $Apply) {
    try {
        $head = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -TimeoutSec 30
        Write-Output "  Download link check: HTTP $($head.StatusCode), $($head.Headers['Content-Length']) bytes, $($head.Headers['Content-Type'])."
    } catch {
        Write-Output "  Download link check FAILED: $($_.Exception.Message)"
    }
    Stop-Run 0 "REPORT ONLY (no -Apply): nothing was downloaded or installed."
}

# --- 6. In progress? Retry limits (so a failing install is not retried forever) ---
if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
$taskNow = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($taskNow -and $taskNow.State -eq 'Running') {
    Stop-Run 0 "WAIT: the backup install task is already running on $env:COMPUTERNAME (status: $($prev.state) - $($prev.message))."
}
if ($prev -and ($prev.state -in 'started', 'downloading', 'installing') -and $prev.updatedEpoch) {
    $ageMin = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [long]$prev.updatedEpoch) / 60
    if ($ageMin -lt 90 -and $taskNow) { Stop-Run 0 "WAIT: backup install status is '$($prev.state)' (updated $([int]$ageMin) min ago)." }
}
$attemptFile = Join-Path $StateDir 'product-install-attempts.json'
$attempts = @()
# Attempts are stored as unix seconds (no time-zone or date-parsing surprises).
if (Test-Path $attemptFile) { try { $attempts = @((Get-Content $attemptFile -Raw | ConvertFrom-Json) | ForEach-Object { [long]$_ }) } catch { $attempts = @() } }
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$recent = @($attempts | Where-Object { ($now - $_) / 3600 -lt 24 })
if ($recent.Count -ge $MaxAttemptsPerDay) { Stop-Run 1 "ATTENTION: $($recent.Count) install attempt(s) already made in the last 24 h (limit $MaxAttemptsPerDay) - not trying again. Last result: $($prev.state) - $($prev.message)" }
if ($recent.Count -gt 0) {
    $sinceLast = ($now - ($recent | Sort-Object | Select-Object -Last 1)) / 3600
    if ($sinceLast -lt $MinHoursBetween) { Stop-Run 0 "WAIT: last attempt was $([math]::Round($sinceLast,1)) h ago (minimum $MinHoursBetween h) - will try on a later run." }
}
# Another installer running right now (e.g. the ESET PROTECT console installing the product)?
$mutex = $null
if ([System.Threading.Mutex]::TryOpenExisting('Global\_MSIExecute', [ref]$mutex)) {
    $mutex.Dispose()
    Stop-Run 0 "WAIT: another Windows Installer run is in progress (possibly the ESET PROTECT console installing the product) - will try on a later run."
}

# Record the attempt BEFORE starting, so a crash still counts.
$attempts = @($recent) + $now
ConvertTo-Json -InputObject @($attempts) | Set-Content -Path $attemptFile -Encoding UTF8

# --- 7. Hand over to the worker ---
try {
    if (-not $PSCommandPath -or -not (Test-Path $PSCommandPath)) { throw 'cannot find this script file to copy for the worker' }
    $workerPath = Join-Path $StateDir 'Install-EsetProduct.worker.ps1'
    Copy-Item -Path $PSCommandPath -Destination $workerPath -Force

    # Job file: holds the key, so only SYSTEM and Administrators may read it (well-known SIDs, so the
    # group names do not matter on non-English Windows). The worker deletes it after reading.
    $jobPath = Join-Path $StateDir 'product-install-job.json'
    @{ url = $url; productName = $productName; key = $key; addLocal = $AddLocal; timeoutMinutes = $InstallTimeoutMinutes } | ConvertTo-Json | Set-Content -Path $jobPath -Encoding UTF8
    & icacls.exe $jobPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) { Remove-Item $jobPath -Force -ErrorAction SilentlyContinue; throw "could not restrict permissions on the job file (icacls exit $LASTEXITCODE), so it was not used" }

    Set-Status @{ state = 'started'; viaBackup = $true; product = $productName; startedUtc = (Get-Date).ToUniversalTime().ToString('o'); startedEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); message = "install task started for $productName"; msiexecExit = $null; licencePublicId = ''; licenceType = '' }

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$workerPath`" -Worker -JobFile `"$jobPath`" -StateDir `"$StateDir`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
} catch {
    Set-Status @{ state = 'failed'; message = "could not start the install task: $($_.Exception.Message)" }
    Stop-Run 1 "ATTENTION: could not start the install task: $($_.Exception.Message)"
}
Stop-Run 0 "STARTED: $productName install is running in the background on $env:COMPUTERNAME (task '$TaskName'). Result will be in $StatusFile and shown by Monitor-ESET.ps1. $activationNote"

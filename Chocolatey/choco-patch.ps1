<#
  choco-patch.ps1 - TRMM script: upgrade the Chocolatey packages listed in the managed list.

  Uses the SAME list as choco-adopt.ps1, so one keystore value drives both:
      <chocolatey package id>=<Windows display name>   (only the id is used here)

  Where the list comes from (first match wins):
      1. -Packages argument
      2. CHOCO_PACKAGES environment variable (set it to {{global.choco_managed_packages}} in TRMM)

  Pass -DryRun to show what would change without changing anything.
#>
param(
    [string]$Packages = "",
    [switch]$DryRun,
    [string]$ProxySourceName = 'lits-proget'
)

# --- 1. Get the package list ---------------------------------------------------
# Env var preferred over an argument to avoid shell quoting problems (see choco-adopt.ps1).
if (-not $Packages) { $Packages = $env:CHOCO_PACKAGES }
if (-not $Packages) {
    Write-Output "ERROR: no package list. Set CHOCO_PACKAGES or pass -Packages."
    exit 1
}

# --- 2. Parse the list (ids only) ----------------------------------------------
# Same parsing rules as choco-adopt.ps1 so both scripts read the list identically.
# This logic is duplicated because TRMM scripts are standalone and cannot share code.
$ids = @()
$parseErrors = $false
foreach ($line in ($Packages -split '[;\r\n]+')) {
    $line = $line.Trim()
    if (-not $line -or $line.StartsWith('#')) { continue }
    $eq = $line.IndexOf('=')
    if ($eq -lt 1 -or $eq -eq ($line.Length - 1)) {
        Write-Output "ERROR: bad entry '$line' (expected id=display name)"
        $parseErrors = $true
        continue
    }
    $id = $line.Substring(0, $eq).Trim()
    # The same package may be listed more than once (e.g. several display-name patterns);
    # only upgrade each id once.
    if ($ids -notcontains $id) { $ids += $id }
}
if ($ids.Count -eq 0) { Write-Output "ERROR: list contained no valid entries."; exit 1 }

# --- 3. Find Chocolatey --------------------------------------------------------
$chocoRoot = $env:ChocolateyInstall
if (-not $chocoRoot) { $chocoRoot = "C:\ProgramData\chocolatey" }
$choco = Join-Path $chocoRoot "bin\choco.exe"
if (-not (Test-Path $choco)) { Write-Output "choco.exe not found, skipping"; exit 0 }

# --- Safety check: proxy source only --------------------------------------------
# Same rule as the existing TRMM scripts 220-224: from 2027-01-01 Chocolatey's Terms of Use
# prohibit organisations using the Community Repository directly, so refuse to run unless our
# proxy source is enabled AND the community source is disabled. Exit 12 matches those scripts.
# Assumed 'choco source list -r' field order: Name|Url|Disabled|... (as used in scripts 219-224).
$sources = foreach ($srcLine in (& $choco source list -r 2>$null)) {
    $p = $srcLine -split '\|'
    if ($p.Count -ge 3) { [pscustomobject]@{ Name = $p[0]; Disabled = ($p[2] -eq 'True') } }
}
$ours      = $sources | Where-Object Name -eq $ProxySourceName
$community = $sources | Where-Object Name -eq 'chocolatey'
if (-not $ours -or $ours.Disabled -or ($community -and -not $community.Disabled)) {
    Write-Output "Refusing to run: source '$ProxySourceName' must be enabled and the community source 'chocolatey' disabled. Run TRMM script 219 first."
    exit 12
}

# --- 4. Log what is outdated before changing anything ---------------------------
# Gives the TRMM task history a record of what was about to be upgraded.
# Output lines are name|current|available|pinned.
Write-Output "Outdated before upgrade:"
& $choco outdated -r

# --- 5. Upgrade only the listed packages ----------------------------------------
# --skip-if-not-installed: 'choco upgrade' normally INSTALLS a missing package, so without
#   this flag a machine that never had e.g. Adobe Reader would get it installed. This
#   keeps the script to patching only.
# -y answers prompts; --no-progress and -r keep the output short.
$upgradeArgs = @("upgrade") + $ids + @("-y", "--no-progress", "-r", "--skip-if-not-installed")
if ($DryRun) { $upgradeArgs += "--noop" }   # --noop = do nothing, just report

& $choco @upgradeArgs
$code = $LASTEXITCODE

# --- 6. Map Chocolatey's exit codes to pass/fail --------------------------------
# 0 = success, 2 = nothing to upgrade (only with enhanced exit codes, Chocolatey 2.3.0+),
# 3010 = success but reboot required, 1641 = success and reboot initiated.
# None of those are failures. Anything else is, and is returned so TRMM shows it.
$ok = @(0, 2, 1641, 3010)
if ($code -in $ok) {
    Write-Output "Upgrade finished (exit code $code)"
    if ($parseErrors) { exit 1 }   # still fail if the list had typos, so they get fixed
    exit 0
}
Write-Output "Upgrade failed (exit code $code)"
exit $code

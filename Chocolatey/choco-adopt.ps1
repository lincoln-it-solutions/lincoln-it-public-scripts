<#
  choco-adopt.ps1 - TRMM script: bring already-installed software under Chocolatey management.

  Package list format (one entry per line, or separated by semicolons):
      <chocolatey package id>=<Windows display name, wildcards allowed>
  Example:
      googlechrome=Google Chrome
      adobereader=Adobe Acrobat*
  Lines starting with # are ignored (comments).

  Where the list comes from (first match wins):
      1. -Packages argument
      2. CHOCO_PACKAGES environment variable (set it to {{global.choco_managed_packages}} in TRMM)

  Default is REPORT ONLY. Pass -Apply to actually run 'choco install'.
#>
param(
    [string]$Packages = "",
    [switch]$Apply,
    [string]$ProxySourceName = 'lits-proget'
)

# --- 1. Get the package list ---------------------------------------------------
# Env var is preferred over an argument because TRMM arguments pass through the shell,
# which can mangle characters like * and spaces. Env vars skip that quoting problem.
if (-not $Packages) { $Packages = $env:CHOCO_PACKAGES }
if (-not $Packages) {
    Write-Output "ERROR: no package list. Set CHOCO_PACKAGES or pass -Packages."
    exit 1
}

# --- 2. Parse the list ---------------------------------------------------------
# Split on newlines or semicolons so the keystore value can be written either way.
$entries = @()
$parseErrors = $false
foreach ($line in ($Packages -split '[;\r\n]+')) {
    $line = $line.Trim()
    if (-not $line -or $line.StartsWith('#')) { continue }

    # Split on the FIRST '=' only, so the display-name pattern may itself contain '='.
    $eq = $line.IndexOf('=')
    if ($eq -lt 1 -or $eq -eq ($line.Length - 1)) {
        # A malformed line is reported (and fails the run at the end) rather than silently
        # skipped, so a typo in the list is noticed instead of leaving software unmanaged.
        Write-Output "ERROR: bad entry '$line' (expected id=display name)"
        $parseErrors = $true
        continue
    }
    $entries += [pscustomobject]@{
        Id   = $line.Substring(0, $eq).Trim()
        Name = $line.Substring($eq + 1).Trim()
    }
}

# --- 3. Find Chocolatey --------------------------------------------------------
# The agent runs as SYSTEM, so don't rely on PATH. Use the machine-level ChocolateyInstall
# variable, falling back to the default install location.
$chocoRoot = $env:ChocolateyInstall
if (-not $chocoRoot) { $chocoRoot = "C:\ProgramData\chocolatey" }
$choco = Join-Path $chocoRoot "bin\choco.exe"

# No Chocolatey means nothing to adopt into. Exit 0 so a broad policy does not raise
# failures on machines that are not Chocolatey-managed (a separate check covers installs).
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

# --- 4. Read installed software ------------------------------------------------
# Both uninstall hives: 64-bit apps register in the first, 32-bit apps in the WOW6432Node one.
# Limitation: per-user installs (HKCU) are not seen from SYSTEM, so they are not adopted.
$keys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
$installed = Get-ItemProperty $keys -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } |
    Select-Object -ExpandProperty DisplayName

# --- 5. Adopt each entry -------------------------------------------------------
$failed = $false
foreach ($e in $entries) {
    # Only adopt what is already present. This script never adds new software to a machine.
    $match = $installed | Where-Object { $_ -like $e.Name } | Select-Object -First 1
    if (-not $match) {
        Write-Output "SKIP   $($e.Id): nothing installed matches '$($e.Name)'"
        continue
    }

    # Chocolatey tracks installed packages as folders under its lib directory, so an
    # existing folder named after the id means the package is already managed.
    if (Test-Path (Join-Path $chocoRoot "lib\$($e.Id)")) {
        Write-Output "OK     $($e.Id): already managed"
        continue
    }

    # Report-only unless -Apply was passed, so a new list can be reviewed on a pilot site first.
    if (-not $Apply) {
        Write-Output "WOULD ADOPT  $($e.Id) (found installed as '$match')"
        continue
    }

    # Install the package over the existing app. -y answers prompts (nobody is at the console),
    # --no-progress and -r keep the TRMM output short.
    Write-Output "ADOPTING $($e.Id) (found installed as '$match')"
    & $choco install $e.Id -y --no-progress -r

    # 0 = success. 3010 / 1641 = success but a reboot is needed/initiated (per Chocolatey docs).
    # Anything else is a failure and is surfaced to TRMM through the exit code below.
    if ($LASTEXITCODE -notin 0, 1641, 3010) {
        Write-Output "FAILED $($e.Id): exit code $LASTEXITCODE"
        $failed = $true
    }
}

if ($failed -or $parseErrors) { exit 1 }
exit 0

<#
  choco-install.ps1 - TRMM script: install MISSING software from a per-client list via Chocolatey.

  This is the third script in the set:
      choco-adopt.ps1   brings software that is already installed under Chocolatey
      choco-patch.ps1   upgrades the packages in the shared list
      choco-install.ps1 (this one) installs software that is NOT on the machine yet

  List format - the same as the shared list, one entry per line (or separated by semicolons):
      <chocolatey package id>=<Windows display name, wildcards allowed>
  Example:
      googlechrome=Google Chrome
      adobereader=Adobe Acrobat*
  Lines starting with # are ignored.

  Where the list comes from (first match wins):
      1. -Packages argument
      2. CHOCO_INSTALL_PACKAGES environment variable.
         In TRMM set it to a CLIENT (or site) custom field, e.g.
             CHOCO_INSTALL_PACKAGES={{client.Choco Install Packages}}
         so each client gets only the software it wants.

  Default is REPORT ONLY. Pass -Apply to actually run 'choco install'.
#>
param(
    [string]$Packages = "",
    [switch]$Apply,
    [string]$ProxySourceName = 'lits-proget'
)

# --- 1. Get the list -----------------------------------------------------------
# Env var preferred over an argument to avoid shell quoting problems (see choco-adopt.ps1).
if (-not $Packages) { $Packages = $env:CHOCO_INSTALL_PACKAGES }

# TRMM passes a custom-field reference through AS-IS when it cannot find the field
# (misspelled name, field not created). Installing from the literal text '{{...}}' would be
# meaningless, so detect it and fail loudly instead of silently doing nothing.
if ($Packages -match '\{\{') {
    Write-Output "ERROR: list still contains '{{...}}' - the TRMM custom field was not resolved. Check the field name (it is case sensitive)."
    exit 1
}

# An empty list is a legitimate state (a client that wants nothing installed), so this is not
# a failure. Exit 0 so the task does not alert for clients with an empty field.
if (-not $Packages -or -not $Packages.Trim()) {
    Write-Output "No packages listed for this client, nothing to do"
    exit 0
}

# --- 2. Parse the list ---------------------------------------------------------
# Same parsing rules as the other two scripts so the list means the same thing everywhere.
$entries = @()
$parseErrors = $false
foreach ($line in ($Packages -split '[;\r\n]+')) {
    $line = $line.Trim()
    if (-not $line -or $line.StartsWith('#')) { continue }

    # Split on the FIRST '=' only, so the display-name pattern may itself contain '='.
    $eq = $line.IndexOf('=')
    if ($eq -lt 1 -or $eq -eq ($line.Length - 1)) {
        # Report malformed lines and fail at the end, rather than silently skipping a typo.
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
# The agent runs as SYSTEM, so don't rely on PATH.
$chocoRoot = $env:ChocolateyInstall
if (-not $chocoRoot) { $chocoRoot = "C:\ProgramData\chocolatey" }
$choco = Join-Path $chocoRoot "bin\choco.exe"

# Without Chocolatey this script cannot install anything. Unlike the patch script, this one
# is explicitly asked to install, so a missing Chocolatey IS a problem worth surfacing.
if (-not (Test-Path $choco)) {
    Write-Output "ERROR: choco.exe not found, cannot install"
    exit 1
}

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
# Both uninstall hives (64-bit and 32-bit apps register in different places).
# Limitation: per-user installs (HKCU) are invisible to SYSTEM, so an app installed only for
# one user would look "missing" and be installed machine-wide. Run with -Apply on a pilot first.
$keys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
$installed = Get-ItemProperty $keys -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } |
    Select-Object -ExpandProperty DisplayName

# --- 5. Install each missing entry ---------------------------------------------
$failed = $false
foreach ($e in $entries) {
    # Already managed by Chocolatey: nothing to do (choco-patch.ps1 keeps it updated).
    if (Test-Path (Join-Path $chocoRoot "lib\$($e.Id)")) {
        Write-Output "OK     $($e.Id): already managed by Chocolatey"
        continue
    }

    # Already installed some other way: do NOT install over it here. That is adoption, which is
    # choco-adopt.ps1's job and is controlled by the shared list. This protects existing installs,
    # e.g. a perpetual Office licence or a vendor-managed version.
    $match = $installed | Where-Object { $_ -like $e.Name } | Select-Object -First 1
    if ($match) {
        Write-Output "SKIP   $($e.Id): already installed as '$match' (use choco-adopt.ps1 to adopt it)"
        continue
    }

    # Report-only unless -Apply was passed.
    if (-not $Apply) {
        Write-Output "WOULD INSTALL  $($e.Id)"
        continue
    }

    # -y answers prompts (nobody is at the console); --no-progress and -r keep output short.
    Write-Output "INSTALLING $($e.Id)"
    & $choco install $e.Id -y --no-progress -r

    # 0 = success; 3010 / 1641 = success but reboot needed/initiated (per Chocolatey docs).
    # Anything else is a failure, surfaced to TRMM through the exit code below.
    if ($LASTEXITCODE -notin 0, 1641, 3010) {
        Write-Output "FAILED $($e.Id): exit code $LASTEXITCODE"
        $failed = $true
    }
}

if ($failed -or $parseErrors) { exit 1 }
exit 0

<#
.SYNOPSIS
    Read-only HP check: Secure Boot state and BIOS settings (read straight
    from HP's WMI interface, nothing installed), plus optional BIOS-update
    check and a Windows Update search. Never flashes or changes a BIOS.

.DESCRIPTION
    Default run (no arguments) makes NO changes to the machine:
      1. Device / installed BIOS.
      2. Secure Boot state as Windows sees it (Confirm-SecureBootUEFI).
      3. BIOS settings related to Secure Boot, read from HP's WMI namespace
         root\HP\InstrumentedBIOS (class HP_BIOSEnumeration), with each
         setting's current value, read-only flag and F10 menu path.
      4. Whether a BIOS setup password is set (HP_BIOSPassword.IsSet).
         Only the set/not-set flag is read, never any password value.
      5. Get-HPBiosUpdates -Check, ONLY IF the HP.Firmware module is already
         installed.
      6. Windows Update search (search only) for pending driver-type updates.

    Optional argument  -InstallHPModule
      Installs HPCMSL from the PowerShell Gallery if HP.Firmware is missing,
      so step 5 can run. This CHANGES the machine. On a ProBook 450 G9 with the
      old built-in PowerShellGet 1.0.0.1 it first has to upgrade PowerShellGet
      (HPCMSL modules use PowerShellGet format 2.0). That upgrade FAILED on
      2026-10-16 ("PackageManagement failed to download"), so this switch is
      off by default. No licence is accepted on anyone's behalf.

    Designed to run from TRMM (as SYSTEM, which is elevated).

.NOTES
    Sources: HP "Understanding HP BIOS Settings" (developers.hp.com/node/213696)
    for the WMI namespace, classes and properties; HP "BIOS Updates, a How-To
    Guide" (developers.hp.com/node/41531) for Get-HPBiosUpdates -Check;
    Microsoft "Installing PowerShellGet" for the module upgrade.
    This script shows what a setting IS now. It cannot show who changed it
    or why.
#>

param(
    # Off by default: only turn on when you accept that modules get installed.
    [switch]$InstallHPModule
)

# Enable TLS 1.2 for the PowerShell Gallery and HP servers (Microsoft's docs
# say the Gallery requires it; Windows PowerShell 5.1 may not enable it).
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# ---------------------------------------------------------------------------
# 0. Admin check
# Why: reading BIOS settings via WMI and searching Windows Update need
# elevation. TRMM runs as SYSTEM, which passes this.
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "Not running as Administrator."
    exit 0
}

# ---------------------------------------------------------------------------
# 1. Is this an HP machine, and what BIOS is installed?
# Why: the HP WMI namespace only exists on HP hardware, so we stop early on
# anything else.
# ---------------------------------------------------------------------------
Write-Host "`n=== 1. Device / installed BIOS ===" -ForegroundColor Cyan

$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS

[PSCustomObject]@{
    Manufacturer    = $cs.Manufacturer
    Model           = $cs.Model
    BIOSVersion     = $bios.SMBIOSBIOSVersion
    BIOSReleaseDate = $bios.ReleaseDate
} | Format-List

if ($cs.Manufacturer -notmatch 'HP|Hewlett') {
    Write-Host "Manufacturer is '$($cs.Manufacturer)', not HP. Stopping." -ForegroundColor Yellow
    exit 0
}

# ---------------------------------------------------------------------------
# 2. Windows' view of Secure Boot
# Why: Confirm-SecureBootUEFI reports the state the firmware is currently in
# (True = on, False = off). It throws on non-UEFI systems, so we catch that
# and print the message instead of guessing.
# ---------------------------------------------------------------------------
Write-Host "=== 2. Secure Boot state as seen by Windows ===" -ForegroundColor Cyan

try {
    Write-Host "Confirm-SecureBootUEFI returned: $(Confirm-SecureBootUEFI -ErrorAction Stop)"
}
catch {
    Write-Host "Could not determine: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 3. BIOS settings related to Secure Boot, read from HP's WMI interface
# Why: shows the real setting names and values on this model, so nothing has
# to be guessed. This uses HP's documented namespace root\HP\InstrumentedBIOS;
# HP_BIOSEnumeration holds settings with a fixed set of possible values
# (e.g. Enable/Disable), which is where most options live. Read only.
# IsReadOnly = 1 means the setting cannot be changed through this interface.
# ---------------------------------------------------------------------------
Write-Host "`n=== 3. BIOS settings matching Secure Boot / certificate / boot-mode terms ===" -ForegroundColor Cyan

# Terms chosen from the Secure Boot topic: Secure Boot itself, Legacy boot,
# certificate / key / KEK names, UEFI CA options.
$pattern = 'Secure|Legacy|Certificate|KEK|UEFI|Boot Mode|Platform Key|Key'

try {
    $all = Get-CimInstance -Namespace 'root\HP\InstrumentedBIOS' -ClassName HP_BIOSEnumeration -ErrorAction Stop
    Write-Host "Total enumeration-type BIOS settings returned: $(@($all).Count)"

    $hits = $all | Where-Object { $_.Name -match $pattern } | Sort-Object Path, Name
    if ($hits) {
        $hits | ForEach-Object {
            Write-Host ("- {0}" -f $_.Name)
            Write-Host ("    CurrentValue   : {0}" -f $_.CurrentValue)
            Write-Host ("    PossibleValues : {0}" -f ($_.PossibleValues -join ', '))
            Write-Host ("    IsReadOnly     : {0}" -f $_.IsReadOnly)
            Write-Host ("    Path           : {0}" -f $_.Path)
        }
    }
    else {
        # Show what IS there so we can see the real names.
        Write-Host "No settings matched. All setting names returned:"
        $all | Sort-Object Name | ForEach-Object { Write-Host "  $($_.Name) = $($_.CurrentValue)" }
    }
}
catch {
    Write-Host "Could not read HP BIOS settings: $($_.Exception.Message)" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 4. Is a BIOS setup password set?
# Why: a password would be needed to change settings remotely. HP's docs say
# HP_BIOSPassword.IsSet is 1 when a password is set, 0 when blank, and that
# password values themselves are never exposed. We print only Name and IsSet.
# ---------------------------------------------------------------------------
Write-Host "`n=== 4. BIOS password flags (set / not set only) ===" -ForegroundColor Cyan

try {
    Get-CimInstance -Namespace 'root\HP\InstrumentedBIOS' -ClassName HP_BIOSPassword -ErrorAction Stop |
        Select-Object Name, IsSet | Format-Table -AutoSize | Out-String | Write-Host
}
catch {
    Write-Host "Could not read password flags: $($_.Exception.Message)" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 5. Is a newer HP BIOS available? (needs the HP.Firmware module)
# Why: Get-HPBiosUpdates -Check is HP's documented check. HP's example flashes
# only when "-not (Get-HPBiosUpdates -Check)" is true, but the page does not
# spell out what True/False means, so we print the RAW value and do not
# interpret it. -Check only reads; it never flashes.
# The module is only installed when -InstallHPModule was passed.
# ---------------------------------------------------------------------------
Write-Host "=== 5. Get-HPBiosUpdates -Check ===" -ForegroundColor Cyan

$module = Get-Module -ListAvailable -Name HP.Firmware | Sort-Object Version -Descending | Select-Object -First 1

if (-not $module -and $InstallHPModule) {
    Write-Host "HP.Firmware not found and -InstallHPModule was given. Installing HPCMSL..."
    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null

        # The old built-in PowerShellGet 1.0.0.1 cannot install format-2.0
        # modules, which all HPCMSL modules use, so upgrade it first.
        $psg = Get-Module -ListAvailable -Name PowerShellGet | Sort-Object Version -Descending | Select-Object -First 1
        Write-Host "Current PowerShellGet: $($psg.Version)"
        if ($psg.Version -lt [version]'2.0.0') {
            Install-Module -Name PowerShellGet -Repository PSGallery -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
        }

        # Install HPCMSL in a NEW powershell.exe so the newer PowerShellGet
        # is the one that loads. No -AcceptLicense: we do not accept terms
        # on anyone's behalf.
        $installCmd = "Install-Module -Name HPCMSL -Scope AllUsers -Force -AllowClobber -ErrorAction Stop"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $installCmd 2>&1 | ForEach-Object { Write-Host "  [child] $_" }
        $module = Get-Module -ListAvailable -Name HP.Firmware | Sort-Object Version -Descending | Select-Object -First 1
    }
    catch {
        Write-Host "Install failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if ($module) {
    try {
        Import-Module HP.Firmware -ErrorAction Stop
        if (-not (Get-Command Get-HPBiosUpdates -ErrorAction SilentlyContinue)) {
            Write-Host "Get-HPBiosUpdates not found. Commands in HP.Firmware matching 'BIOS':"
            Get-Command -Module HP.Firmware | Where-Object Name -match 'BIOS' | Select-Object -ExpandProperty Name
        }
        else {
            Write-Host "Raw return value: $(Get-HPBiosUpdates -Check -ErrorAction Stop)"
        }
    }
    catch {
        Write-Host "Could not run the check: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "HP.Firmware module is not installed, so the BIOS update check was skipped."
    Write-Host "(Re-run with the argument -InstallHPModule to install it. That changes the machine.)"
}

# ---------------------------------------------------------------------------
# 6. Windows Update search (search only)
# Why: shows whether Windows Update is offering any driver-type updates, and
# which categories they carry, so a firmware/BIOS update would be visible.
# We only SEARCH; nothing is downloaded or installed.
# ---------------------------------------------------------------------------
Write-Host "`n=== 6. Windows Update: pending driver-type updates ===" -ForegroundColor Cyan

try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    # IsInstalled=0 limits to updates not yet installed; Type='Driver' is the
    # update type used for driver and firmware packages.
    $result = $searcher.Search("IsInstalled=0 and Type='Driver'")

    Write-Host "Pending driver-type updates found: $($result.Updates.Count)"

    foreach ($u in $result.Updates) {
        # Print every category so nothing is hidden by an assumption about
        # which category a BIOS update would use.
        $cats = ($u.Categories | ForEach-Object { $_.Name }) -join '; '
        Write-Host ("- {0}`n    Categories: {1}" -f $u.Title, $cats)
    }
}
catch {
    Write-Host "Windows Update search failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nDone. No BIOS setting or BIOS update was changed." -ForegroundColor Green
# Exit 0 always: information-gathering script, so no failed-task alert in TRMM.
exit 0

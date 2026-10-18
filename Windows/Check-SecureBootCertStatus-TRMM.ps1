<#
.SYNOPSIS
    Read-only check of Secure Boot state, 2023 certificate update status,
    related event log entries, and BIOS/firmware version.

.DESCRIPTION
    Makes NO changes to the system. It only reads:
      - Secure Boot state
      - Servicing registry values written by Windows
      - TPM-WMI events in the System event log
      - Secure Boot KEK and DB variables (to see if 2023 certs are present)
      - BIOS / model information via CIM

    TRMM VARIANT: identical checks to Check-SecureBootCertStatus.ps1, but
    the transcript/Desktop report is removed. TRMM captures the script's
    output itself, and when run via TRMM there is no logged-in Desktop
    (the agent runs as SYSTEM, which is elevated, so the admin check passes).
    Reading Secure Boot UEFI variables requires admin rights.

.NOTES
    Event IDs and registry values used here come from Microsoft's KB5016061
    (Secure Boot DB and DBX variable update events) and the Secure Boot
    servicing registry key. Event IDs that are not in the documented list
    below are shown as-is and are NOT interpreted by this script.
#>

# ---------------------------------------------------------------------------
# 0. Admin check
# Why: Get-SecureBootUEFI and Confirm-SecureBootUEFI fail without elevation,
# and a silent failure would look like "no certificates found".
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "Not running as Administrator. Re-run from an elevated PowerShell window."
    return
}

# (No Start-Transcript here: TRMM stores the script output in the task/run
# result, so a Desktop file is not needed and would not exist under SYSTEM.)

# ---------------------------------------------------------------------------
# 1. Device, BIOS and OS information
# Why: the BIOS version is what you compare against HP's support page to see
# whether a newer BIOS (with 2023 certificate support) exists for this model.
# Win32_BIOS.SMBIOSBIOSVersion is the string HP shows (e.g. "S70 Ver. 01.12.00").
# ---------------------------------------------------------------------------
Write-Host "`n=== 1. Device / BIOS / OS ===" -ForegroundColor Cyan

$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os   = Get-CimInstance Win32_OperatingSystem

[PSCustomObject]@{
    Manufacturer    = $cs.Manufacturer
    Model           = $cs.Model
    SerialNumber    = $bios.SerialNumber
    BIOSVersion     = $bios.SMBIOSBIOSVersion
    BIOSReleaseDate = $bios.ReleaseDate
    BIOSVendor      = $bios.Manufacturer
    OS              = $os.Caption
    OSBuild         = "$($os.Version) (UBR $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR))"
} | Format-List

# ---------------------------------------------------------------------------
# 2. Is the machine booted in UEFI mode, and is Secure Boot on?
# Why: Confirm-SecureBootUEFI returns True/False on UEFI systems and THROWS on
# legacy BIOS. We catch the throw so we can report "not UEFI" instead of
# guessing. The state is reported exactly as returned.
# ---------------------------------------------------------------------------
Write-Host "=== 2. Secure Boot state ===" -ForegroundColor Cyan

try {
    $sbEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
    Write-Host "Confirm-SecureBootUEFI returned: $sbEnabled"
}
catch {
    $sbEnabled = $null
    Write-Host "Confirm-SecureBootUEFI could not determine state: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 3. Servicing registry values written by Windows during the cert update
# Why: UEFICA2023Status shows how far the update has got (documented values
# include NotStarted / InProgress / Updated). UEFICA2023Error, if present,
# indicates the servicing task recorded a failure.
# We print the raw values and do not interpret missing keys as failure.
# ---------------------------------------------------------------------------
Write-Host "`n=== 3. Secure Boot servicing registry ===" -ForegroundColor Cyan

$servicingPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'

if (Test-Path $servicingPath) {
    # Show every value under the key so nothing is hidden by my assumptions.
    Get-ItemProperty -Path $servicingPath |
        Select-Object * -ExcludeProperty PS* |
        Format-List
}
else {
    Write-Host "Key not found: $servicingPath" -ForegroundColor Yellow
    Write-Host "(This usually means the OS has not received the Secure Boot servicing update yet - not confirmed from this script alone.)"
}

# The parent key holds other Secure Boot values (e.g. the update trigger
# AvailableUpdates). Shown for completeness.
$sbPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
if (Test-Path $sbPath) {
    Write-Host "--- Values directly under $sbPath ---"
    Get-ItemProperty -Path $sbPath |
        Select-Object * -ExcludeProperty PS* |
        Format-List
}

# ---------------------------------------------------------------------------
# 4. TPM-WMI events in the System log
# Why: Windows logs the certificate update progress under the TPM-WMI
# provider. Documented IDs (Microsoft KB5016061 and vendor write-ups):
#   1795 = firmware returned an error when applying a DB/DBX/KEK update
#   1796 = unexpected error during the update
#   1800 = reboot required before the update can be installed
#   1801 = updated certificates available but not yet applied to firmware
#   1808 = update applied successfully
# Other TPM-WMI IDs are listed but labelled "not interpreted".
# ---------------------------------------------------------------------------
Write-Host "`n=== 4. TPM-WMI events (System log) ===" -ForegroundColor Cyan

# Lookup table so the output is readable. Only IDs I have a source for.
$knownIds = @{
    1795 = 'Firmware returned an error applying Secure Boot variable update'
    1796 = 'Unexpected error during Secure Boot update'
    1800 = 'Reboot required before Secure Boot update'
    1801 = 'Updated certificates available but not yet applied to firmware'
    1808 = 'Secure Boot update applied successfully'
}

try {
    # Filter by provider name so we only get Secure Boot servicing events,
    # not every System event. -MaxEvents keeps it quick on busy machines.
    $events = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-TPM-WMI'
    } -MaxEvents 200 -ErrorAction Stop

    if ($events) {
        # Summary count per event ID, so you can see at a glance what exists.
        Write-Host "--- Count by Event ID ---"
        $events | Group-Object Id | Sort-Object Name |
            Select-Object @{n='EventId';e={$_.Name}}, Count,
                          @{n='Meaning';e={ if ($knownIds[[int]$_.Name]) { $knownIds[[int]$_.Name] } else { 'not interpreted by this script' } }} |
            Format-Table -AutoSize

        # Full detail of the documented IDs, newest first, with the complete
        # message text. The message often contains the specific reason
        # (e.g. "blocked due to a known firmware issue").
        Write-Host "--- Documented events (newest first) ---"
        $events | Where-Object { $knownIds.ContainsKey([int]$_.Id) } |
            Sort-Object TimeCreated -Descending |
            ForEach-Object {
                Write-Host ("[{0}] ID {1} ({2})" -f $_.TimeCreated, $_.Id, $knownIds[[int]$_.Id]) -ForegroundColor White
                Write-Host $_.Message
                Write-Host ''
            }
    }
}
catch [System.Exception] {
    # Get-WinEvent throws "No events were found" when nothing matches.
    # That is a real finding (no TPM-WMI events), so report it as such.
    if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') {
        Write-Host "No TPM-WMI events found in the System log." -ForegroundColor Yellow
    }
    else {
        Write-Host "Error reading event log: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
# 5. Are the 2023 certificates actually present in firmware?
# Why: the registry and events show what Windows tried; the KEK and DB
# variables show what is really stored in the firmware.
# Certificate names live as plain ASCII inside the X.509 data, so we decode
# the raw bytes to text and search for the names. This is a string match on
# the raw variable, not a full certificate parse.
# NOTE: Get-SecureBootUEFI can read these variables even when Secure Boot is
# disabled, as long as the system boots in UEFI mode.
# ---------------------------------------------------------------------------
Write-Host "`n=== 5. Certificates present in firmware variables ===" -ForegroundColor Cyan

function Test-UefiVariableForText {
    param(
        [string]$VariableName,   # 'KEK' or 'db'
        [string[]]$SearchText    # names to look for
    )
    try {
        $bytes = (Get-SecureBootUEFI -Name $VariableName -ErrorAction Stop).Bytes
        $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
        foreach ($t in $SearchText) {
            [PSCustomObject]@{
                Variable = $VariableName
                Looking  = $t
                Found    = ($text -match [regex]::Escape($t))
            }
        }
    }
    catch {
        [PSCustomObject]@{
            Variable = $VariableName
            Looking  = '(read failed)'
            Found    = $_.Exception.Message
        }
    }
}

# Names taken from Microsoft documentation and forum reports. The KEK has
# been reported under both "KEK CA 2023" and "KEK 2K CA 2023", so both are checked.
$results = @()
$results += Test-UefiVariableForText -VariableName 'KEK' -SearchText @(
    'Microsoft Corporation KEK CA 2011',
    'Microsoft Corporation KEK CA 2023',
    'Microsoft Corporation KEK 2K CA 2023'
)
$results += Test-UefiVariableForText -VariableName 'db' -SearchText @(
    'Microsoft Windows Production PCA 2011',
    'Windows UEFI CA 2023',
    'Microsoft UEFI CA 2011',
    'Microsoft UEFI CA 2023'
)
$results | Format-Table -AutoSize

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host "`nDone." -ForegroundColor Green
# Exit 0 always: this is an information-gathering script, so it should not
# raise a failed-task alert in TRMM just because a check returned "not found".
exit 0

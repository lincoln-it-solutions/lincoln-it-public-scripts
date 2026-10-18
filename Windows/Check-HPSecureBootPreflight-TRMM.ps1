<#
.SYNOPSIS
    Read-only PRE-FLIGHT check before enabling Secure Boot on an HP machine.
    Changes nothing. Does not enable Secure Boot. Never prints BitLocker
    recovery passwords or any BIOS password.

.DESCRIPTION
    Gathers the facts that decide whether enabling Secure Boot remotely is
    reasonable, then prints a list of FLAGS (things that need attention).
    It is a fact-finder, not a guarantee: the only real test of whether the
    machine boots with Secure Boot on is turning it on.

    Checks:
      1. Firmware mode and current Secure Boot state.
      2. BitLocker volumes and protector TYPES (types only, no key values).
      3. TPM status.
      4. Boot disk layout (GPT and an EFI system partition).
      5. Secure Boot key variables (PK / KEK / db / dbx) present or empty,
         and whether the Microsoft 2011 certificates are in them.
      6. HP BIOS: Secure Boot setting (and whether it is read-only),
         related key settings, boot options, setup/power-on password flags.
      7. Boot entries known to the firmware.

    Designed to run from TRMM (as SYSTEM, which is elevated).

.NOTES
    Sources: HP "Understanding HP BIOS Settings" (developers.hp.com/node/213696)
    for the WMI namespace/properties; Microsoft's Get-SecureBootUEFI and
    Get-BitLockerVolume documentation for the cmdlets.
#>

# ---------------------------------------------------------------------------
# 0. Admin check
# Why: BitLocker, firmware variables and HP WMI need elevation. TRMM runs as
# SYSTEM, which passes this.
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "Not running as Administrator."
    exit 0
}

# Collects anything that needs attention; printed at the end.
# Why: one place to look instead of reading every section.
$flags = New-Object System.Collections.Generic.List[string]

# ---------------------------------------------------------------------------
# 1. Device, firmware mode and Secure Boot state
# Why: Confirm-SecureBootUEFI throws on non-UEFI (legacy BIOS) systems, which
# we treat as a STOP flag; enabling Secure Boot there is not possible.
# ---------------------------------------------------------------------------
Write-Host "`n=== 1. Device / firmware / Secure Boot state ===" -ForegroundColor Cyan

$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
[PSCustomObject]@{
    Manufacturer = $cs.Manufacturer
    Model        = $cs.Model
    BIOSVersion  = $bios.SMBIOSBIOSVersion
} | Format-List

$sbState = $null
try {
    $sbState = Confirm-SecureBootUEFI -ErrorAction Stop
    Write-Host "UEFI firmware: yes. Confirm-SecureBootUEFI returned: $sbState"
    if ($sbState) { $flags.Add("Secure Boot is already ON - nothing to enable.") }
}
catch {
    Write-Host "Confirm-SecureBootUEFI failed: $($_.Exception.Message)" -ForegroundColor Yellow
    $flags.Add("STOP: could not confirm UEFI/Secure Boot support ($($_.Exception.Message))")
}

# ---------------------------------------------------------------------------
# 2. BitLocker
# Why: one source warns BIOS/Secure Boot changes often trigger a BitLocker
# recovery prompt. We list volumes and protector TYPES only. We deliberately
# do NOT print the protector values, because that would expose recovery
# passwords in TRMM's stored output.
# ---------------------------------------------------------------------------
Write-Host "`n=== 2. BitLocker (types only, no key values) ===" -ForegroundColor Cyan

try {
    $vols = Get-BitLockerVolume -ErrorAction Stop
    foreach ($v in $vols) {
        $types = ($v.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ', '
        Write-Host ("{0}  VolumeStatus={1}  ProtectionStatus={2}  Method={3}" -f $v.MountPoint, $v.VolumeStatus, $v.ProtectionStatus, $v.EncryptionMethod)
        Write-Host ("    Protector types: {0}" -f $(if ($types) { $types } else { '(none)' }))
        if ("$($v.ProtectionStatus)" -match 'On|1') {
            $flags.Add("BitLocker protection is ON for $($v.MountPoint) (protectors: $types). Confirm the recovery key is saved outside this PC before changing Secure Boot.")
        }
    }
}
catch {
    Write-Host "Could not read BitLocker state: $($_.Exception.Message)" -ForegroundColor Yellow
    $flags.Add("BitLocker state could not be read ($($_.Exception.Message)).")
}

# ---------------------------------------------------------------------------
# 3. TPM
# Why: a TPM-based BitLocker protector depends on the TPM; shows whether the
# TPM is present and ready.
# ---------------------------------------------------------------------------
Write-Host "`n=== 3. TPM ===" -ForegroundColor Cyan

try {
    Get-Tpm -ErrorAction Stop | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated | Format-List
}
catch {
    Write-Host "Could not read TPM: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 4. Boot disk layout
# Why: UEFI Secure Boot needs the Windows disk to be GPT with an EFI system
# partition. An MBR disk is a STOP flag.
# ---------------------------------------------------------------------------
Write-Host "`n=== 4. Boot disk layout ===" -ForegroundColor Cyan

try {
    $letter = $env:SystemDrive.TrimEnd(':')
    $part   = Get-Partition -DriveLetter $letter -ErrorAction Stop
    $disk   = Get-Disk -Number $part.DiskNumber -ErrorAction Stop
    Write-Host ("Windows is on disk {0}: PartitionStyle={1}, BusType={2}" -f $disk.Number, $disk.PartitionStyle, $disk.BusType)

    # c12a7328-... is the standard GPT type GUID for an EFI System Partition.
    $esp = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' }
    if ($esp) { Write-Host ("EFI system partition found: {0} bytes" -f ($esp | Select-Object -First 1).Size) }
    else      { Write-Host "No EFI system partition found on this disk." -ForegroundColor Yellow }

    if ("$($disk.PartitionStyle)" -ne 'GPT') { $flags.Add("STOP: Windows disk is $($disk.PartitionStyle), not GPT.") }
    if (-not $esp)                           { $flags.Add("No EFI system partition found on the Windows disk.") }
}
catch {
    Write-Host "Could not read disk layout: $($_.Exception.Message)" -ForegroundColor Yellow
    $flags.Add("Disk layout could not be read ($($_.Exception.Message)).")
}

# ---------------------------------------------------------------------------
# 5. Secure Boot key variables
# Why: Secure Boot needs a Platform Key (PK) and keys to validate the boot
# loader. We report whether each variable has content, and look for the
# Microsoft certificate names as plain text in the raw bytes (a text match,
# not a full certificate parse).
# ---------------------------------------------------------------------------
Write-Host "`n=== 5. Secure Boot key variables ===" -ForegroundColor Cyan

$texts = @{}
foreach ($name in 'PK','KEK','db','dbx') {
    try {
        $bytes = (Get-SecureBootUEFI -Name $name -ErrorAction Stop).Bytes
        $len = if ($bytes) { $bytes.Length } else { 0 }
        Write-Host ("{0,-4}: {1} bytes" -f $name, $len)
        $texts[$name] = if ($len -gt 0) { [System.Text.Encoding]::ASCII.GetString($bytes) } else { '' }
        if ($len -eq 0 -and $name -in 'PK','KEK','db') { $flags.Add("Secure Boot variable '$name' is empty.") }
    }
    catch {
        Write-Host ("{0,-4}: could not read ({1})" -f $name, $_.Exception.Message) -ForegroundColor Yellow
        if ($name -in 'PK','KEK','db') { $flags.Add("Secure Boot variable '$name' could not be read.") }
    }
}

Write-Host "--- Certificate names found (text match) ---"
$names = @(
    @{ Var='KEK'; Text='Microsoft Corporation KEK CA 2011' },
    @{ Var='db';  Text='Microsoft Windows Production PCA 2011' },
    @{ Var='db';  Text='Microsoft UEFI CA 2011' },
    @{ Var='db';  Text='Windows UEFI CA 2023' }
)
foreach ($n in $names) {
    $found = $texts[$n.Var] -and ($texts[$n.Var] -match [regex]::Escape($n.Text))
    Write-Host ("{0,-4} {1,-40} {2}" -f $n.Var, $n.Text, [bool]$found)
}

# ---------------------------------------------------------------------------
# 6. HP BIOS settings
# Why: whether the Secure Boot setting can be changed, whether any BIOS
# password blocks changes, and which boot options exist. Read from HP's
# documented WMI namespace root\HP\InstrumentedBIOS. IsReadOnly=1 means the
# setting cannot be changed through this interface.
# ---------------------------------------------------------------------------
Write-Host "`n=== 6. HP BIOS settings ===" -ForegroundColor Cyan

try {
    $all = Get-CimInstance -Namespace 'root\HP\InstrumentedBIOS' -ClassName HP_BIOSEnumeration -ErrorAction Stop

    Write-Host "--- Secure Boot Configuration and key protection ---"
    $all | Where-Object { $_.Path -match 'Secure Boot Configuration' -or $_.Name -match 'Secure Boot' } |
        Sort-Object Path, Name | ForEach-Object {
            Write-Host ("{0} = {1}   (ReadOnly={2}, Options: {3})" -f $_.Name, $_.CurrentValue, $_.IsReadOnly, ($_.PossibleValues -join '/'))
        }

    Write-Host "--- Boot Options ---"
    $all | Where-Object { $_.Path -match 'Boot Options' } | Sort-Object Name | ForEach-Object {
        Write-Host ("{0} = {1}   (ReadOnly={2})" -f $_.Name, $_.CurrentValue, $_.IsReadOnly)
    }

    $sb = $all | Where-Object { $_.Name -eq 'Secure Boot' } | Select-Object -First 1
    if (-not $sb)                    { $flags.Add("No BIOS setting named 'Secure Boot' was found.") }
    elseif ($sb.IsReadOnly -eq 1)    { $flags.Add("BIOS 'Secure Boot' setting is READ-ONLY; it cannot be changed through this interface.") }
}
catch {
    Write-Host "Could not read HP BIOS settings: $($_.Exception.Message)" -ForegroundColor Yellow
    $flags.Add("HP BIOS settings could not be read ($($_.Exception.Message)).")
}

# Password flags only (set / not set). HP says password values are never exposed.
Write-Host "--- BIOS password flags (set = 1, not set = 0) ---"
try {
    $pw = Get-CimInstance -Namespace 'root\HP\InstrumentedBIOS' -ClassName HP_BIOSPassword -ErrorAction Stop
    $pw | ForEach-Object { Write-Host ("{0}: IsSet={1}" -f $_.Name, $_.IsSet) }
    if ($pw | Where-Object { $_.IsSet -eq 1 }) { $flags.Add("A BIOS password is set; changing BIOS settings will need it.") }
}
catch {
    Write-Host "Could not read password flags: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 7. Boot entries
# Why: shows what the firmware can boot (e.g. other operating systems or
# tools). The current Windows loader path is printed raw so it can be read
# against what is expected, without this script interpreting it.
# ---------------------------------------------------------------------------
Write-Host "`n=== 7. Boot entries ===" -ForegroundColor Cyan

Write-Host "--- Current Windows boot entry ---"
bcdedit /enum '{current}' 2>&1 | Select-String -Pattern 'description|path|device|osdevice' | ForEach-Object { Write-Host $_.Line }

Write-Host "--- Firmware boot entries (descriptions) ---"
bcdedit /enum firmware 2>&1 | Select-String -Pattern 'description' | ForEach-Object { Write-Host $_.Line }

# ---------------------------------------------------------------------------
# Summary
# Why: everything that needs attention, in one list. An empty list means the
# checks above found nothing to flag, NOT that the change is guaranteed safe.
# ---------------------------------------------------------------------------
Write-Host "`n=== FLAGS ===" -ForegroundColor Cyan
if ($flags.Count -eq 0) { Write-Host "Nothing flagged by these checks." }
else { $flags | ForEach-Object { Write-Host "- $_" -ForegroundColor Yellow } }

Write-Host "`nDone. Nothing was changed. Secure Boot was NOT enabled." -ForegroundColor Green
# Exit 0 always: information-gathering script, so no failed-task alert in TRMM.
exit 0

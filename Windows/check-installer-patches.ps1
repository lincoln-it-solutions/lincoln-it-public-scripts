# check-installer-patches.ps1
# READ-ONLY: this script does not move, rename or delete anything.
#
# PURPOSE
#   Decide which .msp files in C:\Windows\Installer are still registered with
#   Windows Installer, using a second method that is independent of the COM
#   enumeration used last time. That COM-based report marked 126 of 126 .msp
#   files as orphans, which is not believable on its own, so it cannot be used
#   to justify moving or deleting anything.
#
# HOW IT WORKS
#   Windows Installer records each registered patch in the registry under
#     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\<SID>\Patches\<PatchKey>
#   and the value "LocalPackage" on that key is the path of the cached .msp.
#   (Source: Microsoft Learn, "How to fix MSI software update registration
#   corruption issues".) We read that value for every SID, then compare the
#   result with the .msp files actually on disk.
#
# Run in an elevated PowerShell.

# ---------------------------------------------------------------- 0. context
# Show which account is running the script, so the output can be interpreted.
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host "Running as: $($id.Name)"

# The UserData registry area is only readable by administrators/SYSTEM, so stop
# early with a clear message instead of silently reading nothing.
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Please re-run from an elevated (Administrator) PowerShell." }

$installerDir = 'C:\Windows\Installer'
$userData     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'

# ------------------------------------------------- 1. read patch registrations
# $registered maps "lower-cased cached .msp path" -> details of its registration.
# A hashtable gives fast lookups when we compare against the files on disk.
$registered = @{}
$keysRead   = 0

# Each child of UserData is a SID (S-1-5-18 is typically the machine/SYSTEM one,
# but we read every SID rather than assume which one matters).
foreach ($sidKey in Get-ChildItem -Path $userData -ErrorAction SilentlyContinue) {

    # Each child of <SID>\Patches is one registered patch.
    $patchRoot = Join-Path $sidKey.PSPath 'Patches'
    foreach ($patchKey in Get-ChildItem -Path $patchRoot -ErrorAction SilentlyContinue) {
        $keysRead++
        $props = Get-ItemProperty -Path $patchKey.PSPath -ErrorAction SilentlyContinue
        $pkg   = $props.LocalPackage
        if (-not $pkg) { continue }   # a registration with no cached file path

        # Keep every other value stored on the key as text. I have not assumed
        # which values exist; whatever is there will show up in the report and
        # may name the product the patch belongs to.
        $other = ($props.PSObject.Properties |
            Where-Object { $_.Name -notlike 'PS*' -and $_.Name -ne 'LocalPackage' } |
            ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '

        $registered[$pkg.ToLower()] = [pscustomobject]@{
            Sid      = $sidKey.PSChildName
            PatchKey = $patchKey.PSChildName
            Other    = $other
        }
    }
}

Write-Host "Patch registration keys read: $keysRead; with a LocalPackage path: $($registered.Count)"

# SAFETY CHECK: if nothing was read, comparing against an empty list would label
# every file an orphan again (the mistake in the first report). Stop instead.
if ($registered.Count -eq 0) {
    throw "No patch registrations could be read, so no orphan result would be trustworthy. Do not move or delete anything."
}

# --------------------------------------------------- 2. compare with the disk
# Top level of the Installer folder only; -Force includes hidden/system files.
$files = Get-ChildItem -Path $installerDir -Force -File -Filter *.msp -ErrorAction SilentlyContinue

$report = foreach ($f in $files) {
    $reg = $registered[$f.FullName.ToLower()]
    [pscustomobject]@{
        File           = $f.Name
        SizeMB         = [math]::Round($f.Length / 1MB, 1)
        Date           = $f.LastWriteTime
        Status         = if ($reg) { 'Registered' } else { 'NOT REGISTERED' }
        Sid            = $reg.Sid
        RegistryValues = $reg.Other
    }
}

# --------------------------------------------------------------- 3. summaries
# Space used by registered vs unregistered patches.
Write-Host "`n--- Space by status ---"
$report | Group-Object Status | ForEach-Object {
    [pscustomobject]@{
        Status = $_.Name
        Files  = $_.Count
        SizeGB = [math]::Round(($_.Group | Measure-Object SizeMB -Sum).Sum / 1024, 2)
    }
} | Format-Table -AutoSize

# The reverse check: registrations whose cached file is missing from disk.
# These are not wasting space, but they would break uninstall/repair, so they
# are worth knowing about.
$missing = $registered.Keys | Where-Object { -not (Test-Path -LiteralPath $_) }
Write-Host "Registrations pointing at a file that does not exist: $(@($missing).Count)"

# The 15 largest files with their status, to see where the space sits.
Write-Host "`n--- 15 largest .msp files ---"
$report | Sort-Object SizeMB -Descending | Select-Object -First 15 File, SizeMB, Status, Sid |
    Format-Table -AutoSize

# Save the full per-file report (with the registry values) for review.
New-Item -ItemType Directory -Path C:\Temp -Force | Out-Null
$report | Sort-Object SizeMB -Descending |
    Export-Csv C:\Temp\installer-patch-check.csv -NoTypeInformation
Write-Host "Full report saved to C:\Temp\installer-patch-check.csv"

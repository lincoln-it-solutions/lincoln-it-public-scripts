<#
.SYNOPSIS
  Finds spare copies of Windows Installer patches (.msp) in C:\Windows\Installer
  and, only when asked, moves them to another drive.

.DESCRIPTION
  Default run = REPORT ONLY. Nothing is moved, renamed or deleted.

  What it does, in order:
    1. Reads every patch registration from the registry (each has a LocalPackage
       value holding the path of the cached .msp).
    2. Lists the .msp files on disk and marks each Registered / not registered.
    3. Hashes (SHA-256) the unregistered files that share a size with a
       registered file, to see whether they are byte-identical copies.
    4. Classifies every .msp and prints a summary, then saves a full CSV report.
    5. With -Apply: moves ONLY the unregistered files that are identical to a
       registered file, and writes a manifest so every move can be undone.

  Files in the other classes are never moved by this script.

.PARAMETER Apply
  Actually move the eligible files. Without it, nothing changes.
.PARAMETER Destination
  Folder on a DIFFERENT local drive (e.g. D:\InstallerSpares). Required with -Apply.
.PARAMETER RestoreFrom
  Path to a moved-manifest-*.csv written by an earlier -Apply run. Moves those
  files back to where they came from, then exits.
.PARAMETER ReportFolder
  Where the CSV report is written (default C:\Temp).

.EXAMPLE
  .\installer-cache-cleanup.ps1
.EXAMPLE
  .\installer-cache-cleanup.ps1 -Apply -Destination D:\InstallerSpares -WhatIf
.EXAMPLE
  .\installer-cache-cleanup.ps1 -Apply -Destination D:\InstallerSpares
.EXAMPLE
  .\installer-cache-cleanup.ps1 -RestoreFrom D:\InstallerSpares\moved-manifest-20261016-120000.csv

.NOTES
  RUN TIME: hashing reads whole files, so expect several minutes. If run from
  TRMM, set a timeout well above the 300 second default.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Apply,
    [string]$Destination,
    [string]$RestoreFrom,
    [string]$ReportFolder = 'C:\Temp'
)

$installerDir = 'C:\Windows\Installer'
$userData     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'

# ---------------------------------------------------------------- 0. context
# Show which account is running the script so the output can be interpreted.
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host "Running as: $($id.Name)"

# The UserData registry area and the Installer folder need administrator rights.
# Stop early with a clear message instead of silently reading nothing.
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Please re-run from an elevated (Administrator) PowerShell." }

# ------------------------------------------------------------ restore mode
# Undo an earlier -Apply run using its manifest, then stop. Placed first so a
# restore never triggers the slow hashing steps below.
if ($RestoreFrom) {
    if (-not (Test-Path -LiteralPath $RestoreFrom)) { throw "Manifest not found: $RestoreFrom" }
    $restored = 0; $skipped = 0
    foreach ($row in Import-Csv -LiteralPath $RestoreFrom) {
        # Only move a file back if the moved copy exists AND the original spot is
        # empty, so a restore can never overwrite anything.
        if ((Test-Path -LiteralPath $row.MovedTo) -and -not (Test-Path -LiteralPath $row.OriginalPath)) {
            if ($PSCmdlet.ShouldProcess($row.MovedTo, "Move back to $($row.OriginalPath)")) {
                Move-Item -LiteralPath $row.MovedTo -Destination $row.OriginalPath -ErrorAction Stop
                $restored++
            }
        } else {
            $skipped++
            Write-Warning "Skipped (moved copy missing or original already present): $($row.OriginalPath)"
        }
    }
    Write-Host "Restored: $restored   Skipped: $skipped"
    return
}

# --------------------------------------------- function: read registrations
# Windows Installer records each registered patch under
#   UserData\<SID>\Patches\<PatchKey>   (value LocalPackage = cached .msp path)
# Returns a hashtable: lower-cased .msp path -> details of its registration.
# It is a function so the same read can be repeated just before any move.
function Get-RegisteredPatches {
    $map  = @{}
    $keys = 0
    foreach ($sidKey in Get-ChildItem -Path $userData -ErrorAction SilentlyContinue) {
        $patchRoot = Join-Path $sidKey.PSPath 'Patches'
        foreach ($patchKey in Get-ChildItem -Path $patchRoot -ErrorAction SilentlyContinue) {
            $keys++
            $props = Get-ItemProperty -Path $patchKey.PSPath -ErrorAction SilentlyContinue
            $pkg   = $props.LocalPackage
            if (-not $pkg) { continue }
            # Keep every other value on the key as text. Which values exist is
            # not assumed; whatever is stored may name the owning product.
            $details = ($props.PSObject.Properties |
                Where-Object { $_.Name -notlike 'PS*' -and $_.Name -ne 'LocalPackage' } |
                ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
            $map[$pkg.ToLower()] = [pscustomobject]@{
                Sid      = $sidKey.PSChildName
                PatchKey = $patchKey.PSChildName
                Details  = $details
            }
        }
    }
    Write-Host "Patch registration keys read: $keys; with a LocalPackage path: $($map.Count)"
    return $map
}

# ------------------------------------------------- 1. read registrations
$registered = Get-RegisteredPatches

# SAFETY CHECK: with no registrations every file would look unregistered (the
# mistake in the first report). Stop instead of printing misleading output.
if ($registered.Count -eq 0) {
    throw "No patch registrations could be read, so no result would be trustworthy. Nothing was changed."
}

# --------------------------------------------- 2. list files, mark status
# One object per .msp on disk. Hash, Class and Twin are filled in below.
$items = foreach ($f in Get-ChildItem -Path $installerDir -Force -File -Filter *.msp -ErrorAction SilentlyContinue) {
    $reg = $registered[$f.FullName.ToLower()]
    [pscustomobject]@{
        File       = $f.Name
        Path       = $f.FullName
        Length     = $f.Length
        Date       = $f.LastWriteTime
        Registered = [bool]$reg
        Sid        = $reg.Sid
        Details    = $reg.Details
        Hash       = $null
        Class      = $null
        TwinFile   = $null
        TwinPath   = $null
    }
}

# Registrations whose cached file is missing from disk. They waste no space but
# would break uninstall/repair, so they are worth knowing about.
$missing = @($registered.Keys | Where-Object { -not (Test-Path -LiteralPath $_) })
Write-Host "Registrations pointing at a file that does not exist: $($missing.Count)"

# ------------------------------------------------ 3. hash only what can match
# Identical files must be the same size, so group by size first and hash only
# groups holding BOTH a registered and an unregistered file. This avoids reading
# every file in full.
foreach ($group in ($items | Group-Object Length)) {
    $reg   = @($group.Group | Where-Object { $_.Registered })
    $unreg = @($group.Group | Where-Object { -not $_.Registered })
    if ($reg.Count -gt 0 -and $unreg.Count -gt 0) {
        foreach ($i in $group.Group) {
            Write-Host "Hashing $($i.File) ($([math]::Round($i.Length / 1MB, 1)) MB)"
            $i.Hash = (Get-FileHash -LiteralPath $i.Path -Algorithm SHA256).Hash
        }
    }
}

# Lookup: hash -> a registered file with that content.
$registeredByHash = @{}
foreach ($i in $items | Where-Object { $_.Registered -and $_.Hash }) {
    $registeredByHash[$i.Hash] = $i
}

# ----------------------------------------------------------- 4. classify
foreach ($i in $items) {
    if ($i.Registered) {
        $i.Class = 'Registered (in use)'
        continue
    }
    $twin = if ($i.Hash) { $registeredByHash[$i.Hash] } else { $null }
    if ($twin) {
        $i.Class    = 'Identical to a registered file'
        $i.TwinFile = $twin.File
        $i.TwinPath = $twin.Path
    }
    elseif ($i.Hash) { $i.Class = 'Same size as a registered file, different content' }
    else             { $i.Class = 'No registered file of the same size' }
}

# --------------------------------------------------------------- 5. report
Write-Host "`n--- All .msp files by class ---"
$items | Group-Object Class | ForEach-Object {
    [pscustomobject]@{
        Class  = $_.Name
        Files  = $_.Count
        SizeGB = [math]::Round(($_.Group | Measure-Object Length -Sum).Sum / 1GB, 2)
    }
} | Sort-Object SizeGB -Descending | Format-Table -AutoSize

# Registered patches per SID (shows whether anything other than the machine
# context holds registrations).
Write-Host "--- Registered patches per SID ---"
$items | Where-Object Registered | Group-Object Sid | ForEach-Object {
    [pscustomobject]@{
        Sid    = $_.Name
        Files  = $_.Count
        SizeGB = [math]::Round(($_.Group | Measure-Object Length -Sum).Sum / 1GB, 2)
    }
} | Format-Table -AutoSize

# The 10 largest registered patches with whatever the registry stores about
# them, which may identify the product that owns the space.
Write-Host "--- 10 largest registered patches (registry values shown, truncated) ---"
$items | Where-Object Registered | Sort-Object Length -Descending | Select-Object -First 10 `
    File,
    @{ n = 'SizeMB'; e = { [math]::Round($_.Length / 1MB, 1) } },
    @{ n = 'RegistryValues'; e = { if ($_.Details.Length -gt 110) { $_.Details.Substring(0, 110) + '...' } else { $_.Details } } } |
    Format-Table -Wrap -AutoSize

# Save the full per-file report. -WhatIf:$false so a dry run still writes it.
New-Item -ItemType Directory -Path $ReportFolder -Force -WhatIf:$false | Out-Null
$reportPath = Join-Path $ReportFolder 'installer-cache-report.csv'
$items | Sort-Object Length -Descending |
    Select-Object File, @{ n = 'SizeMB'; e = { [math]::Round($_.Length / 1MB, 1) } },
        Date, Class, TwinFile, Sid, Details, Hash |
    Export-Csv -Path $reportPath -NoTypeInformation -WhatIf:$false
Write-Host "Full report saved to $reportPath"

# ------------------------------------------------------- 6. optional move
# Only files that are unregistered AND byte-identical to a registered file are
# eligible. Everything else stays where it is.
$movable   = @($items | Where-Object { $_.Class -eq 'Identical to a registered file' })
$needBytes = ($movable | Measure-Object Length -Sum).Sum
Write-Host ("`nEligible to move: {0} files, {1} GB (unregistered and identical to a registered file)" -f
    $movable.Count, [math]::Round($needBytes / 1GB, 2))

if (-not $Apply) {
    Write-Host "Report only: nothing was moved. To move them, re-run with -Apply -Destination <folder on another local drive>."
    return
}

# --- pre-flight checks before touching anything
if (-not $Destination) { throw "-Apply needs -Destination (a folder on another local drive, e.g. D:\InstallerSpares)." }
if ($Destination -notmatch '^[A-Za-z]:\\') { throw "Destination must be a local drive path such as D:\InstallerSpares." }
$destRoot = [IO.Path]::GetPathRoot($Destination)
if ($destRoot -ieq [IO.Path]::GetPathRoot($installerDir)) {
    throw "Destination is on the same drive as the Installer folder, which would free no space. Choose another drive."
}
$destLetter = $destRoot.Substring(0, 1)
$destDrive  = Get-PSDrive -Name $destLetter -ErrorAction SilentlyContinue
if (-not $destDrive) { throw "Drive $destRoot was not found." }
if ($destDrive.Free -lt ($needBytes + 2GB)) {
    throw ("Not enough free space on {0}: need about {1} GB plus 2 GB spare, have {2} GB." -f
        $destRoot, [math]::Round($needBytes / 1GB, 2), [math]::Round($destDrive.Free / 1GB, 2))
}
if ($movable.Count -eq 0) { Write-Host "Nothing eligible to move."; return }

New-Item -ItemType Directory -Path $Destination -Force | Out-Null
$manifest = Join-Path $Destination ("moved-manifest-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$cFreeBefore = (Get-PSDrive -Name C).Free

# Re-read the registry immediately before moving: minutes have passed since the
# first read, and an install or update could have changed things.
$registeredNow = Get-RegisteredPatches
$moved = 0; $movedBytes = 0; $skipped = 0; $failed = 0

foreach ($i in $movable) {
    # Skip if the file has become registered, or its registered twin has gone.
    if ($registeredNow.ContainsKey($i.Path.ToLower())) { Write-Warning "Now registered, skipped: $($i.File)"; $skipped++; continue }
    if (-not (Test-Path -LiteralPath $i.TwinPath) -or -not $registeredNow.ContainsKey($i.TwinPath.ToLower())) {
        Write-Warning "Registered twin missing, skipped: $($i.File)"; $skipped++; continue
    }
    $target = Join-Path $Destination $i.File
    if (Test-Path -LiteralPath $target) { Write-Warning "Target already exists, skipped: $target"; $skipped++; continue }

    if ($PSCmdlet.ShouldProcess($i.Path, "Move to $target")) {
        try {
            Move-Item -LiteralPath $i.Path -Destination $target -Force -ErrorAction Stop
            # Append to the manifest straight away so a partial run is still undoable.
            [pscustomobject]@{
                OriginalPath = $i.Path
                MovedTo      = $target
                SizeBytes    = $i.Length
                Hash         = $i.Hash
                TwinFile     = $i.TwinFile
                MovedAt      = (Get-Date).ToString('s')
            } | Export-Csv -Path $manifest -NoTypeInformation -Append
            $moved++; $movedBytes += $i.Length
        } catch {
            $failed++
            Write-Warning "Could not move $($i.File): $($_.Exception.Message)"
        }
    }
}

$cFreeAfter = (Get-PSDrive -Name C).Free
Write-Host ("`nMoved: {0} files ({1} GB)   Skipped: {2}   Failed: {3}" -f
    $moved, [math]::Round($movedBytes / 1GB, 2), $skipped, $failed)
Write-Host ("Free space on C: {0} GB -> {1} GB" -f
    [math]::Round($cFreeBefore / 1GB, 2), [math]::Round($cFreeAfter / 1GB, 2))
if ($moved -gt 0) {
    Write-Host "Manifest: $manifest"
    Write-Host "To undo: .\installer-cache-cleanup.ps1 -RestoreFrom `"$manifest`""
}

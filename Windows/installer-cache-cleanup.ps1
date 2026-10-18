<#
.SYNOPSIS
  Finds spare copies of Windows Installer patches (.msp) in C:\Windows\Installer
  and, only when asked, deletes them or moves them to another drive.

.DESCRIPTION
  Default run = REPORT ONLY. Nothing is moved, renamed or deleted.

  What it does, in order:
    1. Reads every patch registration from the registry (each has a LocalPackage
       value holding the path of the cached .msp).
    2. Lists the .msp files on disk and marks each Registered / not registered.
    3. Scans the Installer-related registry areas for ANY value that names an
       .msp file, so a file referenced somewhere other than LocalPackage is
       never treated as a spare.
    4. Hashes (SHA-256) the unregistered files that share a size with a
       registered file, to see whether they are byte-identical copies.
    5. Classifies every .msp, prints a summary and saves a full CSV report.
    6. With -Apply: acts ONLY on "spare copies", meaning files that are
       unregistered, not named anywhere else in the registry, and byte-identical
       to a registered file. Two ways to act:
         -Delete                 remove the spare copies (frees space on C:)
         -Destination <folder>   move them to a folder on ANOTHER local drive

  Why deleting is recoverable: the registered file that each spare duplicates is
  never touched, so the content survives. Every action is recorded in a manifest
  first, and -RestoreFrom can recreate a deleted spare by copying that identical
  registered file back (this needs free disk space again, equal to what was freed).

  Files in the other classes are never touched by this script.

.PARAMETER Apply
  Actually act on the spare copies. Without it, nothing changes.
.PARAMETER Delete
  With -Apply: delete the spare copies. Cannot be combined with -Destination.
.PARAMETER Destination
  With -Apply: move the spare copies to this folder on a DIFFERENT local drive
  (e.g. D:\InstallerSpares) instead of deleting them.
.PARAMETER RestoreFrom
  Path to a manifest written by an earlier -Apply run. Undoes that run, then exits.
.PARAMETER ReportFolder
  Where the CSV report and any delete manifest are written (default C:\Temp).

.EXAMPLE
  .\installer-cache-cleanup.ps1
.EXAMPLE
  .\installer-cache-cleanup.ps1 -Apply -Delete -WhatIf
.EXAMPLE
  .\installer-cache-cleanup.ps1 -Apply -Delete
.EXAMPLE
  .\installer-cache-cleanup.ps1 -Apply -Destination D:\InstallerSpares
.EXAMPLE
  .\installer-cache-cleanup.ps1 -RestoreFrom C:\Temp\deleted-manifest-20261016-120000.csv

.NOTES
  RUN TIME: the registry scan and the hashing both take a while (hashing reads
  whole files). Expect several minutes. If run from TRMM, set a timeout well
  above the 300 second default.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Apply,
    [switch]$Delete,
    [string]$Destination,
    [string]$RestoreFrom,
    [string]$ReportFolder = 'C:\Temp'
)

$installerDir = 'C:\Windows\Installer'
$userData     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'

# Names for the classes, defined once so the same text is used everywhere.
$classInUse     = 'Registered (in use)'
$classSpare     = 'Spare copy: identical to a registered file'
$classSpareHeld = 'Identical to a registered file, but named elsewhere in the registry (left alone)'
$classDiffer    = 'Same size as a registered file, different content (left alone)'
$classNoTwin    = 'No registered file of the same size (left alone)'

# ---------------------------------------------------------------- 0. context
# Show which account is running the script so the output can be interpreted.
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host "Running as: $($id.Name)"

# The UserData registry area and the Installer folder need administrator rights.
# Stop early with a clear message instead of silently reading nothing.
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Please re-run from an elevated (Administrator) PowerShell." }

Write-Host ("Free space on C: {0} GB" -f [math]::Round((Get-PSDrive -Name C).Free / 1GB, 2))

# ------------------------------------------------------------ restore mode
# Undo an earlier -Apply run using its manifest, then stop. Placed first so a
# restore never triggers the slow scanning and hashing steps below.
if ($RestoreFrom) {
    if (-not (Test-Path -LiteralPath $RestoreFrom)) { throw "Manifest not found: $RestoreFrom" }
    $restored = 0; $skipped = 0
    foreach ($row in Import-Csv -LiteralPath $RestoreFrom) {
        if ($row.PSObject.Properties.Name -contains 'MovedTo') {
            # Manifest from a MOVE: put the file back, but never overwrite anything.
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
        else {
            # Manifest from a DELETE: recreate the spare by copying the identical
            # registered file, then confirm the copy matches the recorded hash.
            if (-not (Test-Path -LiteralPath $row.TwinPath)) {
                $skipped++; Write-Warning "Skipped (identical registered file is missing): $($row.TwinPath)"; continue
            }
            if (Test-Path -LiteralPath $row.OriginalPath) {
                $skipped++; Write-Warning "Skipped (already present): $($row.OriginalPath)"; continue
            }
            if ($PSCmdlet.ShouldProcess($row.TwinPath, "Copy to $($row.OriginalPath)")) {
                Copy-Item -LiteralPath $row.TwinPath -Destination $row.OriginalPath -ErrorAction Stop
                $copyHash = (Get-FileHash -LiteralPath $row.OriginalPath -Algorithm SHA256).Hash
                if ($copyHash -eq $row.Hash) { $restored++ }
                else {
                    # A copy that does not match the recorded hash is not a faithful restore.
                    Remove-Item -LiteralPath $row.OriginalPath -Force
                    $skipped++; Write-Warning "Hash mismatch, copy removed: $($row.OriginalPath)"
                }
            }
        }
    }
    Write-Host "Restored: $restored   Skipped: $skipped"
    return
}

# --------------------------------------------- function: read registrations
# Windows Installer records each registered patch under
#   UserData\<SID>\Patches\<PatchKey>   (value LocalPackage = cached .msp path)
# Returns a hashtable: lower-cased .msp path -> details of its registration.
# It is a function so the same read can be repeated just before any change.
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

# ---------------------------------- function: find .msp names anywhere in registry
# Walks the Installer-related registry areas and collects every .msp file name
# that appears in ANY value (not just LocalPackage). A spare copy must not be
# named anywhere here, otherwise something may still refer to it.
# Limits: only text values are read (not binary data), and only user hives that
# are currently loaded can be searched.
function Get-RegistryMspNames {
    $names = New-Object 'System.Collections.Generic.HashSet[string]'
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer',
        'HKLM:\SOFTWARE\Classes\Installer',
        'HKLM:\SOFTWARE\WOW6432Node\Classes\Installer'
    )
    # Per-user patch registrations live in each loaded user hive. The Registry::
    # prefix reaches HKEY_USERS without creating a drive.
    foreach ($h in Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) {
        $roots += "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Installer"
        $roots += "Registry::HKEY_USERS\$($h.PSChildName)_Classes\Installer"
    }
    # Matches a file name ending in .msp, with or without a leading path.
    $rx = [regex]'(?i)[^\\/:*?"<>|\s;]+\.msp\b'
    foreach ($root in $roots) {
        if (-not (Test-Path -Path $root)) { continue }
        $keys = @(Get-Item -Path $root) + @(Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue)
        foreach ($k in $keys) {
            foreach ($valueName in $k.GetValueNames()) {
                $v = $null
                try { $v = $k.GetValue($valueName) } catch { continue }
                $texts = if ($v -is [string[]]) { $v } elseif ($v -is [string]) { @($v) } else { @() }
                foreach ($t in $texts) {
                    foreach ($m in $rx.Matches($t)) { [void]$names.Add($m.Value.ToLower()) }
                }
            }
        }
    }
    # The leading comma stops PowerShell unrolling the set into a plain array.
    return ,$names
}

# ------------------------------ function: last check before acting on a spare
# Re-verifies a spare against a FRESH registry read, because minutes have passed
# since the first read and an install or update could have changed things.
function Test-SpareStillSafe {
    param($Item, $Now)
    if ($Now.ContainsKey($Item.Path.ToLower())) { Write-Warning "Now registered, skipped: $($Item.File)"; return $false }
    if (-not (Test-Path -LiteralPath $Item.Path)) { Write-Warning "Already gone, skipped: $($Item.File)"; return $false }
    if (-not (Test-Path -LiteralPath $Item.TwinPath) -or -not $Now.ContainsKey($Item.TwinPath.ToLower())) {
        Write-Warning "Registered twin missing, skipped: $($Item.File)"; return $false
    }
    return $true
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

# -------------------------------------- 3. scan the registry for .msp names
Write-Host "Scanning the Installer registry areas for .msp names (this takes a while)..."
$regNames = Get-RegistryMspNames
Write-Host "Distinct .msp file names found in registry values: $($regNames.Count)"

# SAFETY CHECK: every registered patch's file name must appear in this scan. If
# fewer names turned up than registrations, the scan was incomplete, so stop.
if ($regNames.Count -lt $registered.Count) {
    throw "The registry scan found fewer .msp names ($($regNames.Count)) than registrations ($($registered.Count)); it looks incomplete. Nothing was changed."
}

# ------------------------------------------------ 4. hash only what can match
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

# ----------------------------------------------------------- 5. classify
foreach ($i in $items) {
    if ($i.Registered) { $i.Class = $classInUse; continue }
    $twin = if ($i.Hash) { $registeredByHash[$i.Hash] } else { $null }
    if ($twin) {
        $i.TwinFile = $twin.File
        $i.TwinPath = $twin.Path
        # Identical to a registered file. It is only a spare if nothing else in
        # the registry names it.
        if ($regNames.Contains($i.File.ToLower())) { $i.Class = $classSpareHeld }
        else                                       { $i.Class = $classSpare }
    }
    elseif ($i.Hash) { $i.Class = $classDiffer }
    else             { $i.Class = $classNoTwin }
}

# --------------------------------------------------------------- 6. report
Write-Host "`n--- All .msp files by class ---"
$items | Group-Object Class | ForEach-Object {
    [pscustomobject]@{
        Class  = $_.Name
        Files  = $_.Count
        SizeGB = [math]::Round(($_.Group | Measure-Object Length -Sum).Sum / 1GB, 2)
    }
} | Sort-Object SizeGB -Descending | Format-Table -AutoSize -Wrap

# Save the full per-file report. -WhatIf:$false so a dry run still writes it.
New-Item -ItemType Directory -Path $ReportFolder -Force -WhatIf:$false | Out-Null
$reportPath = Join-Path $ReportFolder 'installer-cache-report.csv'
$items | Sort-Object Length -Descending |
    Select-Object File, @{ n = 'SizeMB'; e = { [math]::Round($_.Length / 1MB, 1) } },
        Date, Class, TwinFile, Sid, Details, Hash |
    Export-Csv -Path $reportPath -NoTypeInformation -WhatIf:$false
Write-Host "Full report saved to $reportPath"

# ------------------------------------------------------ 7. optional action
# Only spare copies are eligible. Everything else stays where it is.
$spares    = @($items | Where-Object { $_.Class -eq $classSpare })
$needBytes = ($spares | Measure-Object Length -Sum).Sum
Write-Host ("`nSpare copies eligible: {0} files, {1} GB" -f $spares.Count, [math]::Round($needBytes / 1GB, 2))

if (-not $Apply) {
    Write-Host "Report only: nothing was changed."
    Write-Host "To act on the spare copies, re-run with -Apply and EITHER -Delete OR -Destination <folder on another local drive>."
    Write-Host "Add -WhatIf first to preview exactly what would happen."
    return
}
if ($Delete -and $Destination) { throw "Use either -Delete or -Destination, not both." }
if (-not $Delete -and -not $Destination) { throw "-Apply needs -Delete or -Destination <folder on another local drive>." }
if ($spares.Count -eq 0) { Write-Host "Nothing eligible."; return }

$cFreeBefore = (Get-PSDrive -Name C).Free

# ------------------------------------------------------------- 7a. DELETE
if ($Delete) {
    # The manifest records which identical registered file each spare duplicates,
    # so -RestoreFrom can recreate any spare later.
    $manifest = Join-Path $ReportFolder ("deleted-manifest-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $registeredNow = Get-RegisteredPatches
    $deleted = 0; $deletedBytes = 0; $skipped = 0; $failed = 0

    foreach ($i in $spares) {
        if (-not (Test-SpareStillSafe -Item $i -Now $registeredNow)) { $skipped++; continue }
        if ($PSCmdlet.ShouldProcess($i.Path, "Delete (identical copy of $($i.TwinFile))")) {
            try {
                # Write the manifest row FIRST, then delete, so a spare can never be
                # deleted without a record of it.
                [pscustomobject]@{
                    OriginalPath = $i.Path
                    TwinPath     = $i.TwinPath
                    SizeBytes    = $i.Length
                    Hash         = $i.Hash
                    DeletedAt    = (Get-Date).ToString('s')
                } | Export-Csv -Path $manifest -NoTypeInformation -Append -WhatIf:$false
                Remove-Item -LiteralPath $i.Path -Force -ErrorAction Stop
                $deleted++; $deletedBytes += $i.Length
            } catch {
                $failed++
                Write-Warning "Could not delete $($i.File): $($_.Exception.Message)"
            }
        }
    }

    Write-Host ("`nDeleted: {0} files ({1} GB)   Skipped: {2}   Failed: {3}" -f
        $deleted, [math]::Round($deletedBytes / 1GB, 2), $skipped, $failed)
    Write-Host ("Free space on C: {0} GB -> {1} GB" -f
        [math]::Round($cFreeBefore / 1GB, 2), [math]::Round((Get-PSDrive -Name C).Free / 1GB, 2))
    if ($deleted -gt 0) {
        Write-Host "Undo manifest: $manifest"
        Write-Host "To recreate the deleted spares: .\installer-cache-cleanup.ps1 -RestoreFrom `"$manifest`""
    }
    return
}

# --------------------------------------------------------------- 7b. MOVE
# Pre-flight checks before touching anything.
if ($Destination -notmatch '^[A-Za-z]:\\') { throw "Destination must be a local drive path such as D:\InstallerSpares." }
$destRoot = [IO.Path]::GetPathRoot($Destination)
if ($destRoot -ieq [IO.Path]::GetPathRoot($installerDir)) {
    throw "Destination is on the same drive as the Installer folder, which would free no space. Choose another drive, or use -Delete."
}
$destLetter = $destRoot.Substring(0, 1)
$destDrive  = Get-PSDrive -Name $destLetter -ErrorAction SilentlyContinue
if (-not $destDrive) { throw "Drive $destRoot was not found." }
if ($destDrive.Free -lt ($needBytes + 2GB)) {
    throw ("Not enough free space on {0}: need about {1} GB plus 2 GB spare, have {2} GB." -f
        $destRoot, [math]::Round($needBytes / 1GB, 2), [math]::Round($destDrive.Free / 1GB, 2))
}

New-Item -ItemType Directory -Path $Destination -Force | Out-Null
$manifest = Join-Path $Destination ("moved-manifest-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$registeredNow = Get-RegisteredPatches
$moved = 0; $movedBytes = 0; $skipped = 0; $failed = 0

foreach ($i in $spares) {
    if (-not (Test-SpareStillSafe -Item $i -Now $registeredNow)) { $skipped++; continue }
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
            } | Export-Csv -Path $manifest -NoTypeInformation -Append -WhatIf:$false
            $moved++; $movedBytes += $i.Length
        } catch {
            $failed++
            Write-Warning "Could not move $($i.File): $($_.Exception.Message)"
        }
    }
}

Write-Host ("`nMoved: {0} files ({1} GB)   Skipped: {2}   Failed: {3}" -f
    $moved, [math]::Round($movedBytes / 1GB, 2), $skipped, $failed)
Write-Host ("Free space on C: {0} GB -> {1} GB" -f
    [math]::Round($cFreeBefore / 1GB, 2), [math]::Round((Get-PSDrive -Name C).Free / 1GB, 2))
if ($moved -gt 0) {
    Write-Host "Manifest: $manifest"
    Write-Host "To undo: .\installer-cache-cleanup.ps1 -RestoreFrom `"$manifest`""
}

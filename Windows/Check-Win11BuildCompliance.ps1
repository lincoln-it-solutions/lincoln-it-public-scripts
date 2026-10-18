<#
.SYNOPSIS
    TRMM script check (single script): fails if this Windows 11 workstation is out of date.

.DESCRIPTION
    Everything happens in this one script, on the device, with no keystore or helper job:
      1. Read this device's build (CurrentBuild + UBR from the registry).
      2. Fetch Microsoft's official Windows 11 release information page and parse it.
      3. Work out, in memory, which feature versions are acceptable right now
         (newest + FeatureVersionsAllowed-1 prior) and the oldest acceptable build of each
         (no more than MaxBuildsBehind monthly releases behind the latest).
      4. Compare this device and exit.

    Exit 0 = compliant (or out of scope). Exit 1 = non-compliant, or no usable reference data.
    A non-zero exit fails the TRMM check, which raises the alert (and, via your existing
    alert-to-ticket bridge, a ticket).

    HOW IT AVOIDS A TICKET STORM IF MICROSOFT CHANGES THE PAGE
    Because every device parses the page itself, a layout change would break every device
    at once. To limit that, each device keeps a small cached copy of the last GOOD result and
    keeps using it for up to MaxCacheDays if a fresh fetch/parse fails. The check only starts
    failing on data problems once the cache is older than that. It also refuses to accept new
    data in which a version's newest build has gone DOWN compared with the cache.

    Windows PowerShell 5.1 syntax only (the Windows default); no PowerShell 7 features.
#>
[CmdletBinding()]
param(
    # Microsoft's release information page (HTML; no official JSON feed was found).
    [string]$PageUrl = 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information',

    # Versions never treated as current/prior. 26H1 is excluded because Microsoft's page says
    # it is scoped to new devices and is not an in-place update from 24H2/25H2.
    [string[]]$ExcludedVersions = @('26H1'),

    # How many feature versions are acceptable: 2 = current + 1 prior.
    [int]$FeatureVersionsAllowed = 2,

    # Maximum number of monthly releases a device may be behind the latest of its version.
    [int]$MaxBuildsBehind = 4,

    # Which 'Update type' values count as a "build". B = the monthly Patch Tuesday release,
    # OOB = out-of-band (usually bug fixes, so counted). D = optional preview, not counted.
    [string[]]$CountUpdateTypes = @('B', 'OOB'),

    # Only re-fetch the page if the cached result is older than this many hours.
    # Keeps 1 request per device per half day instead of one per check run.
    [int]$RefreshHours = 12,

    # How long a cached result may be used when a fresh fetch/parse fails.
    [int]$MaxCacheDays = 14,

    # Where the cached result lives on the device. SYSTEM (what TRMM runs as) can write here.
    [string]$CacheDir,

    # --- Testing only ---
    # Read the page from a local HTML file instead of the web.
    [string]$HtmlFile,
    # Pretend the device is on this build, e.g. 26200.8000. Skips registry/workstation checks.
    [string]$TestBuild,
    # Debugging: print what was parsed from the page (per feature version: build number, counted
    # releases and the newest revisions) before judging the device. Use this when a layout change is suspected.
    [switch]$ShowParsed
)

$ErrorActionPreference = 'Stop'

# Older .NET defaults can refuse modern HTTPS; force TLS 1.2.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $CacheDir) {
    $base = $env:ProgramData
    if (-not $base) { $base = [IO.Path]::GetTempPath() }
    $CacheDir = Join-Path $base 'BuildCompliance'
}
$cacheFile = Join-Path $CacheDir 'win11-reference.json'

# ---------------------------------------------------------------------------
# 1. This device's build
# ---------------------------------------------------------------------------
if ($TestBuild) {
    $devPrefix = [int]($TestBuild.Split('.')[0])
    $devUbr    = [int]($TestBuild.Split('.')[1])
} else {
    # Workstations only (ProductType 1). Windows Server 2025 shares build 26100 with
    # Windows 11 24H2, so without this a server could be flagged as an out-of-date client.
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    if ($os.ProductType -ne 1) {
        Write-Output "OUT OF SCOPE: not a workstation OS ($($os.Caption))."
        exit 0
    }
    # CurrentBuild = major build (26200); UBR = update build revision (9445).
    # Together: the full build number Microsoft publishes (26200.9445).
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $devPrefix = [int]$cv.CurrentBuild
    $devUbr    = [int]$cv.UBR
}

# Windows 11 starts at build 22000; lower (Windows 10) is out of scope.
if ($devPrefix -lt 22000) {
    Write-Output "OUT OF SCOPE: build $devPrefix.$devUbr is not Windows 11."
    exit 0
}
$devBuild = "$devPrefix.$devUbr"

# ---------------------------------------------------------------------------
# 2. Parsing helpers
# ---------------------------------------------------------------------------
function ConvertTo-TextLines {
    # Turns the page HTML into plain lines. Table cells are separated by '|' and each table
    # row ends up on its own line. Parsing text (not specific tags or CSS classes) is what
    # makes this resilient to cosmetic changes to the page.
    param([string]$Html)
    $h = $Html -replace '(?is)<(script|style)\b.*?</\1>', ''
    # Collapse ALL raw whitespace (including the line breaks Microsoft's pretty-printed HTML puts
    # between every table cell) into single spaces BEFORE adding our own line breaks. Otherwise
    # each cell lands on its own line and no table row can be reassembled. From here on, a line
    # break exists only where a block-level tag puts one.
    $h = $h -replace '\s+', ' '
    $h = $h -replace '(?i)</t[dh]\s*>', '|'
    # Break the line at BOTH the opening and closing tag of every block-level element.
    # Microsoft wraps each version as <details><summary><strong>Version ...</strong></summary><table>
    # with no closing tag between the label and the table's header row. Breaking only at closing
    # tags left the label and the header on one line, so the header (and so the whole table) was
    # never recognised and zero versions were found. details/summary/thead/tbody are included for that reason.
    $h = $h -replace '(?i)</?(tr|p|div|h[1-6]|li|table|thead|tbody|caption|section|details|summary)\b[^>]*>|<br\s*/?>', "`n"
    $h = $h -replace '<[^>]+>', ''
    $h = [System.Net.WebUtility]::HtmlDecode($h)
    foreach ($line in ($h -split "`r?`n")) {
        $clean = ($line -replace '\s+', ' ').Trim()
        if ($clean) { $clean }
    }
}

function Get-VersionTable {
    # Returns a hashtable: version name -> @{ Prefix = <int>; Releases = @( @{Type=..;Rev=..} ) }
    param([string]$Html)

    $versions = @{}
    $current  = $null    # the most recent "Version 25H2 (OS build 26200)" label
    $inTable  = $false   # true while inside a release-history table
    $iType = -1
    $iBuild = -1

    foreach ($line in (ConvertTo-TextLines -Html $Html)) {

        # Version label that precedes each release-history table.
        $m = [regex]::Match($line, '^Version (\d{2}H\d) \(OS build (\d{5})\)')
        if ($m.Success) {
            $current = @{ Name = $m.Groups[1].Value; Prefix = [int]$m.Groups[2].Value }
            $inTable = $false
            continue
        }

        # A line without '|' is ordinary text, so any table we were in has ended.
        if ($line.IndexOf('|') -lt 0) { $inTable = $false; continue }

        $cells = @($line.Split('|') | ForEach-Object { $_.Trim() })
        # The trailing '|' after the last cell leaves one empty element at the end; drop it.
        # (A bare '1..0' style range misbehaves in PowerShell, so a one-element row is handled apart.)
        if ($cells.Count -eq 1 -and $cells[0] -eq '') {
            $cells = @()
        } elseif ($cells.Count -gt 1 -and $cells[$cells.Count - 1] -eq '') {
            $cells = @($cells[0..($cells.Count - 2)])
        }

        # Header of a release-history table: first column 'Servicing option' AND it has
        # 'Update type' and 'Build'. This excludes the "current versions" summary table and
        # the Hotpatch calendar tables, which use the same version labels but other columns.
        if ($cells.Count -gt 0 -and $cells[0] -eq 'Servicing option') {
            $iType  = [array]::IndexOf($cells, 'Update type')
            $iBuild = [array]::IndexOf($cells, 'Build')
            $inTable = ($iType -ge 0 -and $iBuild -ge 0 -and $null -ne $current)
            continue
        }
        # Header of any other table (Version..., Month...): not release history.
        if ($cells.Count -gt 0 -and ($cells[0] -eq 'Version' -or $cells[0] -eq 'Month')) {
            $inTable = $false
            continue
        }

        if (-not $inTable) { continue }
        if ($cells.Count -le [Math]::Max($iType, $iBuild)) { continue }

        $b = [regex]::Match($cells[$iBuild], '^(\d{5})\.(\d+)$')
        if (-not $b.Success) { continue }

        # Sanity check: a build's first part must equal the section's OS build. If not, the
        # page is not laid out as assumed, so stop rather than guess.
        if ([int]$b.Groups[1].Value -ne $current.Prefix) {
            throw "row build $($cells[$iBuild]) does not match section $($current.Name) (OS build $($current.Prefix)); page layout may have changed"
        }

        # "2026-10 B" -> type 'B'. An empty type is the version's initial release.
        $t = [regex]::Match($cells[$iType], '^\d{4}-\d{2} ([A-Z]+)$')
        $utype = ''
        if ($t.Success) { $utype = $t.Groups[1].Value }

        if (-not $versions.ContainsKey($current.Name)) {
            $versions[$current.Name] = @{ Prefix = $current.Prefix; Releases = New-Object System.Collections.ArrayList }
        }
        [void]$versions[$current.Name].Releases.Add(@{ Type = $utype; Rev = [int]$b.Groups[2].Value })
    }
    return $versions
}

function Get-Reference {
    # Works out the acceptable feature versions and, for each, the oldest acceptable revision.
    param([hashtable]$Versions)

    if ($Versions.Count -lt 3) {
        throw "only $($Versions.Count) feature versions parsed from the page (expected several); layout may have changed"
    }

    # Names like 25H2 sort by year then half: YY*10 + half.
    $candidates = @()
    foreach ($name in $Versions.Keys) {
        $m = [regex]::Match($name, '^(\d{2})H(\d)$')
        if (-not $m.Success) { continue }
        if ($ExcludedVersions -contains $name) { continue }
        # Only count a version once it has at least one counted release to compare against.
        $counted = @($Versions[$name].Releases | Where-Object { $CountUpdateTypes -contains $_.Type })
        if ($counted.Count -lt 1) { continue }
        $candidates += [pscustomobject]@{ Name = $name; Key = ([int]$m.Groups[1].Value * 10 + [int]$m.Groups[2].Value) }
    }
    $chosen = @($candidates | Sort-Object Key -Descending | Select-Object -First $FeatureVersionsAllowed)
    if ($chosen.Count -lt $FeatureVersionsAllowed) {
        throw "expected $FeatureVersionsAllowed usable feature versions but found $($chosen.Count)"
    }

    $entries = @()
    foreach ($c in $chosen) {
        $v = $Versions[$c.Name]
        $revs = @($v.Releases | Where-Object { $CountUpdateTypes -contains $_.Type } |
                  ForEach-Object { $_.Rev } | Sort-Object -Unique -Descending)
        # MinUbr = the oldest revision still within MaxBuildsBehind counted releases of the latest.
        # 0 when fewer than MaxBuildsBehind+1 counted releases exist (brand-new version), so a
        # device on the initial release is never wrongly failed.
        $minUbr = 0
        if ($revs.Count -gt $MaxBuildsBehind) { $minUbr = $revs[$MaxBuildsBehind] }
        $entries += [pscustomobject]@{ Name = $c.Name; Prefix = $v.Prefix; MinUbr = $minUbr; Latest = $revs[0] }
    }
    return $entries
}

function Read-Cache {
    # Returns @{ Fetched = [datetime]; Entries = @(...) } or $null if missing/unreadable.
    if (-not (Test-Path $cacheFile)) { return $null }
    try {
        $j = Get-Content -Raw -Path $cacheFile | ConvertFrom-Json
        # Windows PowerShell 5.1 returns the timestamp as a string; PowerShell 7 returns a
        # [datetime] already. Handle both so the script works whichever TRMM launches.
        $fetched = $j.Fetched
        if ($fetched -isnot [datetime]) {
            $fetched = [datetime]::Parse([string]$fetched, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        }
        return @{ Fetched = $fetched; Entries = @($j.Entries) }
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# 3. Get the reference: fresh cache, else live fetch, else older cache, else fail
# ---------------------------------------------------------------------------
$cache = Read-Cache
$entries = $null
$source = ''

if ($cache -and -not $HtmlFile -and ((Get-Date).ToUniversalTime() - $cache.Fetched.ToUniversalTime()).TotalHours -lt $RefreshHours) {
    $entries = $cache.Entries
    $source = 'cache (fresh)'
} else {
    try {
        if ($HtmlFile) {
            $html = Get-Content -Raw -Path $HtmlFile
        } else {
            $resp = Invoke-WebRequest -Uri $PageUrl -UseBasicParsing -TimeoutSec 60 -Headers @{ 'User-Agent' = 'LincolnIT-BuildCheck/1.0' }
            $html = $resp.Content
        }
        $parsed = Get-VersionTable -Html $html

        # If almost nothing was recognised, say what the page looked like so the alert is actionable
        # (a bare "layout may have changed" gives whoever picks up the ticket nothing to start from).
        if ($parsed.Count -lt 3) {
            $tables = [regex]::Matches($html, '(?i)<table').Count
            $builds = [regex]::Matches($html, 'OS build').Count
            throw "only $($parsed.Count) feature versions parsed from the page (page is $($html.Length) chars, $tables tables, 'OS build' appears $builds times); layout may have changed"
        }

        if ($ShowParsed) {
            Write-Output 'PARSED (feature version: build number, counted releases, newest counted revisions):'
            foreach ($name in ($parsed.Keys | Sort-Object)) {
                $revs = @($parsed[$name].Releases | Where-Object { $CountUpdateTypes -contains $_.Type } |
                          ForEach-Object { $_.Rev } | Sort-Object -Unique -Descending)
                $all  = $parsed[$name].Releases.Count
                Write-Output ("  {0}: build {1}, {2} counted of {3} rows, newest: {4}" -f $name, $parsed[$name].Prefix, $revs.Count, $all, (($revs | Select-Object -First 6) -join ', '))
            }
        }

        $new = Get-Reference -Versions $parsed

        # No-regression check: a version's newest build can only go up. If it went DOWN versus
        # the cached good data, the parse is wrong, so reject it (falls through to the cache).
        if ($cache) {
            foreach ($n in $new) {
                $old = $cache.Entries | Where-Object { $_.Name -eq $n.Name } | Select-Object -First 1
                if ($old -and [int]$n.Latest -lt [int]$old.Latest) {
                    throw "$($n.Name) latest revision went down ($($old.Latest) -> $($n.Latest)); refusing suspect data"
                }
            }
        }

        $entries = $new
        $source = 'live page'
        if (-not $HtmlFile) {
            if (-not (Test-Path $CacheDir)) { New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null }
            [pscustomobject]@{ Fetched = (Get-Date).ToUniversalTime().ToString('o'); Entries = $entries } |
                ConvertTo-Json -Depth 4 | Set-Content -Path $cacheFile -Encoding UTF8
        }
    } catch {
        $liveErr = $_.Exception.Message
        if ($cache) {
            $ageDays = ((Get-Date).ToUniversalTime() - $cache.Fetched.ToUniversalTime()).TotalDays
            if ($ageDays -le $MaxCacheDays) {
                $entries = $cache.Entries
                $source = ('cache {0:N1} days old; live refresh failed: {1}' -f $ageDays, $liveErr)
            } else {
                Write-Output ("DATA ERROR: live refresh failed ({0}) and cached reference is {1:N0} days old (limit {2})." -f $liveErr, $ageDays, $MaxCacheDays)
                exit 1
            }
        } else {
            Write-Output "DATA ERROR: live refresh failed ($liveErr) and there is no cached reference."
            exit 1
        }
    }
}

$allowedNames = ($entries | ForEach-Object { $_.Name }) -join ', '

# ---------------------------------------------------------------------------
# 4. Judge this device
# ---------------------------------------------------------------------------
# Match on build number (not the DisplayVersion registry value) so it behaves the same everywhere.
$match = $entries | Where-Object { [int]$_.Prefix -eq $devPrefix } | Select-Object -First 1
if (-not $match) {
    Write-Output "NON-COMPLIANT: build $devBuild is not an allowed feature version. Allowed: $allowedNames. [data: $source]"
    exit 1
}

if ($devUbr -lt [int]$match.MinUbr) {
    Write-Output "NON-COMPLIANT: build $devBuild ($($match.Name)) is too far behind. Latest is $($match.Prefix).$($match.Latest); oldest acceptable is $($match.Prefix).$($match.MinUbr). Allowed versions: $allowedNames. [data: $source]"
    exit 1
}

Write-Output "COMPLIANT: build $devBuild ($($match.Name)) is within range. Latest is $($match.Prefix).$($match.Latest); oldest acceptable is $($match.Prefix).$($match.MinUbr). Allowed versions: $allowedNames. [data: $source]"
exit 0

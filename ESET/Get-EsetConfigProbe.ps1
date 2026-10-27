<#
.SYNOPSIS
    Read-only probe: can ermm read ESET's configuration, and what does it say about LiveGrid?
.DESCRIPTION
    Written 2026-10-26 to answer, with evidence, whether ESET settings (e.g. LiveGrid) could be
    switched on from TRMM with "ermm set configuration". It only READS:
      1. ermm get configuration  -> writes the settings XML to a temp file (the file is deleted
         at the end; the XML can contain sensitive values so it is NEVER printed in full)
      2. prints: whether the command worked, file size, root element, number of nodes, and ONLY
         the lines that mention LiveGrid / cloud (setting name + value)
      3. ermm get scan-info -> first 400 characters (to learn what a scan reports)
    Nothing on the machine is changed.
#>
$ErrorActionPreference = 'Continue'
$ermm = Join-Path $env:ProgramFiles 'ESET\ESET Security\ermm.exe'
if (-not (Test-Path $ermm)) { Write-Output "ermm.exe not found on $env:COMPUTERNAME"; exit 0 }
Write-Output "== $env:COMPUTERNAME  $(Get-Date -Format s)"

# 1. Ask ESET for its configuration as XML in a temp file. ermm's own help (seen on a client PC,
#    2026-10-26) lists only --file and --format for "get configuration" - no password option.
$tmp = Join-Path $env:TEMP 'eset_cfg_probe.xml'
if (Test-Path $tmp) { Remove-Item $tmp -Force }
$out = & $ermm get configuration --file $tmp --format xml 2>&1 | Out-String
Write-Output "-- get configuration reply: $($out.Trim())"

if (Test-Path $tmp) {
    $len = (Get-Item $tmp).Length
    Write-Output "-- file written: $len bytes"
    try {
        # Parse as XML to report structure without printing values.
        [xml]$x = Get-Content $tmp -Raw
        Write-Output "-- root element: $($x.DocumentElement.Name); total nodes: $($x.SelectNodes('//*').Count)"
    } catch { Write-Output "-- not plain XML (first bytes: $((Get-Content $tmp -Encoding Byte -TotalCount 12) -join ' '))" }
    # 2. Only LiveGrid / cloud lines (setting name and value), capped at 25 lines.
    $hits = Select-String -Path $tmp -Pattern 'livegrid|cloud|charon' -CaseSensitive:$false | Select-Object -First 25
    Write-Output "-- lines mentioning LiveGrid/cloud: $(@($hits).Count) (max 25 shown)"
    foreach ($h in $hits) { Write-Output ('   ' + $h.Line.Trim().Substring(0, [Math]::Min(200, $h.Line.Trim().Length))) }
    Remove-Item $tmp -Force
    Write-Output "-- temp file deleted: $(-not (Test-Path $tmp))"
}

# 3. Scan info (what does ESET report about scans?).
$scan = & $ermm get scan-info 2>&1 | Out-String
$scan = $scan.Trim()
Write-Output "-- get scan-info: $($scan.Substring(0, [Math]::Min(400, $scan.Length)))"

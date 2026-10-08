# =============================================================
# Event log collection test (mounted-image mode)
# Builds a fake mounted image -- a folder with Windows\System32\winevt\Logs
# holding .evtx files under the names of the channels the collector exports
# -- maps it to a free drive letter with subst, runs triage-collector.ps1 on
# it (-Categories EventLogs -Unattended -NoCompress) and checks the result:
#   run 1  every listed log present: each is copied byte for byte into
#          EventLogs\ and has a manifest row (source path, SHA256)
#   run 2  OAlerts.evtx missing: an info line, not a warning or an error;
#          a 300 MB Shell-Core log: skipped with a warning (size limit)
# It also checks, on this machine, that every channel the test lists is
# stored in winevt\Logs under the file name the collector expects ("/" in
# the channel name is "%4"); a channel that does not exist here is skipped.
# The .evtx files are empty exports of this machine's System log (wevtutil
# epl with a query that matches nothing): only their names matter here.
#
# Needs Administrator rights, like the collector (GitHub Actions Windows
# runners are elevated), unless -CollectorPath names a copy of the collector
# without its administrator check. Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-CollectEventLogs.ps1
#   ... -CollectorPath <file>   test another copy of triage-collector.ps1
# =============================================================
param(
    # Collector script to test (default: the repository's triage-collector.ps1)
    [string]$CollectorPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$collector = $CollectorPath
if (-not $collector) {
    $collector = Join-Path $repoRoot "triage-collector.ps1"
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "FAIL: run this test as Administrator (the collector requires it), or pass -CollectorPath" -ForegroundColor Red
        exit 1
    }
}
$script:failures = 0

function Write-TestResult {
    param([string]$Name, [bool]$Passed, [string]$Message = "")
    if ($Passed) {
        Write-Host "PASS: $Name" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Name -- $Message" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-CollectEventLogs.ps1::$Name -- $Message" }
}

# Run a console tool and return its exit code. Error action Continue: with
# Stop, Windows PowerShell 5.1 turns any stderr line into a terminating error.
function Invoke-NativeTool {
    param([string]$FilePath, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $null = & $FilePath @Arguments 2>&1 }
    finally { $ErrorActionPreference = $previous }
    return $LASTEXITCODE
}

# Channels the collector exports (file names in winevt\Logs, "/" as "%4"):
# the Phase 1 logs and the ones added for Phase 2
$coreLogs = @("System", "Security", "Application", "Microsoft-Windows-PowerShell%4Operational")
$newLogs = @(
    "Windows PowerShell",
    "Microsoft-Windows-WMI-Activity%4Operational",
    "Microsoft-Windows-TerminalServices-RDPClient%4Operational",
    "Microsoft-Windows-NTLM%4Operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall",
    "Microsoft-Windows-Shell-Core%4Operational",
    "OAlerts"
)

# --- The channels' file names on this machine ---
foreach ($logName in $newLogs) {
    $channel = $logName -replace '%4', '/'
    $config = @()
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $config = @(& wevtutil.exe gl $channel 2>&1) }
    finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "SKIPPED: channel '$channel' does not exist on this machine (file name not checked)" -ForegroundColor Yellow
        continue
    }
    $fileLine = "$($config | Where-Object { "$_" -match '^\s*logFileName:' } | Select-Object -First 1)"
    $file = if ($fileLine -match 'logFileName:\s*(.+)$') { Split-Path $Matches[1].Trim() -Leaf } else { "" }
    Write-TestResult -Name "channel '$channel' is stored as $logName.evtx" -Passed ($file -eq "$logName.evtx") -Message "wevtutil gl gives logFileName '$file'"
}

$testId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) "TriageEvtxTest_$testId"
$imageRoot = Join-Path $workDir "image"
$logsDir = Join-Path $imageRoot "Windows\System32\winevt\Logs"
$powershellExe = (Get-Process -Id $PID).Path
$drive = $null
Write-Host "Collector: $collector (run with $powershellExe)"

# Runs the collector on the mapped drive into $OutputDir; returns its log lines
function Invoke-TestCollection {
    param([string]$OutputDir)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $collector -TargetDrive $drive -Categories EventLogs `
            -Unattended -NoCompress -OutputPath $OutputDir 2>&1
    }
    finally { $ErrorActionPreference = $previous }
    $logPath = Join-Path $OutputDir "collection_log.txt"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $logPath)) {
        $output | ForEach-Object { Write-Host "  | $_" }
        throw "the collector exited with code $LASTEXITCODE or wrote no collection_log.txt"
    }
    return @(Get-Content -LiteralPath $logPath)
}

# Manifest rows of a collection, by RelativePath
function Get-ManifestRows {
    param([string]$OutputDir)
    $rows = @{}
    foreach ($row in (Import-Csv -LiteralPath (Join-Path $OutputDir "collection_manifest.csv"))) { $rows[$row.RelativePath] = $row }
    return $rows
}

try {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

    # An empty but valid .evtx, copied under every channel's name
    $template = Join-Path $workDir "template.evtx"
    $exit = Invoke-NativeTool "wevtutil.exe" @("epl", "System", $template, "/q:*[System[EventRecordID=0]]")
    if ($exit -ne 0 -or -not (Test-Path -LiteralPath $template)) { throw "wevtutil could not export an empty .evtx from the System log (exit code $exit)" }
    foreach ($logName in @($coreLogs + $newLogs)) {
        Copy-Item -LiteralPath $template -Destination (Join-Path $logsDir "$logName.evtx")
    }

    # A free drive letter for the fake image (another test may hold one)
    foreach ($letter in [char[]]"ZYXWVUTSRQPONMLKJIHGFE") {
        if (Test-Path -LiteralPath "${letter}:\") { continue }
        if ((Invoke-NativeTool "subst.exe" @("${letter}:", $imageRoot)) -eq 0) {
            $drive = "$letter"
            break
        }
    }
    if (-not $drive) { throw "no free drive letter for subst" }
    Write-Host "Fake image $imageRoot mapped to ${drive}:"

    # --- Run 1: every log present ---
    $out1 = Join-Path $workDir "run1"
    $log1 = Invoke-TestCollection -OutputDir $out1
    $manifest1 = Get-ManifestRows -OutputDir $out1
    $templateHash = (Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash
    foreach ($logName in @($coreLogs + $newLogs)) {
        $relPath = "EventLogs\$logName.evtx"
        $dest = Join-Path $out1 $relPath
        $row = $manifest1[$relPath]
        $problem = ""
        if (-not (Test-Path -LiteralPath $dest)) { $problem = "not collected" }
        elseif ((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -ne $templateHash) { $problem = "the copy differs from the source" }
        elseif (-not $row) { $problem = "no manifest row" }
        elseif ($row.SHA256 -ne $templateHash) { $problem = "manifest SHA256 $($row.SHA256) differs from the source" }
        elseif ($row.SourcePath -ne "${drive}:\Windows\System32\winevt\Logs\$logName.evtx") { $problem = "manifest SourcePath is '$($row.SourcePath)'" }
        elseif (-not $row.SourceModifiedUtc) { $problem = "manifest has no source file times" }
        Write-TestResult -Name "run 1: $logName.evtx collected (file copy, manifest row)" -Passed (-not $problem) -Message $problem
    }
    $problems1 = @($log1 | Where-Object { $_ -match 'WARNING: .*\.evtx|ERROR:' })
    Write-TestResult -Name "run 1: no warnings or errors about event logs" -Passed ($problems1.Count -eq 0) -Message ($problems1 -join " || ")

    # --- Run 2: OAlerts missing, Shell-Core over the size limit ---
    Remove-Item -LiteralPath (Join-Path $logsDir "OAlerts.evtx")
    $bigLog = Join-Path $logsDir "Microsoft-Windows-Shell-Core%4Operational.evtx"
    Remove-Item -LiteralPath $bigLog
    [System.IO.File]::WriteAllBytes($bigLog, [byte[]]@())
    # Sparse where possible, so the 300 MB take no disk space
    $null = Invoke-NativeTool "fsutil.exe" @("sparse", "setflag", $bigLog)
    $stream = [System.IO.File]::Open($bigLog, "Open", "ReadWrite", "None")
    try { $stream.SetLength(300MB) } finally { $stream.Dispose() }

    $out2 = Join-Path $workDir "run2"
    $log2 = Invoke-TestCollection -OutputDir $out2
    $manifest2 = Get-ManifestRows -OutputDir $out2

    $oalertsLines = @($log2 | Where-Object { $_ -match 'OAlerts\.evtx' })
    $oalertsInfo = @($oalertsLines | Where-Object { $_ -match 'Skipping OAlerts\.evtx \(not present on target\)' -and $_ -notmatch 'WARNING:|ERROR:' })
    Write-TestResult -Name "run 2: missing OAlerts.evtx is an info line, not collected" `
        -Passed ($oalertsInfo.Count -eq 1 -and $oalertsLines.Count -eq 1 -and -not (Test-Path -LiteralPath (Join-Path $out2 "EventLogs\OAlerts.evtx"))) `
        -Message "log lines: $($oalertsLines -join ' || ')"

    $bigName = "Microsoft-Windows-Shell-Core%4Operational.evtx"
    $bigLines = @($log2 | Where-Object { $_ -like "*$bigName*" })
    $bigWarning = @($bigLines | Where-Object { $_ -match 'WARNING: Skipping .*\(300 MB, over the 256 MB limit for this log\)' })
    Write-TestResult -Name "run 2: 300 MB Shell-Core log skipped with a warning (256 MB limit)" `
        -Passed ($bigWarning.Count -eq 1 -and -not (Test-Path -LiteralPath (Join-Path $out2 "EventLogs\$bigName")) -and -not $manifest2.ContainsKey("EventLogs\$bigName")) `
        -Message "log lines: $($bigLines -join ' || ')"

    $others = @($coreLogs + $newLogs | Where-Object { $_ -notin @("OAlerts", "Microsoft-Windows-Shell-Core%4Operational") })
    $missing = @($others | Where-Object { -not $manifest2.ContainsKey("EventLogs\$_.evtx") })
    Write-TestResult -Name "run 2: the other logs are still collected" -Passed ($missing.Count -eq 0) -Message "missing: $($missing -join ', ')"
}
catch {
    Write-TestResult -Name "test setup or run" -Passed $false -Message $_.Exception.Message
}
finally {
    if ($drive) { $null = Invoke-NativeTool "subst.exe" @("${drive}:", "/d") }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
if ($script:failures -gt 0) {
    Write-Host "FAILED: $($script:failures) check(s)" -ForegroundColor Red
    exit 1
}
Write-Host "All event log collection checks passed" -ForegroundColor Green
exit 0

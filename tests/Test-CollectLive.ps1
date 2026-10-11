# =============================================================
# Live collection test
# Runs triage-collector.ps1 on this computer, the way
# Run-TriageCollector.bat does for its system drive (-TargetDrive <system
# drive letter>), with -Categories Execution,USB,Persistence -Unattended
# -NoCompress, and checks what only a live run reaches -- the call sites of
# helpers that the unit tests check on their own:
#  - the provenance log lines ("Collector: version ..., triage-collector.ps1
#    SHA-256 ..." and "Collector git commit: ...") and collection_info.json's
#    CollectorVersion, CollectorScriptSha256 (the SHA-256 of the script that
#    ran) and CollectorGitCommit, which must agree with them, and
#    CollectorProcesses in the same file, which names the collector's
#    PowerShell (started by this test) first;
#  - AppCompatCache read with .NET: "AppCompatCache: N bytes read from the
#    registry." and Execution\appcompat_cache.reg in the layout of "reg
#    query" (key line, "    AppCompatCache    REG_BINARY    <HEX>") with
#    2 x N hex digits;
#  - the USBSTOR result line and USB\usb_storage_devices.txt, which is never
#    empty (devices, or a note saying why there are none);
#  - the Run key line per hive ("Run keys: N value(s) in HKLM, N value(s) in
#    N loaded user hive(s).") with the HKLM and user counts of
#    Persistence\run_keys.csv.
# The collection goes to a temporary folder, which is removed afterwards.
#
# Needs Administrator rights, like the collector (GitHub Actions Windows
# runners are elevated: there the collector also makes its shadow copy and
# temporary Defender exclusion, and removes them when it finishes). For a
# local run without them, pass -CollectorPath with a copy of the collector
# that has no admin check, kept inside the repository (e.g. under the
# git-ignored reports\ folder): the steps that need admin rights then log
# warnings, which this test does not check. Reads this computer's registry
# and files only; changes nothing on it.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-CollectLive.ps1
#   ... -CollectorPath <copy>   test another copy of triage-collector.ps1
# =============================================================
param(
    # Collector script to test (default: the repository's triage-collector.ps1)
    [string]$CollectorPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$collector = $CollectorPath
if (-not $collector) { $collector = Join-Path $repoRoot "triage-collector.ps1" }
$collector = (Resolve-Path -LiteralPath $collector).Path
$script:failures = 0

# PASS/FAIL line; failures are counted and annotated on GitHub Actions
function Write-TestResult {
    param([bool]$Succeeded, [string]$Message)
    if ($Succeeded) {
        Write-Host "PASS: $Message" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Message" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-CollectLive.ps1::$Message" }
}

# The collector refuses to run without Administrator rights (a -CollectorPath
# copy may not)
if (-not $CollectorPath) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-TestResult -Succeeded $false -Message "Administrator rights are required (the collector needs them). Run elevated, or pass -CollectorPath with a collector copy without the admin check."
        exit 1
    }
}

# Run the collector with the same PowerShell edition as this script
$powershellExe = (Get-Process -Id $PID).Path
$systemLetter = $env:SystemDrive.Substring(0, 1)
$testId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) "TriageLiveTest_$testId"
$outputPath = Join-Path $workDir "collection"

# The message part of the log lines (after "[yyyy-MM-dd HH:mm:ss] ")
function Get-LogMessages {
    param([string]$Path)
    return @([System.IO.File]::ReadAllLines($Path) | ForEach-Object { $_ -replace '^\[[^\]]+\] ', '' })
}

New-Item -ItemType Directory -Path $workDir | Out-Null
try {
    Write-Host "Running the collector ($powershellExe) on this computer: -TargetDrive $systemLetter -Categories Execution,USB,Persistence ..."
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $ErrorActionPreference = "Continue"
    # A script block, not -File: -File passes "Execution,USB,Persistence" as
    # one string, which -Categories refuses; a script block's arguments keep
    # their types. (Its exit code would be the last native tool's the
    # collector ran, so the end of the run is read from the log instead.)
    $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -Command {
        param($Script, $Letter, $Out)
        & $Script -TargetDrive $Letter -Categories Execution, USB, Persistence -Unattended -NoCompress -OutputPath $Out
    } -args $collector, $systemLetter, $outputPath 2>&1
    $ErrorActionPreference = "Stop"
    $watch.Stop()
    Write-Host "  the collector ran for $([Math]::Round($watch.Elapsed.TotalSeconds)) s"
    $logPath = Join-Path $outputPath "collection_log.txt"
    if (-not (Test-Path -LiteralPath $logPath)) {
        $output | Select-Object -Last 40 | ForEach-Object { Write-Host "  | $_" }
        throw "the collector wrote no collection_log.txt to $outputPath"
    }
    $messages = Get-LogMessages $logPath
    $info = Get-Content -Raw -LiteralPath (Join-Path $outputPath "collection_info.json") | ConvertFrom-Json
    Write-TestResult -Succeeded (@($messages | Where-Object { $_ -eq "=== Windows Forensic Triage Collection Complete ===" }).Count -eq 1) -Message "the collection ran to its end ('Collection Complete' in collection_log.txt)"
    Write-TestResult -Succeeded ($info.Mode -eq "Live") -Message "collection_info.json: a live collection of this computer (Mode $($info.Mode))"

    # --- Provenance: log lines and collection_info.json agree with the script ---
    $scriptHash = (Get-FileHash -LiteralPath $collector -Algorithm SHA256).Hash
    $versionLines = @($messages | Where-Object { $_ -match '^Collector: version (\S+), triage-collector\.ps1 SHA-256 ([0-9A-F]{64})$' })
    $commitLines = @($messages | Where-Object { $_ -match '^Collector git commit: ' })
    $loggedVersion = ""
    $loggedHash = ""
    if ($versionLines.Count -eq 1 -and $versionLines[0] -match '^Collector: version (\S+), triage-collector\.ps1 SHA-256 ([0-9A-F]{64})$') {
        $loggedVersion = $Matches[1]
        $loggedHash = $Matches[2]
    }
    Write-TestResult -Succeeded ($versionLines.Count -eq 1 -and $loggedHash -eq $scriptHash -and $loggedVersion -and $loggedVersion -eq $info.CollectorVersion) -Message "provenance: one 'Collector: version' line with the script's SHA-256 and collection_info.json's CollectorVersion ($loggedVersion)"
    Write-TestResult -Succeeded ($info.CollectorScriptSha256 -eq $scriptHash) -Message "collection_info.json: CollectorScriptSha256 is the SHA-256 of the script that ran"
    $commitOk = $false
    if ($commitLines.Count -eq 1) {
        if ($info.CollectorGitCommit) { $commitOk = $commitLines[0].StartsWith("Collector git commit: $($info.CollectorGitCommit) (") -and $info.CollectorGitCommit -match '^([0-9a-f]{40}|[0-9a-f]{64})$' }
        else { $commitOk = $commitLines[0] -eq "Collector git commit: none (not run from a git checkout)" }
    }
    Write-TestResult -Succeeded $commitOk -Message "provenance: one 'Collector git commit' line, the same commit as collection_info.json's CollectorGitCommit ($(if ($info.CollectorGitCommit) { $info.CollectorGitCommit } else { 'none' }))"
    # The collector's own processes (live runs) beside the provenance: its
    # PowerShell first, started by this test (the -Command child)
    $processEntries = @($info.CollectorProcesses)
    $powershellName = [System.IO.Path]::GetFileName($powershellExe)
    $collectorEntryOk = $processEntries.Count -ge 1 -and $processEntries[0].Role -eq "Collector" -and $processEntries[0].Name -eq $powershellName -and $processEntries[0].ParentPid -eq $PID
    Write-TestResult -Succeeded $collectorEntryOk -Message "collection_info.json: CollectorProcesses names the collector's PowerShell first ($(if ($processEntries.Count) { "$($processEntries[0].Role) $($processEntries[0].Name), parent PID $($processEntries[0].ParentPid)" } else { 'no entry' }); this test is PID $PID)"

    # --- AppCompatCache, read with .NET, in reg query's layout ---
    $appCompatLines = @($messages | Where-Object { $_ -match '^AppCompatCache: (\d+) bytes read from the registry\.$' })
    $appCompatBytes = 0
    if ($appCompatLines.Count -eq 1 -and $appCompatLines[0] -match '^AppCompatCache: (\d+) bytes read from the registry\.$') { $appCompatBytes = [int]$Matches[1] }
    Write-TestResult -Succeeded ($appCompatLines.Count -eq 1 -and $appCompatBytes -gt 0) -Message "AppCompatCache: one 'N bytes read from the registry' line (N = $appCompatBytes)"
    $appCompatFile = Join-Path $outputPath "Execution\appcompat_cache.reg"
    $appCompatOk = $false
    if (Test-Path -LiteralPath $appCompatFile) {
        $fileLines = [System.IO.File]::ReadAllLines($appCompatFile)
        $appCompatOk = $fileLines.Count -ge 3 -and $fileLines[0] -eq "" -and
            $fileLines[1] -eq "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" -and
            $fileLines[2] -match '^    AppCompatCache    REG_BINARY    ([0-9A-F]+)$' -and $Matches[1].Length -eq 2 * $appCompatBytes
    }
    Write-TestResult -Succeeded $appCompatOk -Message "Execution\appcompat_cache.reg: the key line and the value's $(2 * $appCompatBytes) hex digits, as reg query prints them"

    # --- USBSTOR: a result line, and a file that says what was found ---
    $usbLines = @($messages | Where-Object { $_ -match '^(WARNING: )?USBSTOR: ' })
    $usbFile = Join-Path $outputPath "USB\usb_storage_devices.txt"
    $usbText = if (Test-Path -LiteralPath $usbFile) { [System.IO.File]::ReadAllText($usbFile) } else { "" }
    $usbOk = $false
    if ($usbLines.Count -eq 1) {
        if ($usbLines[0] -match '^USBSTOR: (\d+) USB storage device\(s\) recorded in the registry \(usb_storage_devices\.txt\)\.$') {
            $usbOk = ([regex]::Matches($usbText, '(?m)^PSChildName\s*:')).Count -eq [int]$Matches[1]
        }
        else { $usbOk = $usbText -match '^\s*\(no USB storage device' }
    }
    Write-TestResult -Succeeded $usbOk -Message "USBSTOR: one result line ($(if ($usbLines.Count) { $usbLines[0] } else { 'none' })) and usb_storage_devices.txt with those devices or a note"

    # --- Run keys: counts per hive, as in run_keys.csv ---
    $runLines = @($messages | Where-Object { $_ -match '^Run keys: (\d+) value\(s\) in HKLM, (\d+) value\(s\) in (\d+) loaded user hive\(s\)\.$' })
    $runOk = $false
    $runCsv = Join-Path $outputPath "Persistence\run_keys.csv"
    if ($runLines.Count -eq 1 -and $runLines[0] -match '^Run keys: (\d+) value\(s\) in HKLM, (\d+) value\(s\) in (\d+) loaded user hive\(s\)\.$') {
        $hklm = [int]$Matches[1]
        $users = [int]$Matches[2]
        $rows = @()
        if (Test-Path -LiteralPath $runCsv) { $rows = @(Import-Csv -LiteralPath $runCsv) }
        $csvHklm = @($rows | Where-Object { $_.Hive -eq "HKLM" }).Count
        $runOk = $hklm -eq $csvHklm -and $users -eq ($rows.Count - $csvHklm)
    }
    Write-TestResult -Succeeded $runOk -Message "Run keys: one line, with per-hive counts that match run_keys.csv ($(if ($runLines.Count) { $runLines[0] } else { 'no line' }))"
}
catch {
    Write-TestResult -Succeeded $false -Message "the test stopped: $($_.Exception.Message)"
}
finally {
    $ErrorActionPreference = "Continue"
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $workDir) { Write-Host "WARNING: could not remove $workDir" -ForegroundColor Yellow }
}

Write-Host ""
if ($script:failures -gt 0) {
    Write-Host "FAIL: $script:failures check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all live collection checks passed" -ForegroundColor Green
exit 0

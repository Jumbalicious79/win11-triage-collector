# =============================================================
# Memory acquisition log test
# Checks how the collector (triage-collector.ps1) keeps the output of the
# memory capture tool, the only record of DumpIt's SHA-256 and NtStatus.
# A stand-in tool (a .cmd file in the test folder) prints DumpIt-like
# lines, one of them on stderr, and Save-MemoryAcquisitionLog must write
# all of them to Memory\memory_acquisition_log.txt and list that file in
# the manifest with its hash and size, without logging or counting an
# error; a tool that prints nothing gives a log with a note, also in the
# manifest. The collection folders have [ ] in their names. Last, the
# collector's memory capture section must save the log through this
# helper and write nothing else to it (the manifest hash would no longer
# match). No admin rights needed. Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryAcquisitionLog.ps1
# =============================================================
param(
    # Collector script to test (default: the repository's triage-collector.ps1)
    [string]$CollectorPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$collector = $CollectorPath
if (-not $collector) { $collector = Join-Path $repoRoot "triage-collector.ps1" }

# --- Load the collector's functions without running a collection ---
# Every function definition that is not inside another function (many sit
# inside the collector's main try block), taken from the script's syntax
# tree: the script itself, with its Administrator check, does not run
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($collector, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    Write-Host "FAIL: $collector does not parse: $($parseErrors[0].Message)" -ForegroundColor Red
    exit 1
}
function Test-InsideFunction {
    param($Node)
    for ($parent = $Node.Parent; $parent; $parent = $parent.Parent) {
        if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $true }
    }
    return $false
}
$definitions = New-Object System.Collections.Generic.List[string]
$nodes = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($node in $nodes) {
    if (-not (Test-InsideFunction $node)) { $definitions.Add($node.Extent.Text) }
}
. ([scriptblock]::Create($definitions -join "`r`n"))
if (-not (Get-Command Save-MemoryAcquisitionLog -ErrorAction SilentlyContinue)) {
    Write-Host "FAIL: Save-MemoryAcquisitionLog not found in $collector" -ForegroundColor Red
    exit 1
}

# --- Collector state: log, manifest and counters ---
# Two collections (one per tool; each case sets $OutputPath), [ ] in their
# names: Out-File without -LiteralPath fails on such a path
$testId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) "TriageMemoryLogTest_$testId"
$collectionDirs = @((Join-Path $workDir "TriageCollection [1]"), (Join-Path $workDir "TriageCollection [2]"))
$toolDir = Join-Path $workDir "tool"
$logFile = Join-Path $workDir "collection_log.txt"
$manifestFile = Join-Path $workDir "collection_manifest.csv"
$script:logToFile = $true
$script:fileCount = 0
$script:errorCount = 0
$script:totalBytes = 0

function Get-LogLines {
    if (-not (Test-Path -LiteralPath $logFile)) { return @() }
    return @(Get-Content -LiteralPath $logFile)
}
function Get-ManifestRows {
    param([string]$SourcePath)
    if (-not (Test-Path -LiteralPath $manifestFile)) { return @() }
    return @(Import-Csv -LiteralPath $manifestFile -Header SHA256, SourcePath, DestPath, SizeBytes, CollectedAt, RelativePath, SourceCreatedUtc, SourceModifiedUtc, SourceAccessedUtc |
        Where-Object { $_.SourcePath -eq $SourcePath })
}

# The collector's error preference: the tool runs and the log is saved
# as in the memory capture section (& <tool> ... 2>&1, then the helper).
# Under Stop, stderr output of the tool would end the call. Returns the
# tool output and the message of an error the helper threw (the
# collector's catch would log it as "Memory capture failed")
function Invoke-CaptureTool {
    param([string]$ToolPath, [string]$LogPath, [string]$ToolName)
    $ErrorActionPreference = "Continue"
    $result = & $ToolPath 2>&1
    $thrown = ""
    try { Save-MemoryAcquisitionLog -Output $result -LogPath $LogPath -ToolName $ToolName }
    catch { $thrown = $_.Exception.Message }
    return [PSCustomObject]@{ Output = @($result | Where-Object { $null -ne $_ }); Thrown = $thrown }
}

$failures = 0
$results = New-Object System.Collections.Generic.List[object]
function Add-Result {
    param([string]$Case, [System.Collections.Generic.List[string]]$Problems, [string]$Info = "")
    $note = $Problems -join "; "
    if ($Problems.Count -gt 0) { $script:failures++ } elseif ($Info) { $note = $Info }
    $results.Add([PSCustomObject]@{
        Result = $(if ($Problems.Count -gt 0) { "FAIL" } else { "PASS" })
        Case   = $Case
        Note   = $note
    })
}

# Manifest row of one saved log: one row, the file's hash, size and
# collection-relative path, no source times (it is not a copied file)
function Test-ManifestRow {
    param([string]$SourcePath, [string]$LogPath, [System.Collections.Generic.List[string]]$Problems)
    $rows = @(Get-ManifestRows $SourcePath)
    if ($rows.Count -ne 1) { $Problems.Add("$($rows.Count) manifest row(s) for $SourcePath"); return }
    $row = $rows[0]
    if (-not (Test-Path -LiteralPath $LogPath)) { $Problems.Add("no file at $LogPath"); return }
    $hash = (Get-FileHash -LiteralPath $LogPath -Algorithm SHA256).Hash
    $size = (Get-Item -LiteralPath $LogPath -Force).Length
    if ($row.DestPath -ne $LogPath) { $Problems.Add("DestPath is '$($row.DestPath)'") }
    if ($row.RelativePath -ne "Memory\memory_acquisition_log.txt") { $Problems.Add("RelativePath is '$($row.RelativePath)'") }
    if ($row.SHA256 -ne $hash) { $Problems.Add("SHA256 $($row.SHA256), file has $hash") }
    if ($row.SizeBytes -ne [string]$size) { $Problems.Add("SizeBytes $($row.SizeBytes), file has $size") }
    $times = @($row.SourceCreatedUtc, $row.SourceModifiedUtc, $row.SourceAccessedUtc) -join ""
    if ($times) { $Problems.Add("source times '$($row.SourceCreatedUtc)', '$($row.SourceModifiedUtc)', '$($row.SourceAccessedUtc)'") }
}

# The collector's variable for the acquisition log path, in its syntax tree
function Test-IsLogVariable {
    param($Node)
    return ($Node -is [System.Management.Automation.Language.VariableExpressionAst] -and $Node.VariablePath.UserPath -eq "memLogFile")
}

# --- The stand-in tools: synthetic DumpIt-like output (no real computer
# name, machine ID or hash), and a tool that prints nothing ---
$stdoutLines = @(
    "  DumpIt 0.0.00000000 (X64) (synthetic test output)",
    "    Computer name:              TRIAGE-TEST",
    "    Created file size:           1048576 bytes (1 Mb)",
    "    NtStatus (troubleshooting):   0x00000000",
    ("    SHA-256: " + ("0123456789ABCDEF" * 4))
)
$stderrText = "Error: synthetic message on stderr"
$dumpItTool = Join-Path $toolDir "dumpit-standin.cmd"
$silentTool = Join-Path $toolDir "silent-standin.cmd"
$toolLines = @("@echo off")
for ($i = 0; $i -lt $stdoutLines.Count; $i++) {
    $toolLines += "echo " + $stdoutLines[$i]
    if ($i -eq 2) { $toolLines += "echo   $stderrText 1>&2" }
}

try {
    New-Item -ItemType Directory -Path $toolDir -Force | Out-Null
    [System.IO.File]::WriteAllText($dumpItTool, (($toolLines -join "`r`n") + "`r`n"), [System.Text.Encoding]::ASCII)
    [System.IO.File]::WriteAllText($silentTool, "@echo off`r`n", [System.Text.Encoding]::ASCII)

    # --- 1. DumpIt-like output: every line in the log, the log in the
    # manifest ---
    $OutputPath = $collectionDirs[0]
    $logPath = Join-Path $OutputPath "Memory\memory_acquisition_log.txt"
    $logBefore = Get-LogLines
    $errorsBefore = $script:errorCount
    $filesBefore = $script:fileCount
    $bytesBefore = $script:totalBytes
    $run = Invoke-CaptureTool -ToolPath $dumpItTool -LogPath $logPath -ToolName "DumpIt"
    $logNew = @(Get-LogLines | Select-Object -Skip $logBefore.Count)

    $problems = New-Object System.Collections.Generic.List[string]
    if ($run.Thrown) { $problems.Add("Save-MemoryAcquisitionLog threw: $($run.Thrown)") }
    $errorRecords = @($run.Output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
    if ($errorRecords.Count -ne 1) { $problems.Add("the stand-in tool gave $($errorRecords.Count) stderr record(s), expected 1") }
    $savedLines = @()
    if (Test-Path -LiteralPath $logPath) {
        $savedLines = @(Get-Content -LiteralPath $logPath -Encoding UTF8)
        # The stdout lines whole and in order; the stderr line where the
        # edition puts it (5.1 writes the whole error record, which repeats
        # the text in its CategoryInfo line)
        $next = 0
        foreach ($line in $stdoutLines) {
            $found = -1
            for ($j = $next; $j -lt $savedLines.Count; $j++) {
                if ($savedLines[$j].TrimEnd() -ceq $line) { $found = $j; break }
            }
            if ($found -lt 0) { $problems.Add("line '$($line.Trim())' missing or out of order"); continue }
            $next = $found + 1
        }
        if (@($savedLines | Where-Object { $_.Contains($stderrText) }).Count -eq 0) { $problems.Add("stderr line '$stderrText' not in the log") }
    } else {
        $problems.Add("no memory_acquisition_log.txt")
    }
    Add-Result "tool output in the log, in order" $problems -Info "$($savedLines.Count) lines"

    $problems = New-Object System.Collections.Generic.List[string]
    Test-ManifestRow -SourcePath "(memory capture tool output: DumpIt)" -LogPath $logPath -Problems $problems
    if (($script:fileCount - $filesBefore) -ne 1) { $problems.Add("file count went up by $($script:fileCount - $filesBefore), expected 1") }
    $logSize = Get-FileLength $logPath
    if ($logSize -ge 0 -and ($script:totalBytes - $bytesBefore) -ne $logSize) { $problems.Add("total bytes went up by $($script:totalBytes - $bytesBefore), expected $logSize") }
    if ($script:errorCount -ne $errorsBefore) { $problems.Add("error count went up by $($script:errorCount - $errorsBefore)") }
    if ($logNew.Count -ne 0) { $problems.Add("log: $($logNew -join ' | ')") }
    Add-Result "log in the manifest, no error" $problems -Info "$logSize bytes"

    # --- 2. A tool that prints nothing: a note instead of an empty file
    # (which Record-Manifest would delete) ---
    $OutputPath = $collectionDirs[1]
    $logPath = Join-Path $OutputPath "Memory\memory_acquisition_log.txt"
    $logBefore = Get-LogLines
    $errorsBefore = $script:errorCount
    $filesBefore = $script:fileCount
    $run = Invoke-CaptureTool -ToolPath $silentTool -LogPath $logPath -ToolName "WinPmem"
    $logNew = @(Get-LogLines | Select-Object -Skip $logBefore.Count)

    $problems = New-Object System.Collections.Generic.List[string]
    if ($run.Thrown) { $problems.Add("Save-MemoryAcquisitionLog threw: $($run.Thrown)") }
    if ($run.Output.Count -ne 0) { $problems.Add("the silent stand-in tool printed $($run.Output.Count) line(s)") }
    $savedLines = @()
    if (Test-Path -LiteralPath $logPath) { $savedLines = @(Get-Content -LiteralPath $logPath -Encoding UTF8) } else { $problems.Add("no memory_acquisition_log.txt") }
    if ($savedLines.Count -ne 1 -or $savedLines[0] -cne "(no output from WinPmem)") { $problems.Add("log file: $($savedLines -join ' | ')") }
    Test-ManifestRow -SourcePath "(memory capture tool output: WinPmem)" -LogPath $logPath -Problems $problems
    if (($script:fileCount - $filesBefore) -ne 1) { $problems.Add("file count went up by $($script:fileCount - $filesBefore), expected 1") }
    if ($script:errorCount -ne $errorsBefore) { $problems.Add("error count went up by $($script:errorCount - $errorsBefore)") }
    if ($logNew.Count -ne 0) { $problems.Add("log: $($logNew -join ' | ')") }
    Add-Result "no output: a note, in the manifest" $problems -Info ($savedLines -join " ")

    # --- 3. The memory capture section (outside any function): the log is
    # saved once, through the helper, and nothing else writes to it ---
    $problems = New-Object System.Collections.Generic.List[string]
    $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
        Where-Object { -not (Test-InsideFunction $_) })
    $helperCalls = @($commands | Where-Object { $_.GetCommandName() -eq "Save-MemoryAcquisitionLog" })
    if ($helperCalls.Count -ne 1) {
        $problems.Add("$($helperCalls.Count) calls of Save-MemoryAcquisitionLog, expected 1")
    } else {
        $elements = @($helperCalls[0].CommandElements)
        $logPathArg = ""
        for ($k = 1; $k -lt $elements.Count; $k++) {
            if ($elements[$k] -is [System.Management.Automation.Language.CommandParameterAst] -and $elements[$k].ParameterName -eq "LogPath") {
                if ($elements[$k].Argument) { $logPathArg = $elements[$k].Argument.Extent.Text }
                elseif ($k + 1 -lt $elements.Count) { $logPathArg = $elements[$k + 1].Extent.Text }
            }
        }
        if ($logPathArg -ne '$memLogFile') { $problems.Add("Save-MemoryAcquisitionLog -LogPath is '$logPathArg', expected `$memLogFile") }
    }
    # Writes to $memLogFile: a writing cmdlet given it (-Path $x or
    # -Path:$x), a .NET Write*/Append* call, or a > / >> redirection
    $writes = New-Object System.Collections.Generic.List[object]
    $writers = @("Out-File", "Set-Content", "Add-Content", "Tee-Object", "Clear-Content")
    foreach ($command in $commands) {
        if ($writers -notcontains $command.GetCommandName()) { continue }
        foreach ($element in $command.CommandElements) {
            if ((Test-IsLogVariable $element) -or ($element -is [System.Management.Automation.Language.CommandParameterAst] -and (Test-IsLogVariable $element.Argument))) { $writes.Add($command); break }
        }
    }
    $methodCalls = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) |
        Where-Object { -not (Test-InsideFunction $_) -and $_.Member.Extent.Text -match '^(Write|Append)' })
    foreach ($call in $methodCalls) {
        if (@($call.Arguments | Where-Object { Test-IsLogVariable $_ }).Count -gt 0) { $writes.Add($call) }
    }
    $redirections = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FileRedirectionAst] }, $true) |
        Where-Object { -not (Test-InsideFunction $_) -and (Test-IsLogVariable $_.Location) })
    foreach ($redirection in $redirections) { $writes.Add($redirection.Parent) }
    foreach ($write in $writes) { $problems.Add("line $($write.Extent.StartLineNumber) writes to `$memLogFile: $($write.Extent.Text)") }
    Add-Result "collector saves the log via the helper" $problems
}
catch {
    $failures++
    Write-Host "FAIL: test setup or run error: $($_.Exception.Message)" -ForegroundColor Red
    if (Test-Path -LiteralPath $logFile) { Get-Content -LiteralPath $logFile | ForEach-Object { Write-Host "  | $_" } }
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
foreach ($r in $results) {
    $color = if ($r.Result -eq "PASS") { "Green" } else { "Red" }
    $line = "  {0}  {1}" -f $r.Result, $r.Case
    if ($r.Note) { $line = "  {0}  {1,-40} -- {2}" -f $r.Result, $r.Case, $r.Note }
    Write-Host $line -ForegroundColor $color
    if ($r.Result -ne "PASS" -and $env:GITHUB_ACTIONS) {
        Write-Host "::error file=tests/Test-MemoryAcquisitionLog.ps1::$($r.Case): $($r.Note)"
    }
}
if ($failures -gt 0 -or $results.Count -eq 0) {
    Write-Host "FAIL: $failures check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: $($results.Count) check(s)" -ForegroundColor Green
exit 0

# =============================================================
# Console QuickEdit test
# Checks how the collector (triage-collector.ps1) turns QuickEdit off in its
# console for the run (a click in the window would otherwise start a
# selection that pauses every console write, and so the run) and puts the
# console's mode back, without running a collection and without touching
# the console this test runs in:
#   - Get-ConsoleModeWithoutQuickEdit: QuickEdit on, already off, the
#     ENABLE_EXTENDED_FLAGS bit missing, no bits, all bits;
#   - Disable-ConsoleQuickEdit and Restore-ConsoleMode in child processes
#     this test starts (same PowerShell edition, no window, the caller's
#     error preference Stop): with input redirected, with no standard input
#     handle, and with a type of the helper's name that lacks its methods,
#     nothing is changed or returned and nothing is written (no error, no
#     warning); in a console of the child's own, QuickEdit is turned off
#     and the mode put back exactly, once, and a console with QuickEdit
#     already off is left as it was;
#   - the collector's code: the helper runs right after the Administrator
#     check (before the first prompt and the collection); every exit after
#     it puts the mode back first; the main finally block puts it back,
#     after the cleanup, when the run is stopped; a finished run puts it
#     back right before the last prompt (after the zip); the log line.
# No admin rights needed. Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-ConsoleMode.ps1
# =============================================================
param(
    # Collector script to test (default: the repository's triage-collector.ps1)
    [string]$CollectorPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$collector = $CollectorPath
if (-not $collector) { $collector = Join-Path $repoRoot "triage-collector.ps1" }
$collector = [System.IO.Path]::GetFullPath($collector)

# --- Load the collector's functions without running a collection ---
# Every function definition that is not inside another function, taken from
# the script's syntax tree: the script itself, with its Administrator
# check, does not run
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
foreach ($name in @("Get-ConsoleModeWithoutQuickEdit", "Disable-ConsoleQuickEdit", "Restore-ConsoleMode")) {
    if (-not (Get-Command $name -CommandType Function -ErrorAction SilentlyContinue)) {
        Write-Host "FAIL: $name not found in $collector" -ForegroundColor Red
        exit 1
    }
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
function New-Problems { return , (New-Object System.Collections.Generic.List[string]) }
function Format-Mode {
    param($Mode)
    if ($null -eq $Mode) { return "none" }
    return "0x{0:X4}" -f [uint32]$Mode
}

# --- The child script: loads the three helpers from the collector and runs
# one case. Its results are "key=value" lines in a file; "records" counts
# everything the helpers wrote to any stream (output aside from the
# returned mode, errors, warnings, Write-Host) ---
$childScript = @'
param([string]$CollectorPath, [string]$Case, [string]$ResultPath)
$ErrorActionPreference = "Stop"
$lines = New-Object System.Collections.Generic.List[string]
$script:records = New-Object System.Collections.Generic.List[string]
try {
    $names = @("Get-ConsoleModeWithoutQuickEdit", "Disable-ConsoleQuickEdit", "Restore-ConsoleMode")
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($CollectorPath, [ref]$null, [ref]$null)
    $found = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $names -contains $node.Name }, $true))
    . ([scriptblock]::Create((@($found | ForEach-Object { $_.Extent.Text }) -join "`r`n")))

    function Invoke-Disable {
        $script:returned = "unset"
        foreach ($record in @(& { $script:returned = Disable-ConsoleQuickEdit } *>&1)) { $script:records.Add("Disable: $record") }
        if ($null -eq $script:returned) { return "none" }
        return "0x{0:X4}" -f [uint32]$script:returned
    }
    function Invoke-Restore {
        foreach ($record in @(& { Restore-ConsoleMode } *>&1)) { $script:records.Add("Restore: $record") }
    }
    # The test's own access to the console (not the collector's type)
    function Initialize-TestNative {
        Add-Type -Namespace ConsoleModeTest -Name Native -ErrorAction Stop -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
"@
    }
    function Get-TestMode {
        $mode = [uint32]0
        if (-not [ConsoleModeTest.Native]::GetConsoleMode([ConsoleModeTest.Native]::GetStdHandle(-10), [ref]$mode)) { return "fail" }
        return "0x{0:X4}" -f $mode
    }
    function Set-TestMode {
        param([uint32]$Mode)
        if (-not [ConsoleModeTest.Native]::SetConsoleMode([ConsoleModeTest.Native]::GetStdHandle(-10), $Mode)) { throw "SetConsoleMode 0x{0:X4} failed" -f $Mode }
    }

    switch ($Case) {
        "Redirected" {
            $lines.Add("returned=" + (Invoke-Disable))
            Invoke-Restore
        }
        "NoStdin" {
            Initialize-TestNative
            [void][ConsoleModeTest.Native]::SetStdHandle(-10, [IntPtr]::Zero)
            $lines.Add("handle=" + [ConsoleModeTest.Native]::GetStdHandle(-10))
            $lines.Add("returned=" + (Invoke-Disable))
            Invoke-Restore
        }
        "TypeClash" {
            # A type of the helper's name from somewhere else, without its
            # methods: the calls fail, and the helper must catch that
            Add-Type -Namespace TriageNative -Name ConsoleMode -ErrorAction Stop -MemberDefinition "public static int Unrelated;"
            $lines.Add("returned=" + (Invoke-Disable))
            Invoke-Restore
        }
        "Console" {
            Initialize-TestNative
            $lines.Add("initial=" + (Get-TestMode))
            # QuickEdit on (the usual default): off, then back exactly
            Set-TestMode 0x01F7
            $lines.Add("on.returned=" + (Invoke-Disable))
            $lines.Add("on.during=" + (Get-TestMode))
            $lines.Add("on.again=" + (Invoke-Disable))
            $lines.Add("on.duringAgain=" + (Get-TestMode))
            Invoke-Restore
            $lines.Add("on.after=" + (Get-TestMode))
            # A second restore does nothing
            Set-TestMode 0x01B7
            Invoke-Restore
            $lines.Add("on.secondRestore=" + (Get-TestMode))
            # QuickEdit already off: left as it was
            Set-TestMode 0x01B7
            $lines.Add("off.returned=" + (Invoke-Disable))
            $lines.Add("off.during=" + (Get-TestMode))
            Invoke-Restore
            $lines.Add("off.after=" + (Get-TestMode))
            # The mode read without ENABLE_EXTENDED_FLAGS: the flag is set
            # for the change, and the mode is put back as read
            Set-TestMode 0x0007
            $lines.Add("noext.returned=" + (Invoke-Disable))
            $lines.Add("noext.during=" + (Get-TestMode))
            Invoke-Restore
            $lines.Add("noext.after=" + (Get-TestMode))
        }
        default { throw "unknown case $Case" }
    }
    $lines.Add("records=" + $script:records.Count)
    foreach ($record in $script:records) { $lines.Add("record=" + $record) }
} catch {
    $lines.Add("exception=" + $_.Exception.Message)
}
[System.IO.File]::WriteAllLines($ResultPath, [string[]]$lines.ToArray())
'@

# Runs the child script in a new process of this PowerShell edition, with
# no window. Redirected: standard input, output and error are pipes (the
# child's input is at its end at once). Otherwise nothing is redirected,
# so the child's standard input is the console it gets for itself.
# Returns the exit code, what it wrote, and its result lines as a hashtable
$testId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) "TriageConsoleModeTest_$testId"
$childPath = Join-Path $workDir "child.ps1"
$exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
function Invoke-Child {
    param([string]$Case, [switch]$Redirected)
    $resultPath = Join-Path $workDir "$Case.txt"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$childPath`" -CollectorPath `"$collector`" -Case $Case -ResultPath `"$resultPath`""
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    if ($Redirected) {
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
    }
    $process = [System.Diagnostics.Process]::Start($psi)
    $stdout = ""
    $stderr = ""
    try {
        if ($Redirected) {
            $process.StandardInput.Close()
            $outTask = $process.StandardOutput.ReadToEndAsync()
            $errTask = $process.StandardError.ReadToEndAsync()
        }
        if (-not $process.WaitForExit(180000)) {
            try { $process.Kill() } catch { Write-Verbose "Could not stop the child: $($_.Exception.Message)" }
            throw "the $Case child did not end within 3 minutes"
        }
        if ($Redirected) {
            $stdout = $outTask.Result
            $stderr = $errTask.Result
        }
        $exitCode = $process.ExitCode
    } finally {
        $process.Dispose()
    }
    $values = @{}
    $recordLines = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath $resultPath) {
        foreach ($line in [System.IO.File]::ReadAllLines($resultPath)) {
            $at = $line.IndexOf('=')
            if ($at -lt 0) { continue }
            $key = $line.Substring(0, $at)
            if ($key -eq "record") { $recordLines.Add($line.Substring($at + 1)) } else { $values[$key] = $line.Substring($at + 1) }
        }
    }
    return [PSCustomObject]@{ ExitCode = $exitCode; Stdout = $stdout; Stderr = $stderr; Values = $values; Records = $recordLines }
}

# Problems common to every child: it ended normally, wrote its results,
# threw nothing, and the helpers wrote nothing to any stream
function Test-Child {
    param($Run, [System.Collections.Generic.List[string]]$Problems)
    if ($Run.ExitCode -ne 0) { $Problems.Add("exit code $($Run.ExitCode)") }
    if ($Run.Values.ContainsKey("exception")) { $Problems.Add("exception: $($Run.Values['exception'])") }
    if (-not $Run.Values.ContainsKey("records")) { $Problems.Add("no results written") }
    elseif ($Run.Values["records"] -ne "0") { $Problems.Add("the helpers wrote $($Run.Values['records']) record(s): $($Run.Records -join ' | ')") }
    if ($Run.Stdout.Trim()) { $Problems.Add("standard output: $($Run.Stdout.Trim())") }
    if ($Run.Stderr.Trim()) { $Problems.Add("standard error: $($Run.Stderr.Trim())") }
}
function Test-Value {
    param($Run, [string]$Key, [string]$Expected, [System.Collections.Generic.List[string]]$Problems)
    $actual = $Run.Values[$Key]
    if ($actual -cne $Expected) { $Problems.Add("$Key is '$actual', expected '$Expected'") }
}

try {
    # --- 1. The mode without QuickEdit (pure) ---
    $modeCases = @(
        @{ What = "QuickEdit on (the usual default)"; Old = 0x01F7; New = 0x01B7 }
        @{ What = "QuickEdit already off: unchanged"; Old = 0x01B7; New = 0x01B7 }
        @{ What = "extended flags missing: flag set"; Old = 0x0007; New = 0x0087 }
        @{ What = "QuickEdit bit without the flag"; Old = 0x0047; New = 0x0087 }
        @{ What = "no bits"; Old = 0x0000; New = 0x0080 }
        @{ What = "all 32 bits"; Old = [uint32]::MaxValue; New = [uint32]0xFFFFFFBFL }
    )
    foreach ($case in $modeCases) {
        $problems = New-Problems
        $new = Get-ConsoleModeWithoutQuickEdit -Mode $case.Old
        if ($new -isnot [uint32]) { $problems.Add("returned a $($new.GetType().Name), expected UInt32") }
        if ([uint32]$new -ne [uint32]$case.New) { $problems.Add("$(Format-Mode $case.Old) gives $(Format-Mode $new), expected $(Format-Mode $case.New)") }
        Add-Result "mode: $($case.What)" $problems -Info "$(Format-Mode $case.Old) -> $(Format-Mode $new)"
    }

    # --- 2. The helpers in child processes ---
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    [System.IO.File]::WriteAllText($childPath, $childScript, [System.Text.Encoding]::ASCII)

    $run = Invoke-Child -Case "Redirected" -Redirected
    $problems = New-Problems
    Test-Child $run $problems
    Test-Value $run "returned" "none" $problems
    Add-Result "input redirected: nothing changed" $problems -Info "exit 0, nothing written"

    $run = Invoke-Child -Case "NoStdin" -Redirected
    $problems = New-Problems
    Test-Child $run $problems
    Test-Value $run "handle" "0" $problems
    Test-Value $run "returned" "none" $problems
    Add-Result "no standard input handle: nothing" $problems -Info "exit 0, nothing written"

    $run = Invoke-Child -Case "TypeClash" -Redirected
    $problems = New-Problems
    Test-Child $run $problems
    Test-Value $run "returned" "none" $problems
    Add-Result "type without the methods: caught" $problems -Info "exit 0, nothing written"

    $run = Invoke-Child -Case "Console"
    $problems = New-Problems
    Test-Child $run $problems
    if ($run.Values["initial"] -eq "fail") { $problems.Add("the child has no console of its own (GetConsoleMode failed)") }
    foreach ($expected in @(
            @("on.returned", "0x01F7"), @("on.during", "0x01B7"), @("on.again", "none"), @("on.duringAgain", "0x01B7"),
            @("on.after", "0x01F7"), @("on.secondRestore", "0x01B7"),
            @("off.returned", "none"), @("off.during", "0x01B7"), @("off.after", "0x01B7"),
            @("noext.returned", "0x0007"), @("noext.during", "0x0087"), @("noext.after", "0x0007"))) {
        Test-Value $run $expected[0] $expected[1] $problems
    }
    Add-Result "own console: off, then put back once" $problems -Info "0x01F7 -> 0x01B7 -> 0x01F7 (child's console was $($run.Values['initial']))"

    # --- 3. The collector's code ---
    $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
        Where-Object { -not (Test-InsideFunction $_) })
    $topStatements = @($ast.EndBlock.Statements)
    # The top-level statement a node is in
    function Get-TopStatement {
        param($Node)
        for ($n = $Node; $n; $n = $n.Parent) {
            if ($n.Parent -and [object]::ReferenceEquals($n.Parent, $ast.EndBlock)) { return $n }
        }
        return $null
    }
    $disableCalls = @($commands | Where-Object { $_.GetCommandName() -eq "Disable-ConsoleQuickEdit" })
    $restoreCalls = @($commands | Where-Object { $_.GetCommandName() -eq "Restore-ConsoleMode" })
    $adminIndex = -1
    $mainTryIndex = -1
    $readKeyIndex = -1
    for ($i = 0; $i -lt $topStatements.Count; $i++) {
        if ($adminIndex -lt 0 -and $topStatements[$i] -is [System.Management.Automation.Language.IfStatementAst] -and $topStatements[$i].Clauses[0].Item1.Extent.Text -match 'IsInRole') { $adminIndex = $i }
        if ($topStatements[$i] -is [System.Management.Automation.Language.TryStatementAst] -and $topStatements[$i].Finally -and $topStatements[$i].Finally.Extent.Text -match 'Invoke-CollectionCleanup') { $mainTryIndex = $i }
        if ($topStatements[$i].Extent.Text -like '*RawUI.ReadKey*') { $readKeyIndex = $i }
    }

    # Right after the Administrator check: only assignments and function
    # definitions in between, so before the first prompt, the first exit
    # that needs a restore and the collection
    $problems = New-Problems
    $disableIndex = -1
    $resultVariable = ""
    if ($disableCalls.Count -ne 1) { $problems.Add("$($disableCalls.Count) calls of Disable-ConsoleQuickEdit outside functions, expected 1") }
    elseif ($adminIndex -lt 0 -or $mainTryIndex -lt 0) { $problems.Add("Administrator check ($adminIndex) or main try block ($mainTryIndex) not found") }
    else {
        $disableStatement = Get-TopStatement $disableCalls[0]
        $disableIndex = [array]::IndexOf($topStatements, $disableStatement)
        if ($disableStatement -is [System.Management.Automation.Language.AssignmentStatementAst]) { $resultVariable = $disableStatement.Left.Extent.Text }
        if ($disableIndex -le $adminIndex) { $problems.Add("called at line $($disableCalls[0].Extent.StartLineNumber), not after the Administrator check") }
        for ($i = $adminIndex + 1; $i -lt $disableIndex; $i++) {
            if ($topStatements[$i] -isnot [System.Management.Automation.Language.AssignmentStatementAst] -and $topStatements[$i] -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
                $problems.Add("line $($topStatements[$i].Extent.StartLineNumber) runs before it: $($topStatements[$i].Extent.Text.Split("`n")[0].Trim())")
            }
        }
        $firstPrompt = @($commands | Where-Object { $_.GetCommandName() -in @("Read-Host", "pause") -and $_.Extent.StartOffset -gt $topStatements[$adminIndex].Extent.EndOffset } | Sort-Object { $_.Extent.StartOffset } | Select-Object -First 1)
        if ($firstPrompt.Count -eq 1 -and $firstPrompt[0].Extent.StartOffset -lt $disableCalls[0].Extent.StartOffset) { $problems.Add("the prompt at line $($firstPrompt[0].Extent.StartLineNumber) comes first") }
        if ($disableIndex -ge $mainTryIndex) { $problems.Add("called after the collection starts") }
        if (-not $resultVariable) { $problems.Add("its result is not kept in a variable (the log line needs it)") }
    }
    Add-Result "collector: off right after the admin check" $problems -Info "line $(if ($disableCalls.Count -eq 1) { $disableCalls[0].Extent.StartLineNumber })"

    # Every exit after it (outside the main try block, whose finally block
    # covers its own) puts the mode back first, in the same block
    $problems = New-Problems
    $exits = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true) |
        Where-Object { -not (Test-InsideFunction $_) -and $disableCalls.Count -eq 1 -and $_.Extent.StartOffset -gt $disableCalls[0].Extent.StartOffset })
    foreach ($exitStatement in $exits) {
        if ($mainTryIndex -ge 0 -and $exitStatement.Extent.StartOffset -gt $topStatements[$mainTryIndex].Body.Extent.StartOffset -and $exitStatement.Extent.EndOffset -le $topStatements[$mainTryIndex].Body.Extent.EndOffset) { continue }
        $block = $exitStatement.Parent
        $before = @()
        if ($block -is [System.Management.Automation.Language.StatementBlockAst] -or $block -is [System.Management.Automation.Language.NamedBlockAst]) {
            $before = @($block.Statements | Where-Object { $_.Extent.EndOffset -le $exitStatement.Extent.StartOffset })
        }
        $restored = @($before | Where-Object { $_ -is [System.Management.Automation.Language.PipelineAst] -and $_.PipelineElements.Count -eq 1 -and $_.PipelineElements[0] -is [System.Management.Automation.Language.CommandAst] -and $_.PipelineElements[0].GetCommandName() -eq "Restore-ConsoleMode" })
        if ($restored.Count -eq 0) { $problems.Add("exit at line $($exitStatement.Extent.StartLineNumber) does not run Restore-ConsoleMode first") }
    }
    if ($disableCalls.Count -eq 1 -and $exits.Count -eq 0) { $problems.Add("no exit found after the call (the early exits were expected)") }
    Add-Result "collector: every exit restores first" $problems -Info "$($exits.Count) exits"

    # The main finally block: after the cleanup, only when the run did not
    # finish (the try block's last statement marks a finished run)
    $problems = New-Problems
    if ($mainTryIndex -lt 0) { $problems.Add("main try block not found") }
    else {
        $mainTry = $topStatements[$mainTryIndex]
        $inFinally = @($restoreCalls | Where-Object { $_.Extent.StartOffset -gt $mainTry.Finally.Extent.StartOffset -and $_.Extent.EndOffset -le $mainTry.Finally.Extent.EndOffset })
        $cleanup = @($commands | Where-Object { $_.GetCommandName() -eq "Invoke-CollectionCleanup" -and $_.Extent.StartOffset -gt $mainTry.Finally.Extent.StartOffset -and $_.Extent.EndOffset -le $mainTry.Finally.Extent.EndOffset })
        if ($inFinally.Count -ne 1) { $problems.Add("$($inFinally.Count) Restore-ConsoleMode calls in the main finally block, expected 1") }
        else {
            if ($cleanup.Count -ne 1 -or $cleanup[0].Extent.StartOffset -gt $inFinally[0].Extent.StartOffset) { $problems.Add("not after Invoke-CollectionCleanup") }
            $condition = $null
            for ($n = $inFinally[0].Parent; $n -and -not [object]::ReferenceEquals($n, $mainTry.Finally); $n = $n.Parent) {
                if ($n -is [System.Management.Automation.Language.IfStatementAst]) { $condition = $n.Clauses[0].Item1.Extent.Text; break }
            }
            if ($condition -ne '-not $script:collectionCompleted') { $problems.Add("its condition is '$condition', expected '-not `$script:collectionCompleted'") }
        }
        $lastBodyStatement = @($mainTry.Body.Statements)[-1]
        if ($lastBodyStatement.Extent.Text -ne '$script:collectionCompleted = $true') { $problems.Add("the try block's last statement is '$($lastBodyStatement.Extent.Text)', not the mark of a finished run") }
    }
    Add-Result "collector: stopped run restores in finally" $problems

    # A finished run: right before the last prompt, after the summary and
    # the zip (which a click must not pause either)
    $problems = New-Problems
    if ($readKeyIndex -le $mainTryIndex + 1) { $problems.Add("the last prompt ($readKeyIndex) not found after the main try block ($mainTryIndex)") }
    else {
        $beforePrompt = $topStatements[$readKeyIndex - 1]
        if ($beforePrompt.Extent.Text -ne "Restore-ConsoleMode") { $problems.Add("the statement before the last prompt is '$($beforePrompt.Extent.Text.Split("`n")[0].Trim())'") }
        $zipStatement = @($topStatements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Clauses[0].Item1.Extent.Text -eq '-not $NoCompress -and -not $memDumpMoveFailed' })
        if ($zipStatement.Count -ne 1) { $problems.Add("compression step not found") }
        elseif ([array]::IndexOf($topStatements, $zipStatement[0]) -gt $readKeyIndex - 1) { $problems.Add("the compression step comes after it") }
        $between = @($restoreCalls | Where-Object { $_.Extent.StartOffset -gt $topStatements[$mainTryIndex].Extent.EndOffset -and $_.Extent.EndOffset -le $topStatements[$readKeyIndex - 1].Extent.StartOffset })
        if ($between.Count -gt 0) { $problems.Add("also restored at line $($between[0].Extent.StartLineNumber), before the zip") }
    }
    Add-Result "collector: finished run restores at the end" $problems

    # The log line, once, in the collection's start-of-run logging, only
    # when the helper changed the mode
    $problems = New-Problems
    $expectedLine = "Console QuickEdit is off for this run, so a click in the window cannot pause it (copy text with the window menu: Edit > Mark)."
    $logCalls = @($commands | Where-Object { $_.GetCommandName() -eq "Log" -and $_.CommandElements.Count -eq 2 -and $_.CommandElements[1] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $_.CommandElements[1].Value -ceq $expectedLine })
    if ($logCalls.Count -ne 1) { $problems.Add("$($logCalls.Count) Log calls with the line, expected 1") }
    else {
        if ($mainTryIndex -lt 0 -or $logCalls[0].Extent.StartOffset -lt $topStatements[$mainTryIndex].Body.Extent.StartOffset -or $logCalls[0].Extent.EndOffset -gt $topStatements[$mainTryIndex].Body.Extent.EndOffset) { $problems.Add("not in the main try block") }
        $guard = $null
        for ($n = $logCalls[0].Parent; $n; $n = $n.Parent) {
            if ($n -is [System.Management.Automation.Language.IfStatementAst]) { $guard = $n.Clauses[0].Item1.Extent.Text; break }
        }
        if (-not $resultVariable -or $guard -ne "`$null -ne $resultVariable") { $problems.Add("its condition is '$guard', expected '`$null -ne $resultVariable'") }
    }
    Add-Result "collector: log line when turned off" $problems
}
catch {
    $failures++
    Write-Host "FAIL: test setup or run error: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
foreach ($r in $results) {
    $color = if ($r.Result -eq "PASS") { "Green" } else { "Red" }
    $line = "  {0}  {1}" -f $r.Result, $r.Case
    if ($r.Note) { $line = "  {0}  {1,-44} -- {2}" -f $r.Result, $r.Case, $r.Note }
    Write-Host $line -ForegroundColor $color
    if ($r.Result -ne "PASS" -and $env:GITHUB_ACTIONS) {
        Write-Host "::error file=tests/Test-ConsoleMode.ps1::$($r.Case): $($r.Note)"
    }
}
if ($failures -gt 0 -or $results.Count -eq 0) {
    Write-Host "FAIL: $failures check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: $($results.Count) check(s)" -ForegroundColor Green
exit 0

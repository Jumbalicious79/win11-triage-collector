# =============================================================
# Collector process IDs test
# Checks how the collector (triage-collector.ps1) records its own
# processes in collection_info.json (CollectorProcesses), which the
# timeline builder uses to leave exactly those processes unflagged in the
# memory dump (by process ID, name and start time, never by name alone):
#
#   a. which processes of a process list are the collector's (synthetic
#      lists): its PowerShell, the .bat's cmd window, the console host,
#      its children started during the run; not the launcher's other
#      children, a launcher or child with a reused PID, the collector's
#      children from before the run, or a PowerShell parent
#   b. the real process tree: PowerShell started by cmd.exe with a
#      console of its own, as Run-TriageCollector.bat starts it (no .bat
#      runs here); PIDs and start times checked against the live
#      processes
#   c. the memory capture tool, run through Invoke-MemoryCaptureTool (a
#      stand-in console program built here with ilasm): its PID and start
#      time, every output line (standard error after standard output),
#      arguments with spaces, [ ], quotes and backslashes, the dump file;
#      a tool that cannot start throws; a stop (as Ctrl+C) ends a tool
#      still running
#   d. collection_info.json written twice: one manifest row, with the
#      second version's hash and size, and the provenance fields
#      (CollectorVersion, CollectorScriptSha256, CollectorGitCommit) in
#      both versions; a second write that fails keeps the first version
#      and the row; a mounted image gets no CollectorProcesses
#   e. the memory section: the process list is read before the tool runs,
#      the tool's record is added right after it, and collection_info.json
#      is written again after the capture
#   f. end to end: the collector (a copy in a temporary folder, with the
#      stand-in as tools\dumpit\<arch>\DumpIt.exe and Get-PhysicalMemoryBytes
#      returning 1 MB, so the stand-in's 1 MB dump is complete and no real
#      memory is captured) run through cmd.exe with -Unattended: a capture
#      (Collector, Launcher, Console and MemoryCapture, each PID and the
#      parent links checked; the stand-in prints a "SHA-256:" line as
#      DumpIt does, which the collector reads from the tool's output and
#      finds equal to its own hash of the dump; the file written again
#      after the capture keeps the provenance fields), memory not chosen,
#      no capture tool, a tool that cannot start, and a mounted image (no
#      CollectorProcesses).
#
# a to e need no admin rights. f runs the collector, which needs
# Administrator rights (GitHub Actions Windows runners are elevated); for
# a local run without them, pass -CollectorPath with a copy of the
# collector that has no admin check. Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-CollectorProcesses.ps1
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
foreach ($name in @("Select-CollectorProcesses", "Get-CollectorProcessRecords", "Add-CollectorProcessRecord", "ConvertTo-CollectorProcessField", "Invoke-MemoryCaptureTool", "ConvertTo-NativeArgument", "Write-CollectionInfo", "Update-ManifestFileRow", "Get-NativeMachineType", "Get-CollectorProvenance")) {
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

# --- Collector state for the functions run here ---
$testId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) "TriageCollectorProcTest_$testId"
$caseDir = Join-Path $workDir "case [1] x"      # spaces and [ ] in every path below
$script:logToFile = $true
$script:fileCount = 0
$script:errorCount = 0
$script:totalBytes = 0
$logFile = Join-Path $workDir "collection_log.txt"
$manifestFile = Join-Path $workDir "collection_manifest.csv"
$script:TargetDrive = "C"
$script:IncludeSecrets = $false
$script:IncludeThunderbirdIndex = $false
# The PowerShell edition running this test runs the probes and the collector
$powershellExe = (Get-Process -Id $PID).Path
$powershellName = [System.IO.Path]::GetFileName($powershellExe)
$manifestHeader = "SHA256,SourcePath,DestPath,SizeBytes,CollectedAt,RelativePath,SourceCreatedUtc,SourceModifiedUtc,SourceAccessedUtc`r`n"

# A process as Get-CollectorProcessRecords lists it
function New-TestProcess {
    param([int]$Id, [int]$ParentId, [string]$Name, $Created)
    return [PSCustomObject]@{ ProcessId = $Id; ParentProcessId = $ParentId; Name = $Name; CreationDateUtc = $Created }
}
# "Role:Pid" of each record, in order
function Get-RoleText {
    param([object[]]$Records)
    return (@($Records | ForEach-Object { "$($_.Role):$($_.Pid)" }) -join " ")
}
# A StartUtc value read back from JSON: PowerShell 7 makes a [datetime] of
# it, Windows PowerShell 5.1 keeps the text
function ConvertTo-TestUtc {
    param($Value)
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Utc) { return $Value }
        return $Value.ToUniversalTime()
    }
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}
# Milliseconds between two times
function Get-DiffMs {
    param([datetime]$First, [datetime]$Second)
    return [math]::Abs(($First - $Second).TotalMilliseconds)
}
# collection_info.json as text and as an object
function Read-CollectionInfo {
    param([string]$Path)
    if (-not [System.IO.File]::Exists($Path)) { return $null }
    $raw = [System.IO.File]::ReadAllText($Path)
    return [PSCustomObject]@{ Raw = $raw; Info = ($raw | ConvertFrom-Json) }
}
# Every StartUtc in collection_info.json is ISO 8601 UTC to 100 ns
function Test-StartUtcText {
    param([string]$Raw, [int]$Expected, [System.Collections.Generic.List[string]]$Problems)
    $all = @([regex]::Matches($Raw, '"StartUtc"\s*:\s*"([^"]*)"') | ForEach-Object { $_.Groups[1].Value })
    $good = @($all | Where-Object { $_ -match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z$' })
    if ($all.Count -ne $Expected -or $good.Count -ne $all.Count) { $Problems.Add("StartUtc values: $($all -join ', ') (expected $Expected, ISO 8601 UTC to 100 ns)") }
}
# Manifest rows of collection_info.json, and whether the row matches the file
function Test-InfoManifestRow {
    param([string]$Manifest, [string]$InfoPath, [System.Collections.Generic.List[string]]$Problems)
    $rows = @(Import-Csv -LiteralPath $Manifest | Where-Object { $_.RelativePath -eq "collection_info.json" })
    if ($rows.Count -ne 1) { $Problems.Add("$($rows.Count) manifest row(s) for collection_info.json"); return }
    $hash = (Get-FileHash -LiteralPath $InfoPath -Algorithm SHA256).Hash
    $size = (Get-Item -LiteralPath $InfoPath -Force).Length
    if ($rows[0].SHA256 -ne $hash -or $rows[0].SizeBytes -ne [string]$size) { $Problems.Add("manifest row $($rows[0].SHA256) / $($rows[0].SizeBytes) bytes, file $hash / $size bytes") }
    if ($rows[0].SourcePath -ne "(collection metadata)") { $Problems.Add("manifest SourcePath '$($rows[0].SourcePath)'") }
    foreach ($leftover in @("$InfoPath.new", "$InfoPath.old", "$Manifest.new", "$Manifest.old")) {
        if ([System.IO.File]::Exists($leftover)) { $Problems.Add("left behind: $leftover") }
    }
}
# The provenance fields of a live run's collection_info.json: right after
# SchemaVersion, with this version and script SHA-256; CollectorProcesses
# last
function Test-InfoProvenance {
    param([object]$Info, [string]$Version, [string]$Sha256, [System.Collections.Generic.List[string]]$Problems)
    $names = (@($Info.PSObject.Properties | ForEach-Object { $_.Name }) -join ",")
    if ($names -notmatch '^SchemaVersion,CollectorVersion,CollectorScriptSha256,CollectorGitCommit,.+,CollectorProcesses$') { $Problems.Add("fields: $names") }
    if ($Info.CollectorVersion -cne $Version -or $Info.CollectorScriptSha256 -cne $Sha256) { $Problems.Add("provenance '$($Info.CollectorVersion)', '$($Info.CollectorScriptSha256)'; expected '$Version', '$Sha256'") }
}
# Run a console tool and return its exit code
function Invoke-NativeTool {
    param([string]$FilePath, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $null = & $FilePath @Arguments 2>&1 }
    finally { $ErrorActionPreference = $previous }
    return $LASTEXITCODE
}

# --- The memory capture tool stand-in ---
# A .NET Framework console program, assembled with the framework's
# ilasm.exe for this machine's processor (the collector only runs ARM64
# capture tools on ARM64 Windows, and a C# compiler for that is not part
# of Windows). It prints DumpIt-like lines, its own PID and start time and
# each argument, one "Error:" line on standard error, sleeps (/SLEEP ms,
# 300 by default), writes /OUTPUT <file> of /SIZE bytes (1 MB + 8 KB of
# zeros by default: complete for a RAM of 1 MB) and exits with 0. When the
# environment variable TRIAGE_TEST_STANDIN_SHA256 is set, it also prints
# "    SHA-256: <its value>" (before the NtStatus line), as DumpIt prints
# the dump's hash
$standInIl = @'
.assembly extern mscorlib { .publickeytoken = (B7 7A 5C 56 19 34 E0 89) .ver 4:0:0:0 }
.assembly extern System { .publickeytoken = (B7 7A 5C 56 19 34 E0 89) .ver 4:0:0:0 }
.assembly CaptureStandIn { .ver 1:0:0:0 }
.module CaptureStandIn.exe
.subsystem 0x0003
.class private auto ansi beforefieldinit StandIn extends [mscorlib]System.Object
{
  .method private hidebysig static int32 Main(string[] args) cil managed
  {
    .entrypoint
    .maxstack 4
    .locals init (class [System]System.Diagnostics.Process self, string output, int32 sleepMs, int64 size, int32 i, string arg, valuetype [mscorlib]System.DateTime start, class [mscorlib]System.IO.FileStream fs, string sha)
    ldnull
    stloc.1
    ldc.i4 300
    stloc.2
    ldc.i8 1056768
    stloc.3
    call class [System]System.Diagnostics.Process [System]System.Diagnostics.Process::GetCurrentProcess()
    stloc.0
    ldstr "  DumpIt stand-in (synthetic test output)"
    call void [mscorlib]System.Console::WriteLine(string)
    ldstr "    Stand-in PID: "
    ldloc.0
    callvirt instance int32 [System]System.Diagnostics.Process::get_Id()
    box [mscorlib]System.Int32
    call string [mscorlib]System.String::Concat(object, object)
    call void [mscorlib]System.Console::WriteLine(string)
    ldloc.0
    callvirt instance valuetype [mscorlib]System.DateTime [System]System.Diagnostics.Process::get_StartTime()
    stloc.s start
    ldloca.s start
    call instance valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::ToUniversalTime()
    stloc.s start
    ldstr "    Stand-in start (UTC): "
    ldloca.s start
    ldstr "o"
    call instance string [mscorlib]System.DateTime::ToString(string)
    call string [mscorlib]System.String::Concat(string, string)
    call void [mscorlib]System.Console::WriteLine(string)
    ldc.i4.0
    stloc.s i
    br LOOPCOND
  LOOPBODY:
    ldarg.0
    ldloc.s i
    ldelem.ref
    stloc.s arg
    ldstr "    argv: "
    ldloc.s arg
    call string [mscorlib]System.String::Concat(string, string)
    call void [mscorlib]System.Console::WriteLine(string)
    ldloc.s i
    ldc.i4.1
    add
    ldarg.0
    ldlen
    conv.i4
    bge NEXT
    ldloc.s arg
    ldstr "/OUTPUT"
    ldc.i4.5
    call bool [mscorlib]System.String::Equals(string, string, valuetype [mscorlib]System.StringComparison)
    brfalse NOTOUTPUT
    ldarg.0
    ldloc.s i
    ldc.i4.1
    add
    ldelem.ref
    stloc.1
  NOTOUTPUT:
    ldloc.s arg
    ldstr "/SLEEP"
    ldc.i4.5
    call bool [mscorlib]System.String::Equals(string, string, valuetype [mscorlib]System.StringComparison)
    brfalse NOTSLEEP
    ldarg.0
    ldloc.s i
    ldc.i4.1
    add
    ldelem.ref
    call int32 [mscorlib]System.Int32::Parse(string)
    stloc.2
  NOTSLEEP:
    ldloc.s arg
    ldstr "/SIZE"
    ldc.i4.5
    call bool [mscorlib]System.String::Equals(string, string, valuetype [mscorlib]System.StringComparison)
    brfalse NEXT
    ldarg.0
    ldloc.s i
    ldc.i4.1
    add
    ldelem.ref
    call int64 [mscorlib]System.Int64::Parse(string)
    stloc.3
  NEXT:
    ldloc.s i
    ldc.i4.1
    add
    stloc.s i
  LOOPCOND:
    ldloc.s i
    ldarg.0
    ldlen
    conv.i4
    blt LOOPBODY
    call class [mscorlib]System.IO.TextWriter [mscorlib]System.Console::get_Error()
    ldstr "  Error: synthetic message on stderr"
    callvirt instance void [mscorlib]System.IO.TextWriter::WriteLine(string)
    ldloc.2
    call void [mscorlib]System.Threading.Thread::Sleep(int32)
    ldloc.1
    brfalse NOFILE
    ldloc.1
    ldc.i4.1
    newobj instance void [mscorlib]System.IO.FileStream::.ctor(string, valuetype [mscorlib]System.IO.FileMode)
    stloc.s fs
    ldloc.s fs
    ldloc.3
    callvirt instance void [mscorlib]System.IO.Stream::SetLength(int64)
    ldloc.s fs
    callvirt instance void [mscorlib]System.IO.Stream::Dispose()
  NOFILE:
    ldstr "    Created file size: "
    ldloc.3
    box [mscorlib]System.Int64
    ldstr " bytes"
    call string [mscorlib]System.String::Concat(object, object, object)
    call void [mscorlib]System.Console::WriteLine(string)
    ldstr "TRIAGE_TEST_STANDIN_SHA256"
    call string [mscorlib]System.Environment::GetEnvironmentVariable(string)
    stloc.s sha
    ldloc.s sha
    brfalse NOSHA
    ldstr "    SHA-256: "
    ldloc.s sha
    call string [mscorlib]System.String::Concat(string, string)
    call void [mscorlib]System.Console::WriteLine(string)
  NOSHA:
    ldstr "    NtStatus (troubleshooting):   0x00000000"
    call void [mscorlib]System.Console::WriteLine(string)
    ldc.i4.0
    ret
  }
}
'@
$standInLines = @("  DumpIt stand-in (synthetic test output)")
$standInEndLines = @("    NtStatus (troubleshooting):   0x00000000", "  Error: synthetic message on stderr")
function New-CaptureStandIn {
    param([string]$Path)
    $machine = Get-NativeMachineType
    $framework = "Framework"
    $platform = @()
    if ($machine -eq 0xAA64) { $framework = "FrameworkArm64"; $platform = @("/PE64", "/ARM64") }
    elseif ($machine -eq 0x8664) { $framework = "Framework64"; $platform = @("/PE64", "/X64") }
    $ilasm = Join-Path $env:WINDIR "Microsoft.NET\$framework\v4.0.30319\ilasm.exe"
    if (-not [System.IO.File]::Exists($ilasm)) { throw "ilasm.exe of the .NET Framework 4 not found: $ilasm" }
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    $source = Join-Path (Split-Path $Path -Parent) "stand-in.il"
    [System.IO.File]::WriteAllText($source, $standInIl, [System.Text.Encoding]::ASCII)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $ilasmOutput = @(& $ilasm /NOLOGO /QUIET /EXE @platform "/OUTPUT=$Path" $source 2>&1) }
    finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0 -or -not [System.IO.File]::Exists($Path)) { throw "ilasm could not build the stand-in: $($ilasmOutput -join ' ')" }
    [System.IO.File]::Delete($source)
}
# What the stand-in printed about itself
function Get-StandInReport {
    param([string[]]$Lines)
    $report = [PSCustomObject]@{ Pid = 0; StartUtc = $null; Argv = @() }
    foreach ($line in $Lines) {
        if ($line -match '^    Stand-in PID: (\d+)$') { $report.Pid = [int]$Matches[1] }
        elseif ($line -match '^    Stand-in start \(UTC\): (\S+)$') { $report.StartUtc = ConvertTo-TestUtc $Matches[1] }
        elseif ($line.StartsWith("    argv: ")) { $report.Argv += $line.Substring(10) }
    }
    return $report
}

try {
    New-Item -ItemType Directory -Path $caseDir -Force | Out-Null
    [System.IO.File]::WriteAllText($manifestFile, $manifestHeader, (New-Object System.Text.UTF8Encoding($true)))

    # =========================================================
    # a. Select-CollectorProcesses on synthetic process lists
    # =========================================================
    $t0 = [datetime]::SpecifyKind([datetime]"2026-10-09T08:15:00", [System.DateTimeKind]::Utc)   # start of the run
    $explorer = New-TestProcess -Id 1000 -ParentId 900 -Name "explorer.exe" -Created $t0.AddHours(-5)
    $launcher = New-TestProcess -Id 300 -ParentId 2000 -Name "cmd.exe" -Created $t0.AddSeconds(-5)          # its parent (the relaunch) is gone
    $launcherConsole = New-TestProcess -Id 301 -ParentId 300 -Name "conhost.exe" -Created $t0.AddSeconds(-4.9)
    $self = New-TestProcess -Id 400 -ParentId 300 -Name "powershell.exe" -Created $t0.AddSeconds(-4)

    # The double-click shape: launcher, its console, a child started
    # during the run. Not: the launcher's net.exe (a child, but not a
    # console), a console of the launcher's PID from before it (a reused
    # PID), a process naming the collector as parent but started before it
    # (a reused PID), the collector's csc.exe from before the run's start,
    # an unrelated process, a process without a start time
    $list = @(
        $explorer, $launcher, $launcherConsole, $self,
        (New-TestProcess -Id 302 -ParentId 300 -Name "conhost.exe" -Created $t0.AddHours(-1)),
        (New-TestProcess -Id 303 -ParentId 300 -Name "net.exe" -Created $t0.AddSeconds(-4.5)),
        (New-TestProcess -Id 401 -ParentId 400 -Name "systeminfo.exe" -Created $t0.AddSeconds(5)),
        (New-TestProcess -Id 402 -ParentId 400 -Name "csc.exe" -Created $t0.AddSeconds(-1)),
        (New-TestProcess -Id 403 -ParentId 400 -Name "notepad.exe" -Created $t0.AddHours(-2)),
        (New-TestProcess -Id 500 -ParentId 1000 -Name "triage-collector.exe" -Created $t0.AddSeconds(1)),
        (New-TestProcess -Id 4 -ParentId 0 -Name "System" -Created $null)
    )
    $records = @(Select-CollectorProcesses -Processes $list -SelfPid 400 -CollectionStartUtc $t0)
    $problems = New-Problems
    $roles = Get-RoleText $records
    if ($roles -cne "Collector:400 Launcher:300 Console:301 Child:401") { $problems.Add("records: $roles") }
    $collectorRecord = @($records | Where-Object { $_.Role -eq "Collector" }) | Select-Object -First 1
    if ($collectorRecord -and ($collectorRecord.Name -cne "powershell.exe" -or $collectorRecord.ParentPid -ne 300 -or $collectorRecord.StartUtc -ne $self.CreationDateUtc)) { $problems.Add("collector record $($collectorRecord.Name) $($collectorRecord.ParentPid) $($collectorRecord.StartUtc)") }
    Add-Result "a: launcher, its console, a child of the run" $problems -Info $roles

    # The launcher's PID reused: a cmd.exe started after the collector
    # (and its console) is not the launcher
    $list = @(
        $self, (New-TestProcess -Id 300 -ParentId 1000 -Name "cmd.exe" -Created $t0.AddSeconds(10)),
        (New-TestProcess -Id 301 -ParentId 300 -Name "conhost.exe" -Created $t0.AddSeconds(10.1))
    )
    $problems = New-Problems
    $roles = Get-RoleText @(Select-CollectorProcesses -Processes $list -SelfPid 400 -CollectionStartUtc $t0)
    if ($roles -cne "Collector:400") { $problems.Add("records: $roles") }
    Add-Result "a: a parent started after it is not the launcher" $problems -Info $roles

    # Started from a PowerShell window (or the script run in one): no
    # launcher; its children from before the run (its own console host
    # included) are not the collector's, its child during the run is
    $shell = New-TestProcess -Id 400 -ParentId 1000 -Name "pwsh.exe" -Created $t0.AddHours(-3)
    $list = @(
        $explorer, $shell,
        (New-TestProcess -Id 410 -ParentId 400 -Name "conhost.exe" -Created $t0.AddHours(-3).AddMilliseconds(30)),
        (New-TestProcess -Id 411 -ParentId 400 -Name "ping.exe" -Created $t0.AddHours(-1)),
        (New-TestProcess -Id 412 -ParentId 400 -Name "systeminfo.exe" -Created $t0.AddSeconds(3))
    )
    $problems = New-Problems
    $roles = Get-RoleText @(Select-CollectorProcesses -Processes $list -SelfPid 400 -CollectionStartUtc $t0)
    if ($roles -cne "Collector:400 Child:412") { $problems.Add("records: $roles") }
    $list = @((New-TestProcess -Id 900 -ParentId 1000 -Name "powershell.exe" -Created $t0.AddHours(-1)), (New-TestProcess -Id 400 -ParentId 900 -Name "powershell.exe" -Created $t0.AddSeconds(-4)))
    $roles2 = Get-RoleText @(Select-CollectorProcesses -Processes $list -SelfPid 400 -CollectionStartUtc $t0)
    if ($roles2 -cne "Collector:400") { $problems.Add("PowerShell parent: $roles2") }
    Add-Result "a: PowerShell parent, older children" $problems -Info "$roles; $roles2"

    # An open cmd window as the launcher (the .bat run in it): its console
    # from its own start is, its other children (earlier tools still
    # running) are not, nor a console started after the collector
    $openCmd = New-TestProcess -Id 300 -ParentId 1000 -Name "CMD.EXE" -Created $t0.AddHours(-2)
    $list = @(
        $openCmd, (New-TestProcess -Id 301 -ParentId 300 -Name "conhost.exe" -Created $t0.AddHours(-2).AddMilliseconds(20)),
        (New-TestProcess -Id 305 -ParentId 300 -Name "ping.exe" -Created $t0.AddMinutes(-30)),
        (New-TestProcess -Id 306 -ParentId 300 -Name "conhost.exe" -Created $t0.AddSeconds(30)),
        $self
    )
    $problems = New-Problems
    $roles = Get-RoleText @(Select-CollectorProcesses -Processes $list -SelfPid 400 -CollectionStartUtc $t0)
    if ($roles -cne "Collector:400 Launcher:300 Console:301") { $problems.Add("records: $roles") }
    Add-Result "a: an open cmd window as the launcher" $problems -Info $roles

    # Not in the list, or no start time: nothing
    $problems = New-Problems
    $none = @(Select-CollectorProcesses -Processes @($explorer, $launcher) -SelfPid 400 -CollectionStartUtc $t0)
    $none2 = @(Select-CollectorProcesses -Processes @((New-TestProcess -Id 400 -ParentId 300 -Name "powershell.exe" -Created $null), $launcher) -SelfPid 400 -CollectionStartUtc $t0)
    if ($none.Count -ne 0 -or $none2.Count -ne 0) { $problems.Add("records: $(Get-RoleText $none) / $(Get-RoleText $none2)") }
    Add-Result "a: collector not in the list -> nothing" $problems

    # The field: role order, StartUtc as ISO 8601 UTC to 100 ns, and the
    # merge (the same PID and start within a second is not added again)
    $problems = New-Problems
    $script:collectorProcesses = New-Object System.Collections.Generic.List[object]
    $start = [datetime]::SpecifyKind([datetime]"2026-10-09T08:15:02.1234567", [System.DateTimeKind]::Utc)
    Add-CollectorProcessRecord @(
        @{ Role = "MemoryCapture"; Pid = 10232; Name = "DumpIt.exe"; StartUtc = $start.AddMinutes(1); ParentPid = 9120 },
        [ordered]@{ Role = "Console"; Pid = 8848; Name = "conhost.exe"; StartUtc = $start.AddSeconds(-2); ParentPid = 8840 },
        [ordered]@{ Role = "Collector"; Pid = 9120; Name = "powershell.exe"; StartUtc = $start; ParentPid = 8840 },
        [ordered]@{ Role = "Launcher"; Pid = 8840; Name = "cmd.exe"; StartUtc = $start.AddSeconds(-3); ParentPid = 7000 }
    )
    Add-CollectorProcessRecord @(
        [ordered]@{ Role = "Collector"; Pid = 9120; Name = "powershell.exe"; StartUtc = $start.AddMilliseconds(400); ParentPid = 8840 },
        [ordered]@{ Role = "Child"; Pid = 0; Name = "x.exe"; StartUtc = $start; ParentPid = 9120 },
        [ordered]@{ Role = "Child"; Pid = 77; Name = "x.exe"; StartUtc = $null; ParentPid = 9120 }
    )
    $field = ConvertTo-CollectorProcessField -Records ($script:collectorProcesses.ToArray())
    $roles = Get-RoleText $field
    if ($roles -cne "Collector:9120 Launcher:8840 Console:8848 MemoryCapture:10232") { $problems.Add("field: $roles") }
    $json = ConvertTo-Json -InputObject ([PSCustomObject]@{ CollectorProcesses = $field }) -Depth 4
    if ($json -notmatch '"StartUtc":\s*"2026-10-09T08:15:02\.1234567Z"') { $problems.Add("JSON: $json") }
    if (@($field)[0].PSObject.Properties.Name -join "," -cne "Role,Pid,Name,StartUtc,ParentPid") { $problems.Add("properties: $(@($field)[0].PSObject.Properties.Name -join ',')") }
    $listText = Format-CollectorProcessList $field
    if ($listText -cne "powershell.exe (PID 9120, collector), cmd.exe (PID 8840, launcher), conhost.exe (PID 8848, console), DumpIt.exe (PID 10232, memory capture tool)") { $problems.Add("log text: $listText") }
    Add-Result "a: field order, format, merge" $problems -Info $listText

    # =========================================================
    # b. The real process tree: PowerShell started by cmd.exe
    # =========================================================
    # The probe loads the collector's functions, writes what
    # Get-CollectorProcessRecords finds (as the field), and waits until the
    # test has compared it with the live processes
    $probe = Join-Path $caseDir "probe.ps1"
    $probeOut = Join-Path $caseDir "probe out.json"
    $probeRelease = Join-Path $caseDir "probe release.txt"
    $probeText = @'
param([string]$CollectorPath, [string]$Out, [string]$Release)
$ErrorActionPreference = "Stop"
$ast = [System.Management.Automation.Language.Parser]::ParseFile($CollectorPath, [ref]$null, [ref]$null)
function Test-InsideFunction {
    param($Node)
    for ($parent = $Node.Parent; $parent; $parent = $parent.Parent) {
        if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $true }
    }
    return $false
}
$definitions = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
    Where-Object { -not (Test-InsideFunction $_) } | ForEach-Object { $_.Extent.Text })
. ([scriptblock]::Create($definitions -join "`r`n"))
$script:startTime = Get-Date
$script:logToFile = $false
$field = ConvertTo-CollectorProcessField @(Get-CollectorProcessRecords)
[System.IO.File]::WriteAllText("$Out.tmp", (ConvertTo-Json -InputObject $field -Depth 4))
[System.IO.File]::Move("$Out.tmp", $Out)
$deadline = (Get-Date).AddSeconds(60)
while (-not [System.IO.File]::Exists($Release) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 100 }
'@
    [System.IO.File]::WriteAllText($probe, $probeText, [System.Text.Encoding]::ASCII)
    $problems = New-Problems
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = Join-Path $env:SystemRoot "System32\cmd.exe"
    $startInfo.Arguments = '/d /c ""' + $powershellExe + '" -NoProfile -ExecutionPolicy Bypass -File "' + $probe + '" -CollectorPath "' + $collector + '" -Out "' + $probeOut + '" -Release "' + $probeRelease + '""'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $cmd = [System.Diagnostics.Process]::Start($startInfo)
    $cmdPid = $cmd.Id
    try {
        $cmdStartUtc = $cmd.StartTime.ToUniversalTime()
        $deadline = (Get-Date).AddSeconds(60)
        while (-not [System.IO.File]::Exists($probeOut) -and -not $cmd.HasExited -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 100 }
        if (-not [System.IO.File]::Exists($probeOut)) {
            $problems.Add("the probe wrote nothing (cmd.exe exit code: $(if ($cmd.HasExited) { $cmd.ExitCode } else { 'still running' }))")
        } else {
            # (Windows PowerShell 5.1 returns a JSON array as one object:
            # ForEach-Object unrolls it)
            $field = @(ConvertFrom-Json ([System.IO.File]::ReadAllText($probeOut)) | ForEach-Object { $_ })
            $roles = (@($field | ForEach-Object { $_.Role }) -join ",")
            if ($roles -cne "Collector,Launcher,Console") { $problems.Add("roles: $roles") }
            $collectorEntry = @($field | Where-Object { $_.Role -eq "Collector" }) | Select-Object -First 1
            $launcherEntry = @($field | Where-Object { $_.Role -eq "Launcher" }) | Select-Object -First 1
            $consoleEntry = @($field | Where-Object { $_.Role -eq "Console" }) | Select-Object -First 1
            if ($launcherEntry) {
                if ($launcherEntry.Pid -ne $cmd.Id -or $launcherEntry.Name -cne "cmd.exe") { $problems.Add("launcher $($launcherEntry.Name) PID $($launcherEntry.Pid), cmd.exe has PID $($cmd.Id)") }
                $diff = Get-DiffMs (ConvertTo-TestUtc $launcherEntry.StartUtc) $cmdStartUtc
                if ($diff -gt 1) { $problems.Add("launcher start $($launcherEntry.StartUtc), cmd.exe started $($cmdStartUtc.ToString('o'))") }
            }
            if ($collectorEntry) {
                if ($collectorEntry.Name -cne $powershellName -or $collectorEntry.ParentPid -ne $cmd.Id) { $problems.Add("collector $($collectorEntry.Name) parent $($collectorEntry.ParentPid)") }
                try {
                    $live = [System.Diagnostics.Process]::GetProcessById([int]$collectorEntry.Pid)
                    $diff = Get-DiffMs (ConvertTo-TestUtc $collectorEntry.StartUtc) $live.StartTime.ToUniversalTime()
                    if ($diff -gt 1) { $problems.Add("collector start $($collectorEntry.StartUtc) is $diff ms from the process's") }
                    $live.Dispose()
                } catch { $problems.Add("collector PID $($collectorEntry.Pid) not running: $($_.Exception.Message)") }
            }
            if ($consoleEntry) {
                $wmi = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$([int]$consoleEntry.Pid)"
                if ($consoleEntry.Name -cne "conhost.exe" -or $consoleEntry.ParentPid -ne $cmd.Id -or -not $wmi -or $wmi.ParentProcessId -ne $cmd.Id) { $problems.Add("console $($consoleEntry.Name) PID $($consoleEntry.Pid) parent $($consoleEntry.ParentPid)") }
                try {
                    $live = [System.Diagnostics.Process]::GetProcessById([int]$consoleEntry.Pid)
                    $diff = Get-DiffMs (ConvertTo-TestUtc $consoleEntry.StartUtc) $live.StartTime.ToUniversalTime()
                    if ($diff -gt 1) { $problems.Add("console start $($consoleEntry.StartUtc) is $diff ms from the process's") }
                    $live.Dispose()
                } catch { $problems.Add("console PID $($consoleEntry.Pid) not running: $($_.Exception.Message)") }
            }
            Test-StartUtcText -Raw ([System.IO.File]::ReadAllText($probeOut)) -Expected 3 -Problems $problems
        }
    } finally {
        [System.IO.File]::WriteAllText($probeRelease, "done")
        if (-not $cmd.WaitForExit(30000)) { $null = Invoke-NativeTool "taskkill.exe" @("/PID", "$($cmd.Id)", "/T", "/F"); $problems.Add("the probe did not end") }
        $cmd.Dispose()
    }
    Add-Result "b: cmd.exe -> PowerShell: launcher, console, collector" $problems -Info "cmd.exe PID $cmdPid"

    # =========================================================
    # c. Invoke-MemoryCaptureTool with the stand-in
    # =========================================================
    $standIn = Join-Path $caseDir "tool [1]\capture tool.exe"
    New-CaptureStandIn -Path $standIn
    $dumpPath = Join-Path $caseDir "dump [1] x\memory dump.dmp"
    New-Item -ItemType Directory -Path (Split-Path $dumpPath -Parent) -Force | Out-Null
    $toolArgs = @("/TYPE", "DMP", "/OUTPUT", $dumpPath, "/SIZE", "4096", 'say "hi"', 'C:\folder with space\', '', 'a\\"b', "tab`tin")
    $problems = New-Problems
    $capture = Invoke-MemoryCaptureTool -Path $standIn -Arguments $toolArgs
    $report = Get-StandInReport $capture.Output
    if ($capture.Name -cne "capture tool.exe" -or $capture.ExitCode -ne 0 -or $capture.Error) { $problems.Add("name '$($capture.Name)', exit code $($capture.ExitCode), error '$($capture.Error)'") }
    if ($capture.ProcessId -le 0 -or $capture.ProcessId -ne $report.Pid) { $problems.Add("PID $($capture.ProcessId), the tool reports $($report.Pid)") }
    if ($capture.StartTimeUtc -isnot [datetime] -or $capture.StartTimeUtc.Kind -ne [System.DateTimeKind]::Utc) { $problems.Add("start time '$($capture.StartTimeUtc)' is not a UTC time") }
    elseif (-not $report.StartUtc -or (Get-DiffMs $capture.StartTimeUtc $report.StartUtc) -gt 1) { $problems.Add("start $($capture.StartTimeUtc.ToString('o')), the tool reports $($report.StartUtc)") }
    if (($report.Argv -join "|") -cne ($toolArgs -join "|")) { $problems.Add("arguments arrived as: $($report.Argv -join ' | ')") }
    $lines = @($capture.Output)
    if ($lines.Count -lt 4 -or $lines[0] -cne $standInLines[0] -or $lines[-2] -cne $standInEndLines[0] -or $lines[-1] -cne $standInEndLines[1]) { $problems.Add("output: $($lines -join ' | ')") }
    if (@($lines | Where-Object { $_ -eq "    Created file size: 4096 bytes" }).Count -ne 1) { $problems.Add("no 'Created file size' line") }
    if (@($lines | Where-Object { $_.Length -eq 0 }).Count -gt 0) { $problems.Add("empty lines in the output") }
    if ((Get-FileLength $dumpPath) -ne 4096) { $problems.Add("dump file: $(Get-FileLength $dumpPath) bytes") }
    Add-Result "c: the tool's PID, start, output, arguments" $problems -Info "PID $($capture.ProcessId), $($lines.Count) lines"

    $problems = New-Problems
    $thrown = ""
    try { $null = Invoke-MemoryCaptureTool -Path (Join-Path $caseDir "tool [1]\missing tool.exe") -Arguments @("/QUIET") } catch { $thrown = $_.Exception.Message }
    if (-not $thrown) { $problems.Add("a missing tool did not throw") }
    Add-Result "c: a tool that cannot start throws" $problems -Info $thrown

    # A stop while the tool runs (Ctrl+C stops the pipeline the same way):
    # the tool is ended, not left running
    $problems = New-Problems
    $stopWarnings = New-Object System.Collections.Generic.List[string]
    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable("stopWarnings", $stopWarnings)
    $helperText = (@($nodes | Where-Object { -not (Test-InsideFunction $_) -and $_.Name -in @("ConvertTo-NativeArgument", "Invoke-MemoryCaptureTool") } | ForEach-Object { $_.Extent.Text }) -join "`r`n")
    $stopper = [PowerShell]::Create()
    $stopper.Runspace = $runspace
    [void]$stopper.AddScript($helperText + "`r`n" + 'function Log-Warning { param([string]$Message) $stopWarnings.Add($Message) }' + "`r`n" + '$null = Invoke-MemoryCaptureTool -Path $args[0] -Arguments @("/SLEEP", "60000")').AddArgument($standIn)
    $async = $stopper.BeginInvoke()
    $standInPid = 0
    $deadline = (Get-Date).AddSeconds(30)
    while ($standInPid -eq 0 -and (Get-Date) -lt $deadline) {
        $found = @(Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId=$PID AND Name='capture tool.exe'")
        if ($found.Count -gt 0) { $standInPid = [int]$found[0].ProcessId } else { Start-Sleep -Milliseconds 100 }
    }
    if ($standInPid -eq 0) { $problems.Add("the stand-in did not start") }
    else {
        Start-Sleep -Milliseconds 300
        $stopper.Stop()
        $running = $false
        try {
            $left = [System.Diagnostics.Process]::GetProcessById($standInPid)
            $running = -not $left.HasExited
            if ($running) { $left.Kill() }
            $left.Dispose()
        } catch { $running = $false }
        if ($running) { $problems.Add("the stand-in (PID $standInPid) was still running after the stop") }
        if (@($stopWarnings | Where-Object { $_ -like "Memory capture tool stopped (Ctrl+C): capture tool.exe (PID $standInPid) was still running*" }).Count -ne 1) { $problems.Add("warnings: $($stopWarnings -join ' | ')") }
    }
    try { $null = $stopper.EndInvoke($async) } catch { Write-Verbose "The stopped pipeline: $($_.Exception.Message)" }
    $stopper.Dispose()
    $runspace.Dispose()
    Add-Result "c: a stop ends the running tool" $problems -Info ($stopWarnings -join " ")

    # =========================================================
    # d. collection_info.json written twice, a failed rewrite, a
    #    mounted image
    # =========================================================
    $OutputPath = Join-Path $caseDir "TriageCollection_d"
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $logFile = Join-Path $OutputPath "collection_log.txt"
    $manifestFile = Join-Path $OutputPath "collection_manifest.csv"
    [System.IO.File]::WriteAllText($manifestFile, $manifestHeader, (New-Object System.Text.UTF8Encoding($true)))
    $infoPath = Join-Path $OutputPath "collection_info.json"
    $script:IsLive = $true
    $script:TargetRoot = "C:\"
    $script:startTime = Get-Date
    $script:collectorProcesses = New-Object System.Collections.Generic.List[object]
    $script:collectorProcessesRead = $false
    $script:collectionInfoRecorded = $false
    $script:fileCount = 0
    $script:errorCount = 0
    $script:totalBytes = 0
    # The collector's provenance, as the run reads it at its start: both
    # versions of the file carry it
    $script:collectorProvenance = Get-CollectorProvenance -ScriptPath $collector -Version "2099.01.02"
    $collectorSha256 = (Get-FileHash -LiteralPath $collector -Algorithm SHA256).Hash

    $problems = New-Problems
    Write-CollectionInfo 6>$null
    $first = Read-CollectionInfo $infoPath
    $logLines = @(Get-Content -LiteralPath $logFile)
    if (-not $first) { $problems.Add("no collection_info.json") }
    else {
        $entries = @($first.Info.CollectorProcesses)
        if ($entries.Count -lt 1 -or $entries[0].Role -cne "Collector" -or $entries[0].Pid -ne $PID -or $entries[0].Name -cne $powershellName) { $problems.Add("first entry: $($entries[0] | ConvertTo-Json -Compress)") }
        Test-StartUtcText -Raw $first.Raw -Expected $entries.Count -Problems $problems
        Test-InfoManifestRow -Manifest $manifestFile -InfoPath $infoPath -Problems $problems
        $expectedLine = "Collector's own processes recorded in collection_info.json: $powershellName (PID $PID, collector)"
        if (@($logLines | Where-Object { $_.Contains($expectedLine) }).Count -ne 1) { $problems.Add("log: $($logLines -join ' | ')") }
        if ($first.Info.Mode -cne "Live" -or $first.Info.SchemaVersion -ne 1) { $problems.Add("Mode '$($first.Info.Mode)', SchemaVersion $($first.Info.SchemaVersion)") }
        Test-InfoProvenance -Info $first.Info -Version "2099.01.02" -Sha256 $collectorSha256 -Problems $problems
    }
    Add-Result "d: first write: field, manifest row, log" $problems -Info "$(@($first.Info.CollectorProcesses).Count) process(es)"

    $problems = New-Problems
    $captureStart = [datetime]::UtcNow
    Add-CollectorProcessRecord @(@{ Role = "MemoryCapture"; Pid = 4242; Name = "DumpIt.exe"; StartUtc = $captureStart; ParentPid = $PID })
    $countBefore = $script:collectorProcesses.Count
    Add-CollectorProcessRecord @(@{ Role = "MemoryCapture"; Pid = 4242; Name = "DumpIt.exe"; StartUtc = $captureStart.AddMilliseconds(500); ParentPid = $PID })
    if ($script:collectorProcesses.Count -ne $countBefore) { $problems.Add("the same process was added twice") }
    $firstBytes = [System.IO.File]::ReadAllBytes($infoPath)
    Write-CollectionInfo -Added "DumpIt.exe (PID 4242)" -AddedAs "the memory capture tool" 6>$null
    $second = Read-CollectionInfo $infoPath
    $entries = @($second.Info.CollectorProcesses)
    $last = $entries[-1]
    if ($last.Role -cne "MemoryCapture" -or $last.Pid -ne 4242 -or $last.ParentPid -ne $PID -or (Get-DiffMs (ConvertTo-TestUtc $last.StartUtc) $captureStart) -gt 0.001) { $problems.Add("last entry: $($last | ConvertTo-Json -Compress)") }
    if ([System.IO.File]::ReadAllText($infoPath) -eq [System.Text.Encoding]::UTF8.GetString($firstBytes)) { $problems.Add("the file did not change") }
    # The provenance fields stay as they were
    Test-InfoProvenance -Info $second.Info -Version "2099.01.02" -Sha256 $collectorSha256 -Problems $problems
    if ($first -and $second.Info.CollectorGitCommit -cne $first.Info.CollectorGitCommit) { $problems.Add("CollectorGitCommit '$($second.Info.CollectorGitCommit)', first '$($first.Info.CollectorGitCommit)'") }
    Test-InfoManifestRow -Manifest $manifestFile -InfoPath $infoPath -Problems $problems
    $sizes = @(Import-Csv -LiteralPath $manifestFile | ForEach-Object { [long]$_.SizeBytes })
    if ($script:totalBytes -ne ($sizes | Measure-Object -Sum).Sum -or $script:fileCount -ne $sizes.Count) { $problems.Add("counters: $($script:fileCount) file(s), $($script:totalBytes) bytes; manifest $($sizes.Count) row(s)") }
    $logLines = @(Get-Content -LiteralPath $logFile)
    if (@($logLines | Where-Object { $_ -match 'collection_info\.json updated: DumpIt\.exe \(PID 4242\) recorded as the memory capture tool$' }).Count -ne 1) { $problems.Add("log: $($logLines -join ' | ')") }
    if (@($logLines | Where-Object { $_ -match 'WARNING|ERROR' }).Count -gt 0 -or $script:errorCount -ne 0) { $problems.Add("warnings or errors: $($logLines -join ' | ')") }
    Add-Result "d: second write: the row follows it, provenance kept" $problems -Info "$($entries.Count) process(es)"

    # The rewrite fails (the file is open, so it cannot be replaced): the
    # second version stays, whole, with its manifest row; a warning, no error
    $problems = New-Problems
    $before = [System.IO.File]::ReadAllBytes($infoPath)
    $manifestBefore = [System.IO.File]::ReadAllText($manifestFile)
    Add-CollectorProcessRecord @(@{ Role = "MemoryCapture"; Pid = 4343; Name = "WinPmem.exe"; StartUtc = [datetime]::UtcNow; ParentPid = $PID })
    $lock = [System.IO.File]::Open($infoPath, "Open", "Read", "Read")
    try { Write-CollectionInfo -Added "WinPmem.exe (PID 4343)" -AddedAs "the memory capture tool" 6>$null }
    finally { $lock.Dispose() }
    $after = [System.IO.File]::ReadAllBytes($infoPath)
    if ([Convert]::ToBase64String($after) -cne [Convert]::ToBase64String($before)) { $problems.Add("the file changed") }
    if ([System.IO.File]::ReadAllText($manifestFile) -cne $manifestBefore) { $problems.Add("the manifest changed") }
    Test-InfoManifestRow -Manifest $manifestFile -InfoPath $infoPath -Problems $problems
    $logLines = @(Get-Content -LiteralPath $logFile)
    $warning = @($logLines | Where-Object { $_ -match 'WARNING: collection_info\.json not updated \(.+\): WinPmem\.exe \(PID 4343\) is not recorded as the memory capture tool, so the timeline builder''s report can show it as a lead\. The version written at the start of the run is kept\.$' })
    if ($warning.Count -ne 1) { $problems.Add("log: $($logLines[-1])") }
    if ($script:errorCount -ne 0) { $problems.Add("error count $($script:errorCount)") }
    Add-Result "d: a failed rewrite keeps the file and its row" $problems

    # A mounted image: no CollectorProcesses (its PIDs are not the image's)
    $problems = New-Problems
    $OutputPath = Join-Path $caseDir "TriageCollection_mounted"
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $logFile = Join-Path $OutputPath "collection_log.txt"
    $manifestFile = Join-Path $OutputPath "collection_manifest.csv"
    [System.IO.File]::WriteAllText($manifestFile, $manifestHeader, (New-Object System.Text.UTF8Encoding($true)))
    $script:IsLive = $false
    $script:TargetRoot = (Join-Path $caseDir "image") + "\"
    $script:collectionInfoRecorded = $false
    New-Item -ItemType Directory -Path $script:TargetRoot -Force | Out-Null
    Write-CollectionInfo 6>$null
    $mounted = Read-CollectionInfo (Join-Path $OutputPath "collection_info.json")
    if (-not $mounted -or $mounted.Info.Mode -cne "MountedImage" -or $mounted.Info.PSObject.Properties["CollectorProcesses"] -or $mounted.Raw.Contains("CollectorProcesses")) { $problems.Add("collection_info.json: $($mounted.Raw)") }
    Add-Result "d: mounted image: no CollectorProcesses" $problems

    # =========================================================
    # e. The memory section in the collector's code
    # =========================================================
    $problems = New-Problems
    $commandsOutside = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | Where-Object { -not (Test-InsideFunction $_) })
    $sections = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$Categories -contains "Memory"' }, $true) | Where-Object { -not (Test-InsideFunction $_) })
    $allowed = $null
    if ($sections.Count -eq 1) {
        $allowed = $sections[0].Find({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$memCaptureAllowed' }, $true)
    }
    if (-not $allowed) { $problems.Add("memory section ($($sections.Count)) or its 'if (`$memCaptureAllowed)' block not found") }
    else {
        $statements = @($allowed.Clauses[0].Item2.Statements)
        function Find-StatementIndex {
            param([object[]]$Statements, [scriptblock]$Test)
            for ($k = 0; $k -lt $Statements.Count; $k++) {
                if ($Statements[$k].Find($Test, $true)) { return $k }
            }
            return -1
        }
        $snapshotIndex = Find-StatementIndex $statements { param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq "Get-CollectorProcessRecords" }
        $tryIndex = -1
        for ($k = 0; $k -lt $statements.Count; $k++) {
            if ($statements[$k] -is [System.Management.Automation.Language.TryStatementAst] -and $statements[$k].Body.Find({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq "Invoke-MemoryCaptureTool" }, $true)) { $tryIndex = $k }
        }
        $updateIndex = Find-StatementIndex $statements { param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq "Write-CollectionInfo" -and @($node.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq "Added" }).Count -eq 1 }
        if ($tryIndex -lt 0) { $problems.Add("no try block runs Invoke-MemoryCaptureTool") }
        if ($snapshotIndex -lt 0 -or $snapshotIndex -ge $tryIndex) { $problems.Add("the process list (Get-CollectorProcessRecords, statement $snapshotIndex) is not read before the capture (statement $tryIndex)") }
        if ($updateIndex -le $tryIndex) { $problems.Add("collection_info.json is not written again after the capture (Write-CollectionInfo -Added: statement $updateIndex, capture: $tryIndex)") }
        if ($tryIndex -ge 0) {
            $body = @($statements[$tryIndex].Body.Statements)
            $toolIndex = Find-StatementIndex $body { param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq "Invoke-MemoryCaptureTool" }
            $recordIndex = Find-StatementIndex $body { param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq "Add-CollectorProcessRecord" -and $node.Extent.Text.Contains('"MemoryCapture"') -and $node.Extent.Text.Contains('$capture.ProcessId') }
            $saveIndex = Find-StatementIndex $body { param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq "Save-MemoryAcquisitionLog" }
            if ($recordIndex -le $toolIndex -or $recordIndex -ge $saveIndex) { $problems.Add("the capture tool's record (statement $recordIndex) is not added right after the tool runs ($toolIndex), before its log is saved ($saveIndex)") }
            $toolCalls = @($statements[$tryIndex].Body.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq "Invoke-MemoryCaptureTool" }, $true))
            foreach ($call in $toolCalls) {
                if ($call.Extent.Text -notmatch '^Invoke-MemoryCaptureTool -Path \$memTool -Arguments ' -or $call.Parent.Parent -isnot [System.Management.Automation.Language.AssignmentStatementAst] -or $call.Parent.Parent.Left.Extent.Text -ne '$capture') { $problems.Add("line $($call.Extent.StartLineNumber): $($call.Parent.Extent.Text)") }
            }
            if ($toolCalls.Count -ne 3) { $problems.Add("$($toolCalls.Count) Invoke-MemoryCaptureTool calls, expected 3 (DumpIt, WinPmem, Magnet RAM Capture)") }
        }
    }
    $ampersand = @($commandsOutside | Where-Object { $_.InvocationOperator -eq "Ampersand" -and $_.CommandElements[0].Extent.Text -eq '$memTool' })
    foreach ($call in $ampersand) { $problems.Add("line $($call.Extent.StartLineNumber) still runs the tool with &") }
    $firstWrites = @($commandsOutside | Where-Object { $_.GetCommandName() -eq "Write-CollectionInfo" -and $_.CommandElements.Count -eq 1 })
    if ($firstWrites.Count -ne 1 -or ($sections.Count -eq 1 -and $firstWrites[0].Extent.StartOffset -gt $sections[0].Extent.StartOffset)) { $problems.Add("$($firstWrites.Count) first Write-CollectionInfo call(s), expected 1 before the memory section") }
    Add-Result "e: memory section order" $problems

    # =========================================================
    # f. End to end: the collector run through cmd.exe
    # =========================================================
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $CollectorPath -and -not $isAdmin) {
        $problems = New-Problems
        $problems.Add("Administrator rights are required for the collector runs. Run elevated, or pass -CollectorPath with a collector copy without the admin check.")
        Add-Result "f: end-to-end runs" $problems
    } else {
        $e2eDir = Join-Path $workDir "end to end"
        $machine = Get-NativeMachineType
        $archFolder = switch ($machine) { 0x8664 { "x64" } 0xAA64 { "ARM64" } 0x14C { "x86" } default { "" } }
        # Collector copies: with the stand-in as DumpIt, with no tool, and
        # with a DumpIt.exe that cannot start (a cut-off copy of the
        # stand-in: its header names this processor, the rest is missing).
        # Each copy reports a RAM of 1 MB
        $copyText = [System.IO.File]::ReadAllText($collector)
        $ramFunction = 'function Get-PhysicalMemoryBytes {'
        if (([regex]::Matches($copyText, [regex]::Escape($ramFunction))).Count -ne 1) { throw "Get-PhysicalMemoryBytes not found once in $collector" }
        $copyText = $copyText.Replace($ramFunction, "function Get-PhysicalMemoryBytes { return [long]1MB }`r`nfunction Get-PhysicalMemoryBytesOfThisMachine {")
        $copies = @{}
        foreach ($kind in @("standin", "notool", "broken")) {
            $copyDir = Join-Path $e2eDir "collector $kind"
            New-Item -ItemType Directory -Path $copyDir -Force | Out-Null
            $copies[$kind] = Join-Path $copyDir "triage-collector.ps1"
            [System.IO.File]::WriteAllText($copies[$kind], $copyText, (New-Object System.Text.UTF8Encoding($true)))
        }
        $dumpItPath = Join-Path $e2eDir "collector standin\tools\dumpit\$archFolder\DumpIt.exe"
        New-CaptureStandIn -Path $dumpItPath
        $brokenPath = Join-Path $e2eDir "collector broken\tools\dumpit\$archFolder\DumpIt.exe"
        New-Item -ItemType Directory -Path (Split-Path $brokenPath -Parent) -Force | Out-Null
        $standInBytes = [System.IO.File]::ReadAllBytes($dumpItPath)
        [System.IO.File]::WriteAllBytes($brokenPath, [byte[]]$standInBytes[0..1023])

        # Runs a collector copy as Run-TriageCollector.bat's elevated cmd.exe
        # does (cmd.exe /d /c ""powershell.exe" -File ..."), in a console of
        # its own with no window, with -Unattended -NoCompress; returns what
        # it left
        function Invoke-CollectorRun {
            param([string]$Name, [string]$Copy, [string[]]$Arguments)
            $out = Join-Path $e2eDir "$Name\TriageCollection_test"
            $argumentText = (@(@("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Copy) + $Arguments + @("-Unattended", "-NoCompress", "-OutputPath", $out)) | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' '
            $runInfo = New-Object System.Diagnostics.ProcessStartInfo
            $runInfo.FileName = Join-Path $env:SystemRoot "System32\cmd.exe"
            $runInfo.Arguments = '/d /c ""' + $powershellExe + '" ' + $argumentText + '"'
            $runInfo.UseShellExecute = $false
            $runInfo.CreateNoWindow = $true
            $runInfo.RedirectStandardOutput = $true
            $runInfo.RedirectStandardError = $true
            $run = [System.Diagnostics.Process]::Start($runInfo)
            $runStartUtc = $run.StartTime.ToUniversalTime()
            $stdoutTask = $run.StandardOutput.ReadToEndAsync()
            $stderrTask = $run.StandardError.ReadToEndAsync()
            if (-not $run.WaitForExit(600000)) { $null = Invoke-NativeTool "taskkill.exe" @("/PID", "$($run.Id)", "/T", "/F") }
            $run.WaitForExit()
            $runLog = Join-Path $out "collection_log.txt"
            $acquisitionLog = Join-Path $out "Memory\memory_acquisition_log.txt"
            $result = [PSCustomObject]@{
                CmdPid      = $run.Id
                CmdStartUtc = $runStartUtc
                Screen      = $stdoutTask.Result + $stderrTask.Result
                Out         = $out
                InfoPath    = Join-Path $out "collection_info.json"
                Info        = Read-CollectionInfo (Join-Path $out "collection_info.json")
                Log         = @(if ([System.IO.File]::Exists($runLog)) { Get-Content -LiteralPath $runLog })
                Acquisition = @(if ([System.IO.File]::Exists($acquisitionLog)) { Get-Content -LiteralPath $acquisitionLog -Encoding UTF8 })
                Manifest    = Join-Path $out "collection_manifest.csv"
            }
            $run.Dispose()
            return $result
        }
        # The process records of a live run: the collector, started by the
        # cmd.exe the test started (the launcher), its console, then the
        # roles expected after them. Child entries may come before those:
        # in PowerShell 7 the Defender cmdlets run in a Windows PowerShell
        # process the collector starts (the compatibility session); each
        # must be the collector's child, started during the run
        function Test-LiveRun {
            param([object]$Run, [string[]]$Roles, [System.Collections.Generic.List[string]]$Problems)
            if (-not $Run.Info) {
                $Problems.Add("no collection_info.json")
                foreach ($line in ($Run.Screen -split "`r?`n" | Select-Object -Last 15)) { Write-Verbose "  | $line" -Verbose }
                return $null
            }
            $entries = @($Run.Info.Info.CollectorProcesses)
            $roleText = (@($entries | Where-Object { $_.Role -ne "Child" } | ForEach-Object { $_.Role }) -join ",")
            $allRoles = (@($entries | ForEach-Object { $_.Role }) -join ",")
            if ($roleText -cne ($Roles -join ",") -or $allRoles -notmatch '^Collector,Launcher,Console(,Child)*(,MemoryCapture)?$') { $Problems.Add("roles: $allRoles") }
            $byRole = @{}
            foreach ($entry in $entries) { if (-not $byRole.ContainsKey($entry.Role)) { $byRole[$entry.Role] = $entry } }
            $collectorEntry = $byRole["Collector"]
            $launcherEntry = $byRole["Launcher"]
            $consoleEntry = $byRole["Console"]
            foreach ($child in @($entries | Where-Object { $_.Role -eq "Child" })) {
                if (-not $collectorEntry -or $child.ParentPid -ne $collectorEntry.Pid -or (ConvertTo-TestUtc $child.StartUtc) -lt (ConvertTo-TestUtc $Run.Info.Info.CollectionStartUtc)) { $Problems.Add("child $($child.Name) PID $($child.Pid), parent $($child.ParentPid), started $($child.StartUtc)") }
            }
            if ($collectorEntry -and ($collectorEntry.Name -cne $powershellName -or $collectorEntry.ParentPid -ne $Run.CmdPid)) { $Problems.Add("collector $($collectorEntry.Name), parent PID $($collectorEntry.ParentPid) (cmd.exe: $($Run.CmdPid))") }
            if ($launcherEntry -and ($launcherEntry.Pid -ne $Run.CmdPid -or $launcherEntry.Name -cne "cmd.exe" -or (Get-DiffMs (ConvertTo-TestUtc $launcherEntry.StartUtc) $Run.CmdStartUtc) -gt 1)) { $Problems.Add("launcher $($launcherEntry.Name) PID $($launcherEntry.Pid) started $($launcherEntry.StartUtc); cmd.exe PID $($Run.CmdPid) started $($Run.CmdStartUtc.ToString('o'))") }
            if ($consoleEntry -and ($consoleEntry.Name -cne "conhost.exe" -or $consoleEntry.ParentPid -ne $Run.CmdPid)) { $Problems.Add("console $($consoleEntry.Name), parent PID $($consoleEntry.ParentPid)") }
            # Start order: launcher, console, collector, the run's start
            if ($launcherEntry -and $consoleEntry -and $collectorEntry) {
                $runStart = ConvertTo-TestUtc $Run.Info.Info.CollectionStartUtc
                $order = @((ConvertTo-TestUtc $launcherEntry.StartUtc), (ConvertTo-TestUtc $consoleEntry.StartUtc), (ConvertTo-TestUtc $collectorEntry.StartUtc), $runStart)
                for ($k = 1; $k -lt $order.Count; $k++) {
                    if ($order[$k] -lt $order[$k - 1]) { $Problems.Add("start times out of order: $(($order | ForEach-Object { $_.ToString('o') }) -join ' ')"); break }
                }
            }
            Test-StartUtcText -Raw $Run.Info.Raw -Expected $entries.Count -Problems $Problems
            Test-InfoManifestRow -Manifest $Run.Manifest -InfoPath $Run.InfoPath -Problems $Problems
            if ($collectorEntry -and $launcherEntry -and $consoleEntry) {
                $line = "Collector's own processes recorded in collection_info.json: $powershellName (PID $($collectorEntry.Pid), collector), cmd.exe (PID $($launcherEntry.Pid), launcher), conhost.exe (PID $($consoleEntry.Pid), console)"
                if (@($Run.Log | Where-Object { $_.Contains($line) }).Count -ne 1) { $Problems.Add("log line '$line' missing") }
            }
            return $byRole
        }

        # f1. A capture with the stand-in: the capture tool's process is
        # added. The stand-in prints a "SHA-256:" line as DumpIt does, with
        # the SHA-256 of the dump it writes (1 MB + 8 KB of zeros): the
        # collector reads it from the output Invoke-MemoryCaptureTool
        # returns and compares it with its own hash of the dump
        $problems = New-Problems
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        try { $standInDumpSha = ([System.BitConverter]::ToString($hasher.ComputeHash((New-Object byte[] 1056768)))).Replace("-", "") }
        finally { $hasher.Dispose() }
        $env:TRIAGE_TEST_STANDIN_SHA256 = $standInDumpSha
        try { $run = Invoke-CollectorRun -Name "capture" -Copy $copies["standin"] -Arguments @("-Categories", "Memory") }
        finally { Remove-Item -Path Env:\TRIAGE_TEST_STANDIN_SHA256 -ErrorAction SilentlyContinue }
        $byRole = Test-LiveRun -Run $run -Roles @("Collector", "Launcher", "Console", "MemoryCapture") -Problems $problems
        # The file written again after the capture keeps the provenance
        # fields: the version the log names and the SHA-256 of the copy
        # that ran
        if ($run.Info) {
            $versionLines = @($run.Log | Where-Object { $_ -match '\] Collector: version \S+, triage-collector\.ps1 SHA-256 [0-9A-F]{64}$' })
            $loggedVersion = ""
            if ($versionLines.Count -eq 1 -and $versionLines[0] -match '\] Collector: version (\S+), ') { $loggedVersion = $Matches[1] }
            if (-not $loggedVersion) { $problems.Add("provenance log line(s): $($versionLines -join ' | ')") }
            Test-InfoProvenance -Info $run.Info.Info -Version $loggedVersion -Sha256 (Get-FileHash -LiteralPath $copies["standin"] -Algorithm SHA256).Hash -Problems $problems
        }
        $hashLines = @($run.Log | Where-Object { $_ -match 'Memory dump SHA-256' })
        if ($hashLines.Count -ne 1 -or -not $hashLines[0].EndsWith("] Memory dump SHA-256 check: match -- the collector's SHA-256 of the dump equals the one DumpIt printed ($standInDumpSha)")) { $problems.Add("SHA-256 line(s): $($hashLines -join ' | ')") }
        $dumpRows = @(if ([System.IO.File]::Exists($run.Manifest)) { Import-Csv -LiteralPath $run.Manifest | Where-Object { $_.SourcePath -eq "(memory dump via DumpIt)" } })
        if ($dumpRows.Count -ne 1 -or $dumpRows[0].SHA256 -cne $standInDumpSha) { $problems.Add("memory dump manifest row(s): $(@($dumpRows | ForEach-Object { $_.SHA256 }) -join ', ')") }
        if ($byRole -and $byRole["MemoryCapture"]) {
            $memoryEntry = $byRole["MemoryCapture"]
            $report = Get-StandInReport $run.Acquisition
            if ($memoryEntry.Name -cne "DumpIt.exe" -or $memoryEntry.Pid -ne $report.Pid -or $memoryEntry.ParentPid -ne $byRole["Collector"].Pid) { $problems.Add("memory capture $($memoryEntry.Name) PID $($memoryEntry.Pid) parent $($memoryEntry.ParentPid); the stand-in reports PID $($report.Pid)") }
            if (-not $report.StartUtc -or (Get-DiffMs (ConvertTo-TestUtc $memoryEntry.StartUtc) $report.StartUtc) -gt 1) { $problems.Add("memory capture start $($memoryEntry.StartUtc), the stand-in reports $($report.StartUtc)") }
            if ((ConvertTo-TestUtc $memoryEntry.StartUtc) -lt (ConvertTo-TestUtc $run.Info.Info.CollectionStartUtc)) { $problems.Add("the capture tool started before the run") }
            if (@($run.Log | Where-Object { $_ -match "collection_info\.json updated: DumpIt\.exe \(PID $($report.Pid)\) recorded as the memory capture tool$" }).Count -ne 1) { $problems.Add("no 'collection_info.json updated' log line") }
            if (@($run.Log | Where-Object { $_ -match 'OK: Memory dump captured: ' }).Count -ne 1) { $problems.Add("the dump was not captured: $(@($run.Log | Where-Object { $_ -match 'Memory' }) -join ' | ')") }
            if ($run.Acquisition.Count -lt 2 -or $run.Acquisition[-1] -cne $standInEndLines[1] -or $run.Acquisition[-2] -cne $standInEndLines[0]) { $problems.Add("acquisition log: $($run.Acquisition -join ' | ')") }
        }
        Add-Result "f: capture: processes, DumpIt's SHA-256, provenance" $problems -Info $(if ($byRole) { "PIDs " + (@($byRole.Values | Sort-Object { $_.Pid } | ForEach-Object { "$($_.Role) $($_.Pid)" }) -join ", ") })

        # f2. Memory not chosen (-Unattended without Memory, as "No" at the
        # prompt): no capture tool, no second write
        $problems = New-Problems
        $run = Invoke-CollectorRun -Name "declined" -Copy $copies["standin"] -Arguments @("-Categories", "USB")
        $null = Test-LiveRun -Run $run -Roles @("Collector", "Launcher", "Console") -Problems $problems
        if (@($run.Log | Where-Object { $_ -match 'collection_info\.json updated|Capturing memory' }).Count -gt 0) { $problems.Add("memory was captured") }
        Add-Result "f: memory not chosen: no capture tool" $problems

        # f3. No capture tool in tools\
        $problems = New-Problems
        $run = Invoke-CollectorRun -Name "notool" -Copy $copies["notool"] -Arguments @("-Categories", "Memory")
        $null = Test-LiveRun -Run $run -Roles @("Collector", "Launcher", "Console") -Problems $problems
        if (@($run.Log | Where-Object { $_ -match 'WARNING: Memory capture: no tool found' }).Count -ne 1) { $problems.Add("no 'no tool found' warning") }
        if (@($run.Log | Where-Object { $_ -match 'collection_info\.json updated' }).Count -gt 0) { $problems.Add("collection_info.json was updated") }
        Add-Result "f: no capture tool: no capture tool recorded" $problems

        # f4. A capture tool that cannot start: an error, nothing recorded
        $problems = New-Problems
        $run = Invoke-CollectorRun -Name "broken" -Copy $copies["broken"] -Arguments @("-Categories", "Memory")
        $null = Test-LiveRun -Run $run -Roles @("Collector", "Launcher", "Console") -Problems $problems
        if (@($run.Log | Where-Object { $_ -match 'ERROR: Memory capture failed: ' }).Count -ne 1) { $problems.Add("no 'Memory capture failed' error: $(@($run.Log | Where-Object { $_ -match 'Memory' }) -join ' | ')") }
        if (@($run.Log | Where-Object { $_ -match 'collection_info\.json updated' }).Count -gt 0) { $problems.Add("collection_info.json was updated") }
        Add-Result "f: a tool that cannot start: nothing recorded" $problems

        # f5. A mounted image (a folder mapped to a drive letter with subst):
        # no CollectorProcesses, no capture
        $problems = New-Problems
        $imageDir = Join-Path $e2eDir "image"
        New-Item -ItemType Directory -Path (Join-Path $imageDir "Windows\System32") -Force | Out-Null
        $used = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
        $script:substLetter = @("T", "S", "R", "Q", "P", "O", "N", "M", "L", "K", "J", "I", "H") | Where-Object { $used -notcontains $_ } | Select-Object -First 1
        if (-not $script:substLetter -or (Invoke-NativeTool "subst.exe" @("$($script:substLetter):", $imageDir)) -ne 0) {
            $script:substLetter = $null
            $problems.Add("subst could not map the test image to a drive letter")
        } else {
            $run = Invoke-CollectorRun -Name "mounted" -Copy $copies["standin"] -Arguments @("-TargetDrive", $script:substLetter, "-Categories", "Memory")
            if (-not $run.Info -or $run.Info.Info.Mode -cne "MountedImage" -or $run.Info.Info.PSObject.Properties["CollectorProcesses"] -or $run.Info.Raw.Contains("CollectorProcesses")) { $problems.Add("collection_info.json: $(if ($run.Info) { $run.Info.Raw } else { 'none' })") }
            if (@($run.Log | Where-Object { $_ -match 'Skipping Memory capture \(mounted image' }).Count -ne 1) { $problems.Add("memory capture not skipped") }
            if ($run.Info) { Test-InfoManifestRow -Manifest $run.Manifest -InfoPath $run.InfoPath -Problems $problems }
        }
        Add-Result "f: mounted image: no CollectorProcesses" $problems
    }
}
catch {
    $failures++
    Write-Host "FAIL: test setup or run error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    if ($script:substLetter) { $null = Invoke-NativeTool "subst.exe" @("$($script:substLetter):", "/d") }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
foreach ($r in $results) {
    $color = if ($r.Result -eq "PASS") { "Green" } else { "Red" }
    $line = "  {0}  {1}" -f $r.Result, $r.Case
    if ($r.Note) { $line = "  {0}  {1,-52} -- {2}" -f $r.Result, $r.Case, $r.Note }
    Write-Host $line -ForegroundColor $color
    if ($r.Result -ne "PASS" -and $env:GITHUB_ACTIONS) {
        Write-Host "::error file=tests/Test-CollectorProcesses.ps1::$($r.Case): $($r.Note)"
    }
}
if ($failures -gt 0 -or $results.Count -eq 0) {
    Write-Host "FAIL: $failures check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: $($results.Count) check(s)" -ForegroundColor Green
exit 0

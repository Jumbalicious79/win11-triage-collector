# =============================================================
# Memory capture free space test
# Checks how the collector (triage-collector.ps1) makes sure a memory dump
# fits before it is captured, and how it checks the result, without
# capturing anything:
#   - the space check (Get-MemoryCaptureSpaceCheck) with run 2's numbers
#     and the other cases: reserve on the system drive, another drive,
#     FAT32, -MinFreeSpaceGB, unknown free space or RAM, the collection's
#     share, and the log line it gives;
#   - Get-VolumeSpace on the temp folder's drive, a UNC path and a missing
#     drive;
#   - the prompt (run with stand-ins for the drives and the answers): the
#     numbers, the warning about the system drive, other drives offered;
#   - the result check (Get-MemoryCaptureResult) on a redacted DumpIt log
#     (fixtures\memory) and a failing variant;
#   - the memory section, run with a stand-in capture tool: no room (an
#     error, no capture), low reserve (a warning, capture), a complete dump
#     (recorded), a failed, empty or missing one (an error; set aside out of
#     the collection or deleted), -MemoryOutputPath;
#   - the summary and compression step with a dump: moved next to the zip,
#     kept with the folder (no zip) when it cannot be moved, left where
#     -MemoryOutputPath put it.
# No admin rights needed. Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemorySpaceCheck.ps1
# =============================================================
param(
    # Collector script to test (default: the repository's triage-collector.ps1)
    [string]$CollectorPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$collector = $CollectorPath
if (-not $collector) { $collector = Join-Path $repoRoot "triage-collector.ps1" }
$fixtureDir = Join-Path $PSScriptRoot "fixtures\memory"

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
foreach ($name in @("Get-VolumeSpace", "Get-MemoryCaptureSpaceCheck", "Format-SpaceCheck", "Get-TriageSpaceCheck", "Get-MemoryDumpPath", "Get-MemoryCaptureChoices", "Get-MemoryCaptureResult", "Move-IncompleteMemoryDump")) {
    if (-not (Get-Command $name -CommandType Function -ErrorAction SilentlyContinue)) {
        Write-Host "FAIL: $name not found in $collector" -ForegroundColor Red
        exit 1
    }
}

# Collector code run as it is: the memory prompt (top level), the memory
# section (in the main try block) and the summary and compression steps at
# the end (up to the final "Press any key")
$topStatements = @($ast.EndBlock.Statements)
$promptStatement = @($topStatements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Clauses[0].Item1.Extent.Text -eq '$script:IsLive -and ($Categories -notcontains "Memory")' })
$sectionStatement = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$Categories -contains "Memory"' }, $true) |
    Where-Object { -not (Test-InsideFunction $_) })
$firstFinal = -1
$lastFinal = -1
for ($i = 0; $i -lt $topStatements.Count; $i++) {
    if ($firstFinal -lt 0 -and $topStatements[$i].Extent.Text -like '$endTime = Get-Date*') { $firstFinal = $i }
    if ($topStatements[$i].Extent.Text -like '*RawUI.ReadKey*') { $lastFinal = $i }
}
if ($promptStatement.Count -ne 1 -or $sectionStatement.Count -ne 1 -or $firstFinal -lt 0 -or $lastFinal -le $firstFinal) {
    Write-Host "FAIL: collector code not found (prompt: $($promptStatement.Count), memory section: $($sectionStatement.Count), summary: $firstFinal..$lastFinal)" -ForegroundColor Red
    exit 1
}
$promptBlock = [scriptblock]::Create($promptStatement[0].Extent.Text)
$sectionBlock = [scriptblock]::Create($sectionStatement[0].Extent.Text)
$finalBlock = [scriptblock]::Create((@($topStatements[$firstFinal..($lastFinal - 1)] | ForEach-Object { $_.Extent.Text }) -join "`r`n"))

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

# A volume as Get-VolumeSpace returns it
function New-TestVolume {
    param([string]$Root, [double]$FreeGB, [double]$TotalGB, [string]$FileSystem = "NTFS")
    return [PSCustomObject]@{ Root = $Root; FreeBytes = [long]($FreeGB * 1GB); TotalBytes = [long]($TotalGB * 1GB); FileSystem = $FileSystem }
}

# Text as it reads back from collection_log.txt: Log writes with
# Add-Content (ANSI in Windows PowerShell 5.1, UTF-8 in 7)
function ConvertTo-LogText {
    param([string]$Text)
    return [System.Text.Encoding]::Default.GetString([System.Text.Encoding]::Default.GetBytes($Text))
}

# Lines (regexes) that must appear in order in a list of lines
function Test-LinesInOrder {
    param([string[]]$Lines, [string[]]$Expected, [System.Collections.Generic.List[string]]$Problems, [string]$Where)
    $next = 0
    foreach ($pattern in $Expected) {
        $found = -1
        for ($j = $next; $j -lt $Lines.Count; $j++) {
            if ($Lines[$j] -match $pattern) { $found = $j; break }
        }
        if ($found -lt 0) { $Problems.Add("$Where has no line /$pattern/ (in order)"); continue }
        $next = $found + 1
    }
}

$ram2 = [long]34261106688   # run 2: the RAM (DumpIt's dump was this + 8 KB)
$testId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) "TriageMemorySpaceTest_$testId [x]"
$savedSystemDrive = $env:SystemDrive

try {
    # =========================================================
    # 1. The space check with fixed numbers
    # =========================================================
    $c487 = New-TestVolume "C:\" 40.8 487.41
    $spaceCases = @(
        @{ What = "run 2: C:, 40.8 GB free -> LowReserve"; Volume = $c487; System = $true; With = $true
           Result = "LowReserve"; Dump = $ram2 + 1MB; Collection = 5GB; Reserve = 20GB
           Reason = '^C:\\ would be left with ~3\.9 GB free, less than the 20 GB to keep free on the system drive$' }
        @{ What = "C: at 2.6 GB free -> NoFit"; Volume = (New-TestVolume "C:\" 2.6 487.41); System = $true; With = $true
           Result = "NoFit"; Reason = '^less than 1 GB would be left free on C:\\$' }
        @{ What = "D: at 453 GB free -> Ok"; Volume = (New-TestVolume "D:\" 453 1400)
           Result = "Ok"; Dump = $ram2 + 1MB; Collection = 0; Reserve = 1GB }
        @{ What = "FAT32 stick, 16 GB RAM -> NoFit"; Volume = (New-TestVolume "E:\" 60 64 "FAT32"); Ram = 16GB; With = $true
           Result = "NoFit"; Reason = '^E:\\ is FAT32, which cannot hold a file of 4 GB or more$' }
        @{ What = "FAT32 stick, 2 GB RAM -> Ok"; Volume = (New-TestVolume "E:\" 60 64 "FAT32"); Ram = 2GB; With = $true
           Result = "Ok" }
        @{ What = "exFAT stick, 16 GB RAM -> Ok"; Volume = (New-TestVolume "E:\" 60 64 "exFAT"); Ram = 16GB; With = $true
           Result = "Ok" }
        @{ What = "-MinFreeSpaceGB 0, 40.8 GB free -> Ok"; Volume = $c487; System = $true; With = $true; Min = 0
           Result = "Ok"; Reserve = 0 }
        @{ What = "-MinFreeSpaceGB 50 on the system drive"; Volume = (New-TestVolume "C:\" 80 487.41); System = $true; With = $true; Min = 50
           Result = "LowReserve"; Reserve = 50GB }
        @{ What = "-MinFreeSpaceGB is for the system drive only"; Volume = (New-TestVolume "D:\" 453 1400); Min = 500
           Result = "Ok"; Reserve = 1GB }
        @{ What = "unknown volume -> Unknown"; Volume = $null; System = $true; With = $true
           Result = "Unknown"; Reason = '^the free space could not be read$' }
        @{ What = "unknown RAM -> Unknown"; Volume = $c487; Ram = 0; System = $true
           Result = "Unknown"; Dump = -1; Reason = '^the size of the RAM could not be read$' }
        @{ What = "reserve at least 4 GB (30 GB volume)"; Volume = (New-TestVolume "C:\" 20 30); Ram = 1GB; System = $true
           Result = "Ok"; Reserve = 4GB }
        @{ What = "reserve 10% of the volume (100 GB)"; Volume = (New-TestVolume "C:\" 20 100); Ram = 1GB; System = $true
           Result = "Ok"; Reserve = 10GB }
        @{ What = "WinPmem raw image: RAM x 1.05"; Volume = (New-TestVolume "D:\" 453 1400); Tool = "WinPmem"
           Result = "Ok"; Dump = [long][math]::Ceiling($ram2 * 1.05) }
        @{ What = "collection with -SkipLargeFiles: 1 GB x 1.25"; Volume = (New-TestVolume "D:\" 453 1400); With = $true; Large = $false
           Result = "Ok"; Collection = [long](1GB * 1.25) }
        @{ What = "collection with -NoCompress: 4 GB"; Volume = (New-TestVolume "D:\" 453 1400); With = $true; Compress = $false
           Result = "Ok"; Collection = 4GB }
        @{ What = "collection alone (-NoDump)"; Volume = (New-TestVolume "C:\" 40.8 487.41); System = $true; With = $true; NoDump = $true
           Result = "Ok"; Dump = 0; Collection = 5GB }
        @{ What = "1 GB left on another drive -> Ok"; Volume = [PSCustomObject]@{ Root = "D:\"; FreeBytes = $ram2 + 1MB + 1GB; TotalBytes = 1400GB; FileSystem = "NTFS" }
           Result = "Ok" }
        @{ What = "1 byte less -> NoFit"; Volume = [PSCustomObject]@{ Root = "D:\"; FreeBytes = $ram2 + 1MB + 1GB - 1; TotalBytes = 1400GB; FileSystem = "NTFS" }
           Result = "NoFit" }
    )
    foreach ($case in $spaceCases) {
        $params = @{
            Volume         = $case.Volume
            RamBytes       = $(if ($case.ContainsKey("Ram")) { [long]$case.Ram } else { $ram2 })
            ToolName       = $(if ($case.ContainsKey("Tool")) { $case.Tool } else { "DumpIt" })
            OnSystemDrive  = [bool]$case.System
            WithCollection = [bool]$case.With
            LargeFiles     = $(if ($case.ContainsKey("Large")) { [bool]$case.Large } else { $true })
            Compress       = $(if ($case.ContainsKey("Compress")) { [bool]$case.Compress } else { $true })
            MinFreeSpaceGB = $(if ($case.ContainsKey("Min")) { [int]$case.Min } else { -1 })
        }
        if ($case.NoDump) { $params.NoDump = $true }
        $problems = New-Problems
        $check = Get-MemoryCaptureSpaceCheck @params
        if ($check.Result -ne $case.Result) { $problems.Add("result $($check.Result), expected $($case.Result) ($($check.Reason))") }
        if ($case.ContainsKey("Dump") -and [long]$check.DumpBytes -ne [long]$case.Dump) { $problems.Add("dump $($check.DumpBytes) bytes, expected $($case.Dump)") }
        if ($case.ContainsKey("Collection") -and [long]$check.CollectionBytes -ne [long]$case.Collection) { $problems.Add("collection $($check.CollectionBytes) bytes, expected $($case.Collection)") }
        if ($case.ContainsKey("Reserve") -and [long]$check.ReserveBytes -ne [long]$case.Reserve) { $problems.Add("reserve $($check.ReserveBytes) bytes, expected $($case.Reserve)") }
        if ($case.ContainsKey("Reason") -and $check.Reason -notmatch $case.Reason) { $problems.Add("reason '$($check.Reason)'") }
        if ($check.Result -eq "Ok" -and $check.Reason) { $problems.Add("reason '$($check.Reason)' for Ok") }
        Add-Result "space: $($case.What)" $problems -Info $check.Result
    }

    # The log line, also as the prompt shows it
    $lineCases = @(
        @{ What = "run 2"; Params = @{ Volume = $c487; RamBytes = $ram2; OnSystemDrive = $true; WithCollection = $true }
           Line = 'Free space on C:\: 40.8 GB; memory dump ~31.9 GB + collection ~5 GB would leave ~3.9 GB (to keep free on the system drive: 20 GB)' }
        @{ What = "another drive"; Params = @{ Volume = (New-TestVolume "D:\" 453 1400); RamBytes = $ram2 }
           Line = 'Free space on D:\: 453 GB; memory dump ~31.9 GB would leave ~421.1 GB (to keep free: 1 GB)' }
        @{ What = "no room"; Params = @{ Volume = (New-TestVolume "C:\" 2.6 487.41); RamBytes = $ram2; OnSystemDrive = $true; WithCollection = $true }
           Line = 'Free space on C:\: 2.6 GB; memory dump ~31.9 GB + collection ~5 GB would need ~34.3 GB more (to keep free on the system drive: 20 GB)' }
        @{ What = "collection alone"; Params = @{ Volume = $c487; OnSystemDrive = $true; WithCollection = $true; NoDump = $true }
           Line = 'Free space on C:\: 40.8 GB; collection ~5 GB would leave ~35.8 GB (to keep free on the system drive: 20 GB)' }
    )
    foreach ($case in $lineCases) {
        $params = $case.Params
        $problems = New-Problems
        $line = Format-SpaceCheck (Get-MemoryCaptureSpaceCheck @params)
        if ($line -cne $case.Line) { $problems.Add("'$line'") }
        Add-Result "log line: $($case.What)" $problems -Info $line
    }

    # =========================================================
    # 2. Get-VolumeSpace on real drives (read only)
    # =========================================================
    $problems = New-Problems
    $tempRoot = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetTempPath())
    $volume = Get-VolumeSpace (Join-Path $workDir "not\created\yet.dmp")
    $drive = New-Object System.IO.DriveInfo($tempRoot)
    if (-not $volume) {
        $problems.Add("no result for $tempRoot")
    } else {
        if ($volume.Root -ne $tempRoot) { $problems.Add("root '$($volume.Root)', expected '$tempRoot'") }
        if ($volume.FileSystem -ne $drive.DriveFormat) { $problems.Add("file system '$($volume.FileSystem)', DriveInfo says '$($drive.DriveFormat)'") }
        if ($volume.TotalBytes -ne $drive.TotalSize) { $problems.Add("total $($volume.TotalBytes), DriveInfo says $($drive.TotalSize)") }
        if ($volume.FreeBytes -le 0 -or $volume.FreeBytes -gt $volume.TotalBytes) { $problems.Add("free $($volume.FreeBytes) of $($volume.TotalBytes)") }
        if ([math]::Abs($volume.FreeBytes - $drive.AvailableFreeSpace) -gt 1GB) { $problems.Add("free $($volume.FreeBytes), DriveInfo says $($drive.AvailableFreeSpace)") }
    }
    Add-Result "volume: the temp folder's drive" $problems -Info "$tempRoot $($volume.FileSystem), $(Format-SpaceGB $volume.FreeBytes) GB free"

    $problems = New-Problems
    $usedLetters = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
    $freeLetter = @("QWVUTSRPONMLKJIHGZYX".ToCharArray() | Where-Object { $usedLetters -notcontains [string]$_ }) | Select-Object -First 1
    if ($freeLetter) {
        $missing = Get-VolumeSpace "${freeLetter}:\TriageMemory\x.dmp"
        if ($null -ne $missing) { $problems.Add("a result for the missing drive ${freeLetter}:") }
    }
    Add-Result "volume: a missing drive gives nothing" $problems -Info "${freeLetter}:"

    # UNC path (the Scripting.FileSystemObject branch): the admin share of
    # the temp folder's drive, where it can be reached
    $problems = New-Problems
    $unc = "\\localhost\" + $tempRoot.Substring(0, 1) + "$"
    $uncInfo = "skipped: $unc not reachable"
    if (Test-Path -LiteralPath $unc) {
        $uncVolume = Get-VolumeSpace (Join-Path $unc "Windows")
        if (-not $uncVolume) {
            $problems.Add("no result for $unc")
        } else {
            if ($uncVolume.Root -ne $unc) { $problems.Add("root '$($uncVolume.Root)', expected '$unc'") }
            if ($uncVolume.TotalBytes -ne $drive.TotalSize) { $problems.Add("total $($uncVolume.TotalBytes), DriveInfo says $($drive.TotalSize)") }
            if ($uncVolume.FileSystem -ne $drive.DriveFormat) { $problems.Add("file system '$($uncVolume.FileSystem)'") }
            if ($uncVolume.FreeBytes -le 0) { $problems.Add("free $($uncVolume.FreeBytes)") }
            $uncInfo = "$unc $($uncVolume.FileSystem), $(Format-SpaceGB $uncVolume.FreeBytes) GB free"
        }
    }
    Add-Result "volume: UNC path" $problems -Info $uncInfo

    # =========================================================
    # 3. The result check on DumpIt's output
    # =========================================================
    $okLog = @(Get-Content -LiteralPath (Join-Path $fixtureDir "dumpit_acquisition_ok.txt"))
    $failedLog = @(Get-Content -LiteralPath (Join-Path $fixtureDir "dumpit_acquisition_failed.txt"))
    $stderrRecord = New-Object System.Management.Automation.ErrorRecord (New-Object System.Exception "Error: synthetic message on stderr"), "NativeCommandError", "NotSpecified", $null
    $resultCases = @(
        @{ What = "DumpIt log of a complete capture"; Output = $okLog; Dump = 34261114880; Ram = $ram2
           Complete = $true; NtStatus = "0x00000000"; Reported = 34261114880; Summary = '^34261114880 bytes \(100% of the RAM\); DumpIt reported NtStatus 0x00000000 and a file of 34261114880 bytes$' }
        @{ What = "failing DumpIt log"; Output = $failedLog; Dump = 12GB; Ram = $ram2
           Complete = $false; NtStatus = "0xC000007F"; Reported = 17179869184; ErrorLines = @("Error: Not enough disk space to save dump file.")
           Problems = @('^DumpIt reported NtStatus 0xC000007F$', '^DumpIt reported a file of 17179869184 bytes, the dump has 12884901888 bytes$', '^the dump has 12884901888 bytes, less than 95% of the RAM \(34261106688 bytes\)$') }
        @{ What = "complete log, file 4 KB short"; Output = $okLog; Dump = 34261114880 - 4096; Ram = $ram2
           Complete = $false; Problems = @('^DumpIt reported a file of 34261114880 bytes, the dump has 34261110784 bytes$') }
        @{ What = "no dump file"; Output = $okLog; Dump = -1; Ram = $ram2
           Complete = $false; Problems = @('^no dump file was written$') }
        @{ What = "empty dump file"; Output = @(); Dump = 0; Ram = $ram2
           Complete = $false; Problems = @('^the dump file is empty$') }
        @{ What = "raw image, nothing reported"; Output = @("WinPmem synthetic output"); Dump = [long]($ram2 * 1.02); Ram = $ram2; Tool = "WinPmem"
           Complete = $true; NtStatus = ""; Reported = -1; Summary = 'WinPmem reported no NtStatus or file size$' }
        @{ What = "raw image under 95% of the RAM"; Output = @(); Dump = [long]($ram2 * 0.9); Ram = $ram2; Tool = "WinPmem"
           Complete = $false; Problems = @('^the dump has \d+ bytes, less than 95% of the RAM \(34261106688 bytes\)$') }
        @{ What = "RAM unknown: size not checked"; Output = @(); Dump = 1MB; Ram = 0; Tool = "MagnetRAM"
           Complete = $true }
        @{ What = "stderr error line (Windows PowerShell 5.1)"; Output = @("  DumpIt synthetic", $stderrRecord, $null); Dump = $ram2 + 8192; Ram = $ram2
           Complete = $true; ErrorLines = @("Error: synthetic message on stderr") }
    )
    foreach ($case in $resultCases) {
        $tool = "DumpIt"
        if ($case.ContainsKey("Tool")) { $tool = $case.Tool }
        $problems = New-Problems
        $check = Get-MemoryCaptureResult -Output $case.Output -DumpBytes ([long]$case.Dump) -RamBytes ([long]$case.Ram) -ToolName $tool
        if ($check.Complete -ne $case.Complete) { $problems.Add("complete: $($check.Complete) ($($check.Problems -join '; '))") }
        if ($case.ContainsKey("NtStatus") -and $check.NtStatus -cne $case.NtStatus) { $problems.Add("NtStatus '$($check.NtStatus)'") }
        if ($case.ContainsKey("Reported") -and [long]$check.ReportedBytes -ne [long]$case.Reported) { $problems.Add("reported $($check.ReportedBytes)") }
        if ($case.ContainsKey("Summary") -and $check.Summary -notmatch $case.Summary) { $problems.Add("summary '$($check.Summary)'") }
        $expectedErrors = @()
        if ($case.ContainsKey("ErrorLines")) { $expectedErrors = @($case.ErrorLines) }
        if ((@($check.ErrorLines) -join "|") -cne ($expectedErrors -join "|")) { $problems.Add("error lines '$(@($check.ErrorLines) -join ' | ')'") }
        $expectedProblems = @()
        if ($case.ContainsKey("Problems")) { $expectedProblems = @($case.Problems) }
        if (@($check.Problems).Count -ne $expectedProblems.Count) { $problems.Add("$(@($check.Problems).Count) problem(s): $(@($check.Problems) -join '; ')") }
        else { for ($k = 0; $k -lt $expectedProblems.Count; $k++) { if (@($check.Problems)[$k] -notmatch $expectedProblems[$k]) { $problems.Add("problem '$(@($check.Problems)[$k])'") } } }
        $info = $check.Summary
        if (-not $check.Complete) { $info = @($check.Problems) -join "; " }
        Add-Result "result: $($case.What)" $problems -Info $info
    }

    # =========================================================
    # 4. Stand-ins for the machine: drives, RAM, capture tool, answers
    # =========================================================
    # Volumes by root; a root not listed gives $null (unknown)
    $script:testVolumes = @{}
    function Get-VolumeSpace {
        param([string]$Path)
        $root = [System.IO.Path]::GetPathRoot($Path).ToUpperInvariant()
        if ($script:testVolumes.ContainsKey($root)) { return $script:testVolumes[$root] }
        return $null
    }
    $script:testDriveRoots = @()
    function Get-MemoryDumpDriveRoots { return $script:testDriveRoots }
    $script:testRamBytes = [long]0
    function Get-PhysicalMemoryBytes { return $script:testRamBytes }
    # The capture tool: a function run as "& $memTool /TYPE DMP ... /OUTPUT
    # <file>" that writes a dump of DumpBytes (-1: none) and prints Lines
    $script:standIn = $null
    $script:toolCalls = 0
    function Invoke-TestCaptureTool {
        $script:toolCalls++
        $outFile = $null
        for ($a = 0; $a -lt $args.Count - 1; $a++) { if ($args[$a] -eq "/OUTPUT") { $outFile = [string]$args[$a + 1] } }
        if ($script:standIn.DumpBytes -ge 0) {
            $stream = [System.IO.File]::Create($outFile)
            try { $stream.SetLength($script:standIn.DumpBytes) } finally { $stream.Dispose() }
        }
        foreach ($line in $script:standIn.Lines) { $line }
        if ($script:standIn.Throw) { throw $script:standIn.Throw }
    }
    function Find-MemoryCaptureTool {
        $script:skippedMemTools = @()
        return [PSCustomObject]@{ Name = "DumpIt"; Path = "Invoke-TestCaptureTool"; RelPath = "tools\dumpit\x64\DumpIt.exe" }
    }
    # Read-Host answers from a queue (a function comes before the cmdlet);
    # a question more than the test expects ends the prompt with an error
    $script:answers = New-Object System.Collections.Generic.Queue[string]
    $script:prompts = New-Object System.Collections.Generic.List[string]
    Set-Item -Path function:Read-Host -Value {
        param([string]$Prompt)
        $script:prompts.Add($Prompt)
        if ($script:answers.Count -eq 0) { throw "the test has no answer left for '$Prompt'" }
        return $script:answers.Dequeue()
    }

    # =========================================================
    # 5. The prompt (run 2's machine: C: 40.8 GB free, D: 453 GB)
    # =========================================================
    $env:SystemDrive = "C:"
    $script:OutputPath = "C:\Triage\reports\TriageCollection_2026-01-02_03-04"
    $script:SkipLargeFiles = $false
    $script:NoCompress = $false
    $script:MinFreeSpaceGB = -1
    $script:IsLive = $true
    $script:testRamBytes = $ram2
    # E: FAT32, F: too small, H: free space unknown: none of them offered
    $script:testDriveRoots = @("C:\", "D:\", "E:\", "F:\", "H:\")
    $defaultCategories = @("FileSystem", "Registry", "EventLogs", "Execution", "Network", "UserActivity", "Browser", "USB", "Persistence", "AntiVirus")

    # Runs the prompt with these answers; returns what it showed and set
    function Invoke-Prompt {
        param([string[]]$Answers, [string]$MemoryOutputPathIn = "")
        $script:answers.Clear()
        foreach ($answer in $Answers) { $script:answers.Enqueue($answer) }
        $script:prompts.Clear()
        $script:memorySpaceAccepted = $false
        $Categories = $defaultCategories
        $MemoryOutputPath = $MemoryOutputPathIn
        $thrown = ""
        $screen = @()
        try { $screen = @(. $promptBlock 6>&1 | ForEach-Object { "$_" }) }
        catch { $thrown = $_.Exception.Message }
        return [PSCustomObject]@{
            Screen           = $screen
            Thrown           = $thrown
            Categories       = $Categories
            MemoryOutputPath = $MemoryOutputPath
            Accepted         = $script:memorySpaceAccepted
            Prompts          = @($script:prompts)
            AnswersLeft      = $script:answers.Count
        }
    }
    $script:testVolumes = @{
        "C:\" = New-TestVolume "C:\" 40.8 487.41
        "D:\" = New-TestVolume "D:\" 453 1400
        "E:\" = New-TestVolume "E:\" 60 64 "FAT32"
        "F:\" = New-TestVolume "F:\" 20 500
    }
    $runTwoLines = @(
        '^  Captures a full RAM dump \(~32 GB on this system\)\.$',
        ('^  Dump file: ' + [regex]::Escape("$OutputPath\Memory\memory_dump.dmp") + '$'),
        ('^  ' + [regex]::Escape('Free space on C:\: 40.8 GB; memory dump ~31.9 GB + collection ~5 GB would leave ~3.9 GB (to keep free on the system drive: 20 GB)') + '$'),
        '^  The dump would be written to the system drive being examined',
        '^  Low free space: C:\\ would be left with ~3\.9 GB free, less than the 20 GB to keep free on the system drive\.$',
        '^  \[1\] Write the dump to D:\\TriageMemory \(453 GB free\) -- recommended$',
        '^  \[2\] Write the dump to C:\\ anyway$',
        '^  \[3\] Skip memory, collect artifacts only$'
    )
    $run = Invoke-Prompt -Answers @("1")
    $problems = New-Problems
    if ($run.Thrown) { $problems.Add("prompt threw: $($run.Thrown)") }
    Test-LinesInOrder -Lines $run.Screen -Expected ($runTwoLines + @('^Memory capture enabled\. Will run first\.$', '^Memory dump: D:\\TriageMemory\\TriageCollection_2026-01-02_03-04_memory_dump\.dmp$')) -Problems $problems -Where "screen"
    if (@($run.Screen | Where-Object { $_ -match '\[4\]|E:\\|F:\\|H:\\' }).Count -gt 0) { $problems.Add("E: (FAT32), F: (too small) or H: (unknown) offered") }
    if (($run.Prompts -join "|") -ne "Include memory capture? (1-3)") { $problems.Add("prompts: $($run.Prompts -join ' | ')") }
    if ($run.Categories[0] -ne "Memory") { $problems.Add("Categories: $($run.Categories -join ',')") }
    if ($run.MemoryOutputPath -ne "D:\TriageMemory") { $problems.Add("MemoryOutputPath '$($run.MemoryOutputPath)'") }
    if ($run.Accepted) { $problems.Add("marked as accepted anyway") }
    Add-Result "prompt: run 2, other drive chosen" $problems -Info "D:\TriageMemory"

    $run = Invoke-Prompt -Answers @("0", "4", "two", "2")
    $problems = New-Problems
    if ($run.Thrown) { $problems.Add("prompt threw: $($run.Thrown)") }
    Test-LinesInOrder -Lines $run.Screen -Expected ($runTwoLines + @('^Memory capture enabled\. Will run first\.$')) -Problems $problems -Where "screen"
    if ($run.Prompts.Count -ne 4 -or $run.AnswersLeft -ne 0) { $problems.Add("$($run.Prompts.Count) question(s), $($run.AnswersLeft) answer(s) left") }
    if ($run.Categories[0] -ne "Memory" -or $run.MemoryOutputPath) { $problems.Add("Categories $($run.Categories -join ','), MemoryOutputPath '$($run.MemoryOutputPath)'") }
    if (-not $run.Accepted) { $problems.Add("not marked as accepted anyway") }
    Add-Result "prompt: run 2, here anyway (after bad answers)" $problems -Info "asked $($run.Prompts.Count) times"

    $run = Invoke-Prompt -Answers @("3")
    $problems = New-Problems
    if ($run.Thrown) { $problems.Add("prompt threw: $($run.Thrown)") }
    Test-LinesInOrder -Lines $run.Screen -Expected @('^Memory capture skipped\.$') -Problems $problems -Where "screen"
    if ($run.Categories -contains "Memory" -or $run.MemoryOutputPath) { $problems.Add("Categories $($run.Categories -join ','), MemoryOutputPath '$($run.MemoryOutputPath)'") }
    Add-Result "prompt: run 2, skipped" $problems

    # No room on C: and no other drive: nothing to choose, no question
    $script:testVolumes["C:\"] = New-TestVolume "C:\" 2.6 487.41
    $script:testDriveRoots = @("C:\", "E:\")
    $run = Invoke-Prompt -Answers @()
    $problems = New-Problems
    if ($run.Thrown) { $problems.Add("prompt threw: $($run.Thrown)") }
    Test-LinesInOrder -Lines $run.Screen -Expected @('^  Not enough free space: less than 1 GB would be left free on C:\\\.$', '^  No other drive has room for the dump\.$', '^Memory capture skipped\.$') -Problems $problems -Where "screen"
    if ($run.Prompts.Count -ne 0) { $problems.Add("asked: $($run.Prompts -join ' | ')") }
    if (@($run.Screen | Where-Object { $_ -match '^\s+\[\d\]' }).Count -gt 0) { $problems.Add("choices shown") }
    if ($run.Categories -contains "Memory") { $problems.Add("Memory added") }
    Add-Result "prompt: no room anywhere, no question" $problems

    # Plenty of room: today's Yes / No, still the system drive warning
    $script:testVolumes["C:\"] = New-TestVolume "C:\" 400 487.41
    $run = Invoke-Prompt -Answers @("1")
    $problems = New-Problems
    if ($run.Thrown) { $problems.Add("prompt threw: $($run.Thrown)") }
    Test-LinesInOrder -Lines $run.Screen -Expected @('would leave ~363\.1 GB', '^  The dump would be written to the system drive being examined', '^  \[1\] Yes -- capture memory \(recommended for incident response\)$', '^  \[2\] No  -- skip memory, collect artifacts only$', '^Memory capture enabled\. Will run first\.$') -Problems $problems -Where "screen"
    if (($run.Prompts -join "|") -ne "Include memory capture? (1-2)") { $problems.Add("prompts: $($run.Prompts -join ' | ')") }
    if ($run.Categories[0] -ne "Memory" -or $run.MemoryOutputPath -or $run.Accepted) { $problems.Add("Categories $($run.Categories -join ','), MemoryOutputPath '$($run.MemoryOutputPath)', accepted $($run.Accepted)") }
    Add-Result "prompt: room on the system drive, Yes / No" $problems

    # -MemoryOutputPath on another drive: checked there, no system drive warning
    $run = Invoke-Prompt -Answers @("2") -MemoryOutputPathIn "D:\Dumps"
    $problems = New-Problems
    if ($run.Thrown) { $problems.Add("prompt threw: $($run.Thrown)") }
    Test-LinesInOrder -Lines $run.Screen -Expected @('^  Dump file: D:\\Dumps\\TriageCollection_2026-01-02_03-04_memory_dump\.dmp$', ('^  ' + [regex]::Escape('Free space on D:\: 453 GB; memory dump ~31.9 GB would leave ~421.1 GB (to keep free: 1 GB)') + '$'), '^Memory capture skipped\.$') -Problems $problems -Where "screen"
    if (@($run.Screen | Where-Object { $_ -match 'system drive being examined' }).Count -gt 0) { $problems.Add("system drive warning for D:") }
    if ($run.MemoryOutputPath -ne "D:\Dumps") { $problems.Add("MemoryOutputPath '$($run.MemoryOutputPath)'") }
    Add-Result "prompt: -MemoryOutputPath on another drive" $problems

    # USB workflow, collection on a FAT32 stick: no room for the dump there;
    # D: is offered, C: (the system drive, with room) is not, and there is
    # no system drive warning
    $script:OutputPath = "E:\win11-triage-collector\reports\TriageCollection_2026-01-02_03-04"
    $script:testDriveRoots = @("C:\", "D:\", "E:\", "F:\")
    $run = Invoke-Prompt -Answers @("1")
    $problems = New-Problems
    if ($run.Thrown) { $problems.Add("prompt threw: $($run.Thrown)") }
    Test-LinesInOrder -Lines $run.Screen -Expected @(
        '^  Dump file: E:\\win11-triage-collector\\reports\\TriageCollection_2026-01-02_03-04\\Memory\\memory_dump\.dmp$',
        ('^  ' + [regex]::Escape('Free space on E:\: 60 GB; memory dump ~31.9 GB + collection ~5 GB would leave ~23.1 GB (to keep free: 1 GB)') + '$'),
        '^  Not enough free space: E:\\ is FAT32, which cannot hold a file of 4 GB or more\.$',
        '^  \[1\] Write the dump to D:\\TriageMemory \(453 GB free\) -- recommended$',
        '^  \[2\] Skip memory, collect artifacts only$',
        '^Memory dump: D:\\TriageMemory\\TriageCollection_2026-01-02_03-04_memory_dump\.dmp$'
    ) -Problems $problems -Where "screen"
    if (@($run.Screen | Where-Object { $_ -match 'system drive|C:\\TriageMemory|\[3\]' }).Count -gt 0) { $problems.Add("system drive warning, or C: offered") }
    if ($run.MemoryOutputPath -ne "D:\TriageMemory" -or $run.Categories[0] -ne "Memory") { $problems.Add("MemoryOutputPath '$($run.MemoryOutputPath)', Categories $($run.Categories -join ',')") }
    Add-Result "prompt: collection on a FAT32 stick, D: offered" $problems

    # Collection on an NTFS stick with room: Yes / No, a 1 GB margin only
    $script:OutputPath = "G:\win11-triage-collector\reports\TriageCollection_2026-01-02_03-04"
    $script:testVolumes["G:\"] = New-TestVolume "G:\" 200 256
    $run = Invoke-Prompt -Answers @("2")
    $problems = New-Problems
    if ($run.Thrown) { $problems.Add("prompt threw: $($run.Thrown)") }
    Test-LinesInOrder -Lines $run.Screen -Expected @(
        ('^  ' + [regex]::Escape('Free space on G:\: 200 GB; memory dump ~31.9 GB + collection ~5 GB would leave ~163.1 GB (to keep free: 1 GB)') + '$'),
        '^  \[1\] Yes -- capture memory', '^  \[2\] No  -- skip memory', '^Memory capture skipped\.$'
    ) -Problems $problems -Where "screen"
    if (@($run.Screen | Where-Object { $_ -match 'system drive' }).Count -gt 0) { $problems.Add("system drive warning for G:") }
    Add-Result "prompt: collection on an NTFS stick, Yes / No" $problems
    $script:OutputPath = "C:\Triage\reports\TriageCollection_2026-01-02_03-04"

    # Free space unknown: a warning and Yes / No
    $script:testVolumes.Remove("C:\")
    $run = Invoke-Prompt -Answers @("1")
    $problems = New-Problems
    if ($run.Thrown) { $problems.Add("prompt threw: $($run.Thrown)") }
    Test-LinesInOrder -Lines $run.Screen -Expected @('^  Free space on C:\\: unknown', '^  Free space not checked: the free space could not be read\.$', '^  \[1\] Yes -- capture memory', '^Memory capture enabled\.') -Problems $problems -Where "screen"
    if (-not $run.Accepted) { $problems.Add("not marked as accepted") }
    Add-Result "prompt: free space unknown" $problems

    # The choices themselves (Get-MemoryCaptureChoices)
    $problems = New-Problems
    $twoDrives = @(
        [PSCustomObject]@{ Root = "D:\"; DumpDir = "D:\TriageMemory"; Check = [PSCustomObject]@{ FreeBytes = 453GB } },
        [PSCustomObject]@{ Root = "G:\"; DumpDir = "G:\TriageMemory"; Check = [PSCustomObject]@{ FreeBytes = 100GB } }
    )
    $choiceCases = @(
        @{ Result = "Ok"; Drives = @(); Actions = "Here,Skip" }
        @{ Result = "Unknown"; Drives = @(); Actions = "Here,Skip" }
        @{ Result = "LowReserve"; Drives = $twoDrives; Actions = "Other,Other,Here,Skip" }
        @{ Result = "LowReserve"; Drives = @(); Actions = "Here,Skip" }
        @{ Result = "NoFit"; Drives = $twoDrives; Actions = "Other,Other,Skip" }
        @{ Result = "NoFit"; Drives = @(); Actions = "Skip" }
    )
    foreach ($case in $choiceCases) {
        $choices = @(Get-MemoryCaptureChoices -Check ([PSCustomObject]@{ Result = $case.Result; Root = "C:\" }) -OtherDrives $case.Drives)
        $actions = ($choices | ForEach-Object { $_.Action }) -join ","
        if ($actions -ne $case.Actions) { $problems.Add("$($case.Result) with $(@($case.Drives).Count) drive(s): $actions") }
        $recommended = @($choices | Where-Object { $_.Label -like "*recommended*" })
        if ($case.Drives.Count -gt 0 -and ($recommended.Count -ne 1 -or $recommended[0].DumpDir -ne "D:\TriageMemory")) { $problems.Add("$($case.Result): recommended '$(@($recommended | ForEach-Object { $_.Label }) -join ' | ')'") }
    }
    Add-Result "prompt: choices per result" $problems

    # =========================================================
    # 6. The memory section, with the stand-in capture tool
    # =========================================================
    $tempRoot = [System.IO.Path]::GetPathRoot($workDir).ToUpperInvariant()
    $env:SystemDrive = $tempRoot.TrimEnd('\')   # the temp folder's drive stands in for C:
    $script:Categories = @("Memory", "FileSystem")
    $script:testRamBytes = [long]1MB
    $completeBytes = [long]1MB + 8192
    function New-StandIn {
        param([long]$DumpBytes, [long]$ReportedBytes = -2, [string]$NtStatus = "0x00000000", [string[]]$Extra = @(), [string]$Throw = "")
        if ($ReportedBytes -eq -2) { $ReportedBytes = $DumpBytes }
        $lines = @("  DumpIt 0.0.00000000 (X64) (synthetic test output)") + $Extra
        if ($ReportedBytes -ge 0) { $lines += "    Created file size:           $ReportedBytes bytes (1 Mb)" }
        if ($NtStatus) { $lines += "    NtStatus (troubleshooting):   $NtStatus" }
        return [PSCustomObject]@{ DumpBytes = $DumpBytes; Lines = $lines; Throw = $Throw }
    }

    # Runs the memory section for a new collection folder; returns what it
    # logged and left behind
    function Invoke-MemorySection {
        param([string]$Name, [object]$StandIn, [string]$DumpDir = "", [object]$Volume = "default", [switch]$Accepted, [switch]$EarlierDump)
        $script:OutputPath = Join-Path $workDir "$Name\TriageCollection_2026-01-02_03-04"
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        $script:logFile = Join-Path $OutputPath "collection_log.txt"
        $script:manifestFile = Join-Path $OutputPath "collection_manifest.csv"
        [System.IO.File]::WriteAllText($manifestFile, "SHA256,SourcePath,DestPath,SizeBytes,CollectedAt,RelativePath,SourceCreatedUtc,SourceModifiedUtc,SourceAccessedUtc`r`n", (New-Object System.Text.UTF8Encoding($true)))
        $script:logToFile = $true
        $script:fileCount = 0
        $script:errorCount = 0
        $script:totalBytes = 0
        $script:memDumpPath = $null
        $script:memDumpIncompletePath = $null
        $script:memorySpaceAccepted = [bool]$Accepted
        $script:MemoryOutputPath = $DumpDir
        $script:standIn = $StandIn
        $script:toolCalls = 0
        if ($Volume -is [string]) { $Volume = New-TestVolume $tempRoot 500 1000 }
        $script:testVolumes = @{}
        if ($Volume) { $script:testVolumes[$tempRoot] = $Volume }
        $dumpPath = Get-MemoryDumpPath -ToolName "DumpIt" -DumpDir $DumpDir
        if ($EarlierDump) {
            New-Item -ItemType Directory -Path (Split-Path $dumpPath -Parent) -Force | Out-Null
            [System.IO.File]::WriteAllText($dumpPath, "earlier dump")
        }
        $thrown = ""
        try {
            & {
                $ErrorActionPreference = "Continue"
                . $sectionBlock
            } 6>$null
        } catch { $thrown = $_.Exception.Message }
        $rows = @()
        if (Test-Path -LiteralPath $manifestFile) {
            $rows = @(Import-Csv -LiteralPath $manifestFile)
        }
        return [PSCustomObject]@{
            Thrown       = $thrown
            Log          = @(Get-Content -LiteralPath $logFile)
            Errors       = $script:errorCount
            ToolCalls    = $script:toolCalls
            DumpPath     = $dumpPath
            AcqLog       = Join-Path $OutputPath "Memory\memory_acquisition_log.txt"
            Rows         = $rows
            MemDumpPath  = $script:memDumpPath
            Incomplete   = $script:memDumpIncompletePath
        }
    }
    function Test-SectionRun {
        param([object]$Run, [string[]]$Lines, [int]$Errors, [int]$ToolCalls, [System.Collections.Generic.List[string]]$Problems, [string[]]$Absent = @())
        if ($Run.Thrown) { $Problems.Add("section threw: $($Run.Thrown)") }
        Test-LinesInOrder -Lines $Run.Log -Expected $Lines -Problems $Problems -Where "log"
        foreach ($pattern in $Absent) {
            $hits = @($Run.Log | Where-Object { $_ -match $pattern })
            if ($hits.Count -gt 0) { $Problems.Add("log has '$($hits[0])'") }
        }
        if ($Run.Errors -ne $Errors) { $Problems.Add("error count $($Run.Errors), expected $Errors") }
        if ($Run.ToolCalls -ne $ToolCalls) { $Problems.Add("tool ran $($Run.ToolCalls) time(s), expected $ToolCalls") }
        if ($Problems.Count -gt 0) { foreach ($line in $Run.Log) { Write-Verbose "  | $line" } }
    }
    $rootText = [regex]::Escape((ConvertTo-LogText $tempRoot))

    # Complete dump in Memory\: recorded, kept
    $run = Invoke-MemorySection -Name "complete" -StandIn (New-StandIn $completeBytes)
    $problems = New-Problems
    $dumpText = [regex]::Escape((ConvertTo-LogText $run.DumpPath))
    Test-SectionRun $run @(
        "Memory dump file: $dumpText$",
        "Free space on ${rootText}: 500 GB; memory dump ~0 GB \+ collection ~5 GB would leave ~495 GB \(to keep free on the system drive: 20 GB\)$",
        'The memory dump is written to the system drive being examined',
        'Capturing memory',
        "Memory dump check: $completeBytes bytes \(100\.8% of the RAM\); DumpIt reported NtStatus 0x00000000 and a file of $completeBytes bytes$",
        "OK: Memory dump captured: $dumpText"
    ) 0 1 $problems -Absent @('WARNING', 'ERROR')
    if ($run.MemDumpPath -ne $run.DumpPath) { $problems.Add("memDumpPath '$($run.MemDumpPath)'") }
    if ((Get-FileLength $run.DumpPath) -ne $completeBytes) { $problems.Add("dump is $(Get-FileLength $run.DumpPath) bytes") }
    $dumpRows = @($run.Rows | Where-Object { $_.SourcePath -eq "(memory dump via DumpIt)" })
    if ($dumpRows.Count -ne 1 -or $dumpRows[0].RelativePath -ne "Memory\memory_dump.dmp") { $problems.Add("$($dumpRows.Count) dump row(s) in the manifest") }
    if (@($run.Rows | Where-Object { $_.SourcePath -eq "(memory capture tool output: DumpIt)" }).Count -ne 1) { $problems.Add("acquisition log not in the manifest") }
    Add-Result "section: complete dump" $problems -Info "$completeBytes bytes"

    # No room: an error, no capture, nothing written
    $run = Invoke-MemorySection -Name "noroom" -StandIn (New-StandIn $completeBytes) -Volume (New-TestVolume $tempRoot 2 100)
    $problems = New-Problems
    Test-SectionRun $run @(
        "Free space on ${rootText}: 2 GB; memory dump ~0 GB \+ collection ~5 GB would need ~3 GB more",
        "ERROR: Memory capture skipped: less than 1 GB would be left free on $rootText\. Free up space, or write the dump to another drive with -MemoryOutputPath\.$"
    ) 1 0 $problems -Absent @('Capturing memory')
    if ((Get-FileLength $run.DumpPath) -ge 0 -or (Test-Path -LiteralPath $run.AcqLog) -or $run.MemDumpPath -or $run.Incomplete) { $problems.Add("something was written or set") }
    Add-Result "section: no room -> error, no capture" $problems

    # Low reserve, no prompt: a warning, the capture runs
    $run = Invoke-MemorySection -Name "lowreserve" -StandIn (New-StandIn $completeBytes) -Volume (New-TestVolume $tempRoot 12 100)
    $problems = New-Problems
    Test-SectionRun $run @(
        "Free space on ${rootText}: 12 GB; memory dump ~0 GB \+ collection ~5 GB would leave ~7 GB \(to keep free on the system drive: 10 GB\)$",
        "WARNING: Capturing anyway: $rootText would be left with ~7 GB free, less than the 10 GB to keep free on the system drive\. -MemoryOutputPath writes the dump to another drive\.$",
        'OK: Memory dump captured'
    ) 0 1 $problems
    if ($run.MemDumpPath -ne $run.DumpPath) { $problems.Add("memDumpPath '$($run.MemDumpPath)'") }
    Add-Result "section: low reserve -> warning, capture" $problems

    $run = Invoke-MemorySection -Name "lowaccepted" -StandIn (New-StandIn $completeBytes) -Volume (New-TestVolume $tempRoot 12 100) -Accepted
    $problems = New-Problems
    Test-SectionRun $run @('WARNING: Capturing anyway \(chosen at the prompt\): ', 'OK: Memory dump captured') 0 1 $problems
    Add-Result "section: low reserve chosen at the prompt" $problems

    # Free space unknown: a warning, the capture runs
    $run = Invoke-MemorySection -Name "unknown" -StandIn (New-StandIn $completeBytes) -Volume $null
    $problems = New-Problems
    Test-SectionRun $run @("Free space on ${rootText}: unknown$", 'WARNING: Capturing without a free space check: the free space could not be read\.$', 'OK: Memory dump captured') 0 1 $problems
    Add-Result "section: free space unknown -> warning, capture" $problems

    # Failed capture: error, DumpIt's error line, the dump moved out of the
    # collection as .incomplete, not recorded
    $run = Invoke-MemorySection -Name "failed" -StandIn (New-StandIn -DumpBytes 524288 -ReportedBytes $completeBytes -NtStatus "0xC000007F" -Extra @("    Error: Not enough disk space to save dump file."))
    $problems = New-Problems
    $incompletePath = "${OutputPath}_memory_dump.dmp.incomplete"
    Test-SectionRun $run @(
        'WARNING: DumpIt: Error: Not enough disk space to save dump file\.$',
        "ERROR: Memory capture failed: DumpIt reported NtStatus 0xC000007F; DumpIt reported a file of $completeBytes bytes, the dump has 524288 bytes; the dump has 524288 bytes, less than 95% of the RAM \(1048576 bytes\)\.$",
        'WARNING: Check acquisition log: ',
        ("WARNING: Incomplete memory dump kept outside the collection \(not zipped, not for analysis\): " + [regex]::Escape((ConvertTo-LogText $incompletePath)))
    ) 1 1 $problems -Absent @('OK: Memory dump captured')
    if ((Get-FileLength $run.DumpPath) -ge 0) { $problems.Add("dump still in the collection") }
    if ((Get-FileLength $incompletePath) -ne 524288) { $problems.Add("no 524288-byte file at $incompletePath") }
    if ($run.MemDumpPath -or $run.Incomplete -ne $incompletePath) { $problems.Add("memDumpPath '$($run.MemDumpPath)', incomplete '$($run.Incomplete)'") }
    if (@($run.Rows | Where-Object { $_.SourcePath -eq "(memory dump via DumpIt)" }).Count -ne 0) { $problems.Add("dump in the manifest") }
    if (@($run.Rows | Where-Object { $_.SourcePath -eq "(memory capture tool output: DumpIt)" }).Count -ne 1) { $problems.Add("acquisition log not in the manifest") }
    Add-Result "section: failed -> error, set aside" $problems

    # Empty dump: error, deleted
    $run = Invoke-MemorySection -Name "empty" -StandIn (New-StandIn -DumpBytes 0 -ReportedBytes -1 -NtStatus "")
    $problems = New-Problems
    Test-SectionRun $run @('ERROR: Memory capture failed: the dump file is empty\.$', 'Deleted the empty memory dump file: ') 1 1 $problems
    if ((Get-FileLength $run.DumpPath) -ge 0 -or $run.MemDumpPath -or $run.Incomplete) { $problems.Add("dump left or set") }
    Add-Result "section: empty dump -> error, deleted" $problems

    # No dump written
    $run = Invoke-MemorySection -Name "nodump" -StandIn (New-StandIn -DumpBytes -1 -ReportedBytes -1 -NtStatus "")
    $problems = New-Problems
    Test-SectionRun $run @('ERROR: Memory capture failed: no dump file was written\.$') 1 1 $problems
    if ($run.MemDumpPath -or $run.Incomplete) { $problems.Add("memDumpPath '$($run.MemDumpPath)', incomplete '$($run.Incomplete)'") }
    Add-Result "section: no dump written -> error" $problems

    # The tool fails after writing part of the dump: the catch, then set aside
    $run = Invoke-MemorySection -Name "throws" -StandIn (New-StandIn -DumpBytes 4096 -Throw "synthetic tool failure")
    $problems = New-Problems
    Test-SectionRun $run @('ERROR: Memory capture failed: synthetic tool failure$', 'WARNING: Incomplete memory dump kept outside the collection') 1 1 $problems
    if ((Get-FileLength $run.DumpPath) -ge 0 -or -not $run.Incomplete -or $run.MemDumpPath) { $problems.Add("dump not set aside") }
    Add-Result "section: tool error -> error, set aside" $problems

    # An earlier dump at the path: not overwritten, no capture
    $run = Invoke-MemorySection -Name "earlier" -StandIn (New-StandIn $completeBytes) -EarlierDump
    $problems = New-Problems
    Test-SectionRun $run @(("ERROR: Memory capture skipped: a file is already at " + [regex]::Escape((ConvertTo-LogText $run.DumpPath)))) 1 0 $problems
    if ((Get-FileLength $run.DumpPath) -ne 12 -or $run.MemDumpPath -or $run.Incomplete) { $problems.Add("earlier dump changed or set") }
    Add-Result "section: earlier dump at the path -> kept, no capture" $problems

    # -MemoryOutputPath: the dump there under the collection's name, the
    # acquisition log in Memory\, the dump row outside the collection
    $dumpDir = Join-Path $workDir "dumps\not yet created"
    $run = Invoke-MemorySection -Name "dumpdir" -StandIn (New-StandIn $completeBytes) -DumpDir $dumpDir
    $problems = New-Problems
    $expectedDump = Join-Path $dumpDir "TriageCollection_2026-01-02_03-04_memory_dump.dmp"
    if ($run.DumpPath -ne $expectedDump) { $problems.Add("dump path '$($run.DumpPath)'") }
    Test-SectionRun $run @(("Memory dump file: " + [regex]::Escape((ConvertTo-LogText $expectedDump)) + '$'), 'OK: Memory dump captured') 0 1 $problems
    if ($run.MemDumpPath -ne $expectedDump -or (Get-FileLength $expectedDump) -ne $completeBytes) { $problems.Add("memDumpPath '$($run.MemDumpPath)', $(Get-FileLength $expectedDump) bytes") }
    if (-not (Test-Path -LiteralPath $run.AcqLog)) { $problems.Add("no acquisition log in Memory\") }
    $dumpRows = @($run.Rows | Where-Object { $_.SourcePath -eq "(memory dump via DumpIt)" })
    if ($dumpRows.Count -ne 1 -or $dumpRows[0].DestPath -ne $expectedDump -or $dumpRows[0].RelativePath) { $problems.Add("dump row: $(@($dumpRows | ForEach-Object { $_.DestPath + ' | ' + $_.RelativePath }) -join '; ')") }
    Add-Result "section: -MemoryOutputPath" $problems

    # A failed capture to -MemoryOutputPath: renamed in place
    $run = Invoke-MemorySection -Name "dumpdirfailed" -StandIn (New-StandIn -DumpBytes 4096 -ReportedBytes 4096) -DumpDir (Join-Path $workDir "dumps2")
    $problems = New-Problems
    Test-SectionRun $run @('ERROR: Memory capture failed: the dump has 4096 bytes, less than 95% of the RAM', 'WARNING: Incomplete memory dump kept outside the collection') 1 1 $problems
    if ($run.Incomplete -ne "$($run.DumpPath).incomplete" -or (Get-FileLength $run.Incomplete) -ne 4096 -or (Get-FileLength $run.DumpPath) -ge 0) { $problems.Add("incomplete '$($run.Incomplete)'") }
    Add-Result "section: -MemoryOutputPath, failed -> renamed" $problems

    # =========================================================
    # 7. Summary and compression with a dump
    # =========================================================
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $script:startTime = Get-Date
    $script:TargetDrive = "C"
    # Runs the summary and compression steps on a small collection with a
    # dump; returns the screen, the files left and the zip's entries
    function Invoke-Final {
        param([string]$Name, [string]$DumpDir = "", [switch]$NoZip, [switch]$LockDump, [switch]$Incomplete)
        $script:OutputPath = Join-Path $workDir "$Name\TriageCollection_2026-01-02_03-04"
        New-Item -ItemType Directory -Path (Join-Path $OutputPath "Memory") -Force | Out-Null
        $script:logFile = Join-Path $OutputPath "collection_log.txt"
        [System.IO.File]::WriteAllText($logFile, "start`r`n")
        [System.IO.File]::WriteAllText((Join-Path $OutputPath "Memory\memory_acquisition_log.txt"), "synthetic`r`n")
        $script:logToFile = $true
        $script:NoCompress = [bool]$NoZip
        $script:fileCount = 3
        $script:errorCount = 0
        $script:totalBytes = 1000
        $dump = Get-MemoryDumpPath -ToolName "DumpIt" -DumpDir $DumpDir
        New-Item -ItemType Directory -Path (Split-Path $dump -Parent) -Force | Out-Null
        [System.IO.File]::WriteAllText($dump, "DUMP")
        $script:memDumpPath = $dump
        $script:memDumpIncompletePath = $null
        if ($Incomplete) { $script:memDumpPath = $null; $script:memDumpIncompletePath = "$dump.incomplete" }
        $lock = $null
        if ($LockDump) { $lock = [System.IO.File]::Open($dump, "Open", "Read", "Read") }
        try {
            $screen = @(& {
                $ErrorActionPreference = "Continue"
                . $finalBlock
            } 6>&1 | ForEach-Object { "$_" })
        } finally {
            if ($lock) { $lock.Dispose() }
        }
        $entries = @()
        if (Test-Path -LiteralPath "$OutputPath.zip") {
            $zip = [System.IO.Compression.ZipFile]::OpenRead("$OutputPath.zip")
            try { $entries = @($zip.Entries | ForEach-Object { $_.FullName }) } finally { $zip.Dispose() }
        }
        return [PSCustomObject]@{
            Screen  = $screen
            Dump    = $dump
            Next    = "${OutputPath}_memory_dump.dmp"
            Folder  = Test-Path -LiteralPath $OutputPath
            Zip     = Test-Path -LiteralPath "$OutputPath.zip"
            Entries = $entries
        }
    }

    $final = Invoke-Final -Name "zip"
    $problems = New-Problems
    Test-LinesInOrder -Lines $final.Screen -Expected @(
        ('Memory dump:    ' + [regex]::Escape($final.Next) + ' \(kept outside the zip\)$'),
        'Memory dump detected .* keeping it next to the zip\.$',
        'OK: Compressed to ',
        ('^  Memory dump:    ' + [regex]::Escape($final.Next) + ' \(')
    ) -Problems $problems -Where "screen"
    if (-not $final.Zip -or $final.Folder) { $problems.Add("zip $($final.Zip), folder kept $($final.Folder)") }
    if ((Get-FileLength $final.Next) -ne 4 -or (Get-FileLength $final.Dump) -ge 0) { $problems.Add("dump not next to the zip") }
    if (@($final.Entries | Where-Object { $_ -like "*memory_dump*" }).Count -gt 0) { $problems.Add("dump in the zip") }
    if (@($final.Entries | Where-Object { $_ -like "*/Memory/memory_acquisition_log.txt" }).Count -ne 1) { $problems.Add("acquisition log not in the zip") }
    Add-Result "compression: dump moved next to the zip" $problems

    $final = Invoke-Final -Name "locked" -LockDump
    $problems = New-Problems
    Test-LinesInOrder -Lines $final.Screen -Expected @(
        'WARNING: Could not move the memory dump out of the collection folder, so the folder is not compressed: ',
        'The collection is kept at: ',
        'Zip NOT created -- collection left at: ',
        ('^  Memory dump:    ' + [regex]::Escape($final.Dump) + ' \(')
    ) -Problems $problems -Where "screen"
    if (@($final.Screen | Where-Object { $_ -match 'Compressing to:' }).Count -gt 0) { $problems.Add("compression started") }
    if ($final.Zip -or -not $final.Folder -or (Get-FileLength $final.Dump) -ne 4) { $problems.Add("zip $($final.Zip), folder kept $($final.Folder), dump in it $((Get-FileLength $final.Dump) -eq 4)") }
    Add-Result "compression: dump not movable -> no zip, folder kept" $problems

    $final = Invoke-Final -Name "dumpdir" -DumpDir (Join-Path $workDir "dumpdir-final")
    $problems = New-Problems
    Test-LinesInOrder -Lines $final.Screen -Expected @(
        ('Memory dump:    ' + [regex]::Escape($final.Dump) + '$'),
        '  \(timeline builder: pass it as -MemoryDumpPath\)$',
        'OK: Compressed to ',
        ('^  Memory dump:    ' + [regex]::Escape($final.Dump) + ' \(')
    ) -Problems $problems -Where "screen"
    if (-not $final.Zip -or (Get-FileLength $final.Dump) -ne 4) { $problems.Add("zip $($final.Zip), dump left $((Get-FileLength $final.Dump) -eq 4)") }
    if (@($final.Screen | Where-Object { $_ -match 'Memory dump detected' }).Count -gt 0) { $problems.Add("dump moved") }
    Add-Result "compression: -MemoryOutputPath dump left in place" $problems

    $final = Invoke-Final -Name "nozip" -NoZip
    $problems = New-Problems
    Test-LinesInOrder -Lines $final.Screen -Expected @(('^  Output:         ' + [regex]::Escape($OutputPath) + '$'), ('^  Memory dump:    ' + [regex]::Escape($final.Dump) + '$')) -Problems $problems -Where "screen"
    if ($final.Zip -or -not $final.Folder) { $problems.Add("zip $($final.Zip), folder kept $($final.Folder)") }
    $logged = @(Get-Content -LiteralPath $logFile)
    Test-LinesInOrder -Lines $logged -Expected @(('Memory dump:    ' + [regex]::Escape((ConvertTo-LogText $final.Dump)) + '$')) -Problems $problems -Where "collection_log.txt"
    Add-Result "summary: -NoCompress names the dump" $problems

    $final = Invoke-Final -Name "incomplete" -NoZip -Incomplete
    $problems = New-Problems
    Test-LinesInOrder -Lines $final.Screen -Expected @(('^  Memory dump:    INCOMPLETE, not for analysis: ' + [regex]::Escape("$($final.Dump).incomplete") + '$')) -Problems $problems -Where "screen"
    Add-Result "summary: incomplete dump named" $problems
}
catch {
    $failures++
    Write-Host "FAIL: test setup or run error: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" -ForegroundColor Red
}
finally {
    $env:SystemDrive = $savedSystemDrive
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
foreach ($r in $results) {
    $color = if ($r.Result -eq "PASS") { "Green" } else { "Red" }
    $line = "  {0}  {1}" -f $r.Result, $r.Case
    if ($r.Note) { $line = "  {0}  {1,-52} -- {2}" -f $r.Result, $r.Case, $r.Note }
    Write-Host $line -ForegroundColor $color
    if ($r.Result -ne "PASS" -and $env:GITHUB_ACTIONS) {
        Write-Host "::error file=tests/Test-MemorySpaceCheck.ps1::$($r.Case): $($r.Note)"
    }
}
if ($failures -gt 0 -or $results.Count -eq 0) {
    Write-Host "FAIL: $failures check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: $($results.Count) check(s)" -ForegroundColor Green
exit 0

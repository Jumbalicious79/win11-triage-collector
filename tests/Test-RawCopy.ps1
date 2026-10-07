# =============================================================
# Raw copy fallback test
# Creates test files on the system drive, locks them exclusively and checks
# that Copy-ForensicFile (triage-collector.ps1) still collects them, byte for
# byte, through the raw NTFS read -- the last fallback after a normal copy
# and the shadow copy (the shadow copy is switched off here, as on a machine
# where none can be made). Needs Administrator rights, like the collector
# (GitHub Actions Windows runners are elevated). Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-RawCopy.ps1
# =============================================================
param(
    # Collector script to test (default: the repository's triage-collector.ps1)
    [string]$CollectorPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$collector = $CollectorPath
if (-not $collector) { $collector = Join-Path $repoRoot "triage-collector.ps1" }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "FAIL: run this test as Administrator (raw volume reads need it)" -ForegroundColor Red
    exit 1
}

# --- Load the collector's functions without running a collection ---
# Every function definition that is not inside another function (many sit
# inside the collector's main try block), plus the C# source of the raw NTFS
# reader, taken from the script's syntax tree
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
$nodes = $ast.FindAll({
    param($node)
    ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) -or
    ($node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$script:triageNtfsSource')
}, $true)
foreach ($node in $nodes) {
    if (-not (Test-InsideFunction $node)) { $definitions.Add($node.Extent.Text) }
}
. ([scriptblock]::Create($definitions -join "`r`n"))
if (-not $script:triageNtfsSource -or -not (Get-Command Copy-ForensicFile -ErrorAction SilentlyContinue)) {
    Write-Host "FAIL: Copy-ForensicFile or the raw NTFS reader source not found in $collector" -ForegroundColor Red
    exit 1
}

# --- Collector state for a live collection of the system drive ---
$TargetDrive = $env:SystemDrive.TrimEnd(':')
$script:TargetRoot = "$env:SystemDrive\"
$script:IsLive = $true
$script:shadowUnavailable = $true
$script:shadowPath = $null
$script:ntfsReaderReady = $null
$script:rawFileReader = $null
$script:rawFileReaderUnavailable = $false
$script:logToFile = $true
$script:fileCount = 0
$script:errorCount = 0
$script:totalBytes = 0

$testId = [guid]::NewGuid().ToString("N").Substring(0, 8)
# Source files directly on the system drive: the raw reader resolves paths
# through the $MFT of that volume
$sourceDir = Join-Path $script:TargetRoot "TriageRawCopyTest_$testId"
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) "TriageRawCopyTest_$testId"
$OutputPath = Join-Path $workDir "collection"
$destDir = Join-Path $OutputPath "Files"
$logFile = Join-Path $workDir "collection_log.txt"
$manifestFile = Join-Path $OutputPath "collection_manifest.csv"

$random = New-Object System.Random 20261007
function New-RandomBytes {
    param([int]$Count)
    $bytes = New-Object byte[] $Count
    $random.NextBytes($bytes)
    return , $bytes
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
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

$locks = New-Object System.Collections.Generic.List[System.IO.FileStream]
$failures = 0
$results = New-Object System.Collections.Generic.List[object]

try {
    New-Item -ItemType Directory -Path $sourceDir, $destDir | Out-Null

    # --- Test files ---
    # Name: file name; Lock: hold it open with no sharing; Expect: Raw (raw
    # read collects it), Copy (normal copy), Refused (raw read must decline)
    $cases = New-Object System.Collections.Generic.List[object]

    # Data outside the MFT record, size not a whole number of clusters
    $path = Join-Path $sourceDir "large.bin"
    [System.IO.File]::WriteAllBytes($path, (New-RandomBytes (5MB + 123)))
    $cases.Add([PSCustomObject]@{ Name = "large.bin"; What = "5 MB file (data in clusters)"; Lock = $true; Expect = "Raw" })

    # Data stored inside the MFT record itself
    $path = Join-Path $sourceDir "small.bin"
    [System.IO.File]::WriteAllBytes($path, (New-RandomBytes 200))
    $cases.Add([PSCustomObject]@{ Name = "small.bin"; What = "200-byte file (data in the MFT record)"; Lock = $true; Expect = "Raw" })

    # Non-ASCII name with spaces and brackets
    $name = "R" + [char]0x00E9 + "sum" + [char]0x00E9 + " copy [1] (" + [char]0x00DF + ").txt"
    $path = Join-Path $sourceDir $name
    [System.IO.File]::WriteAllBytes($path, (New-RandomBytes 3000))
    $cases.Add([PSCustomObject]@{ Name = $name; What = "non-ASCII name with spaces"; Lock = $true; Expect = "Raw" })

    # Sparse file: 32 MB with data only at 0-1 MB and 20-21 MB; the holes have
    # no clusters on disk and must come out as zeros
    $path = Join-Path $sourceDir "sparse.bin"
    [System.IO.File]::WriteAllBytes($path, [byte[]]@())
    if ((Invoke-NativeTool "fsutil.exe" @("sparse", "setflag", $path)) -eq 0) {
        $stream = [System.IO.File]::Open($path, "Open", "ReadWrite", "None")
        try {
            $block = New-RandomBytes 1MB
            $stream.Write($block, 0, $block.Length)
            $stream.Position = 20MB
            $block = New-RandomBytes 1MB
            $stream.Write($block, 0, $block.Length)
            $stream.SetLength(32MB)
        } finally { $stream.Dispose() }
        $cases.Add([PSCustomObject]@{ Name = "sparse.bin"; What = "sparse file with holes"; Lock = $true; Expect = "Raw" })
    } else {
        Write-Host "  (sparse file case skipped: fsutil sparse setflag failed)"
    }

    # Valid data length below the file size: clusters past the written part
    # are allocated but hold old disk contents, which must read as zeros
    $path = Join-Path $sourceDir "preallocated.bin"
    $stream = [System.IO.File]::Open($path, "CreateNew", "ReadWrite", "None")
    try {
        $block = New-RandomBytes 1MB
        $stream.Write($block, 0, $block.Length)
        $stream.SetLength(4MB)
    } finally { $stream.Dispose() }
    $cases.Add([PSCustomObject]@{ Name = "preallocated.bin"; What = "file extended past its written data"; Lock = $true; Expect = "Raw" })

    # NTFS-compressed: not supported by the raw reader, which must decline
    # cleanly (logged, nothing left in the collection)
    $path = Join-Path $sourceDir "compressed.txt"
    [System.IO.File]::WriteAllText($path, ("compressible test text " * 20000))
    $compactExit = Invoke-NativeTool "compact.exe" @("/c", $path)
    if ($compactExit -eq 0 -and (([System.IO.File]::GetAttributes($path) -band [System.IO.FileAttributes]::Compressed) -ne 0)) {
        $cases.Add([PSCustomObject]@{ Name = "compressed.txt"; What = "NTFS-compressed file"; Lock = $true; Expect = "Refused" })
    } else {
        Write-Host "  (compressed file case skipped: this volume does not support NTFS compression)"
    }

    # Not locked: the normal copy must still be used
    $path = Join-Path $sourceDir "unlocked.bin"
    [System.IO.File]::WriteAllBytes($path, (New-RandomBytes 100KB))
    $cases.Add([PSCustomObject]@{ Name = "unlocked.bin"; What = "unlocked file"; Lock = $false; Expect = "Copy" })

    # Expected contents, then flush the volume so the $MFT and file data on
    # disk are current (the raw reader reads the disk, not the file cache)
    foreach ($case in $cases) {
        $case | Add-Member -NotePropertyName Source -NotePropertyValue (Join-Path $sourceDir $case.Name)
        $case | Add-Member -NotePropertyName Hash -NotePropertyValue (Get-Sha256 $case.Source)
    }
    Write-VolumeCache -DriveLetter $TargetDrive

    foreach ($case in @($cases | Where-Object { $_.Lock })) {
        $locks.Add([System.IO.File]::Open($case.Source, "Open", "Read", "None"))
    }

    # --- Collect each file the way the collector does ---
    Write-Host "Collecting $($cases.Count) test file(s) from $sourceDir ..."
    foreach ($case in $cases) {
        $errorsBefore = $script:errorCount
        $logBefore = @()
        if (Test-Path -LiteralPath $logFile) { $logBefore = @(Get-Content -LiteralPath $logFile) }

        Copy-ForensicFile -SourcePath $case.Source -DestDir $destDir

        $logNew = @()
        if (Test-Path -LiteralPath $logFile) { $logNew = @(Get-Content -LiteralPath $logFile | Select-Object -Skip $logBefore.Count) }
        $dest = Join-Path $destDir $case.Name
        $copied = Test-Path -LiteralPath $dest
        $viaRaw = @($logNew | Where-Object { $_ -match 'Collected by raw NTFS read' }).Count -gt 0
        $problem = ""

        switch ($case.Expect) {
            "Raw" {
                if (-not $copied) { $problem = "not collected" }
                elseif (-not $viaRaw) { $problem = "collected, but not by the raw NTFS read" }
                elseif ((Get-Sha256 $dest) -ne $case.Hash) { $problem = "copy differs from the original (SHA256)" }
            }
            "Copy" {
                if (-not $copied) { $problem = "not collected" }
                elseif ($viaRaw) { $problem = "used the raw NTFS read for an unlocked file" }
                elseif ((Get-Sha256 $dest) -ne $case.Hash) { $problem = "copy differs from the original (SHA256)" }
            }
            "Refused" {
                if ($copied) { $problem = "a file was left in the collection" }
                elseif ($script:errorCount -le $errorsBefore) { $problem = "the failure was not counted as an error" }
                elseif (-not @($logNew | Where-Object { $_ -match 'Raw NTFS read of .* failed: .*is compressed' }).Count) { $problem = "the log does not say the raw read declined a compressed file" }
            }
        }

        # Every collected file must have a manifest row with its hash
        if (-not $problem -and $copied) {
            $row = Import-Csv -LiteralPath $manifestFile -Header SHA256, SourcePath, DestPath, SizeBytes, CollectedAt, RelativePath, SourceCreatedUtc, SourceModifiedUtc, SourceAccessedUtc |
                Where-Object { $_.SourcePath -eq $case.Source } | Select-Object -Last 1
            if (-not $row) { $problem = "no manifest row" }
            elseif ($row.SHA256 -ne $case.Hash) { $problem = "manifest hash differs from the original" }
        }

        if ($problem) { $failures++ }
        $results.Add([PSCustomObject]@{
            Result = $(if ($problem) { "FAIL" } else { "PASS" })
            Case   = $case.What
            Expect = $case.Expect
            Note   = $problem
        })
    }
}
catch {
    $failures++
    Write-Host "FAIL: test setup or run error: $($_.Exception.Message)" -ForegroundColor Red
    if (Test-Path -LiteralPath $logFile) { Get-Content -LiteralPath $logFile | ForEach-Object { Write-Host "  | $_" } }
}
finally {
    foreach ($lock in $locks) { $lock.Dispose() }
    if ($script:rawFileReader) { $script:rawFileReader.Dispose() }
    Remove-Item -LiteralPath $sourceDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

foreach ($r in $results) {
    $color = if ($r.Result -eq "PASS") { "Green" } else { "Red" }
    $line = "  {0}  {1,-40} expected: {2}" -f $r.Result, $r.Case, $r.Expect
    if ($r.Note) { $line += " -- $($r.Note)" }
    Write-Host $line -ForegroundColor $color
    if ($r.Result -ne "PASS" -and $env:GITHUB_ACTIONS) {
        Write-Host "::error file=tests/Test-RawCopy.ps1::$($r.Case): $($r.Note)"
    }
}
if ($failures -gt 0 -or $results.Count -eq 0) {
    Write-Host "FAIL: $failures case(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: $($results.Count) case(s)" -ForegroundColor Green
exit 0

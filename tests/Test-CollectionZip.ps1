# =============================================================
# Collection zip test
# Checks New-CollectionZip (triage-collector.ps1), which zips the collection
# folder: every entry name uses '/' (the ZIP format's separator; the "\"
# that ZipFile.CreateFromDirectory writes in Windows PowerShell 5.1 stays
# part of the name in Linux tools) and starts with "<folder>/"; an empty
# folder gets its own entry; a hidden system file, a non-ASCII name and a
# name with [ ] are included; contents (SHA256) and file times (within the
# 2 seconds the zip format keeps) match. A zip path inside the folder is
# refused and a zip that fails (a locked file) is deleted, so no zip file
# is left behind. In Windows PowerShell 5.1 the .NET switch that makes
# CreateFromDirectory write '\' is read (and so cached) first, and a
# control zip made with CreateFromDirectory must have '\'. No admin rights
# needed. Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-CollectionZip.ps1
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
if (-not (Get-Command New-CollectionZip -ErrorAction SilentlyContinue)) {
    Write-Host "FAIL: New-CollectionZip not found in $collector" -ForegroundColor Red
    exit 1
}
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

# --- Test folder, named like a collection; the zip goes next to it ---
$testId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) "TriageCollectionZipTest_$testId"
$folderName = "TriageCollection_2026-01-02_03-04"
$sourceDir = Join-Path $workDir $folderName
$zipPath = "$sourceDir.zip"
$isWindowsPowerShell = ($PSVersionTable.PSEdition -ne "Core")

$random = New-Object System.Random 20261008
$sha256 = [System.Security.Cryptography.SHA256]::Create()
# Before 1980 a zip stores 1980-01-01; a fixed old time in March (no DST
# change nearby) checks that the original time is kept, not the copy time
$oldModified = New-Object DateTime 2019, 3, 4, 5, 6, 8, ([DateTimeKind]::Utc)
# Built from character codes so this file stays ASCII (Windows PowerShell
# 5.1 reads a script without BOM as ANSI): e-acute, Cyrillic, CJK
$nonAsciiName = "R" + [char]0x00E9 + "sum" + [char]0x00E9 + "_" + [char]0x0416 + [char]0x0443 + [char]0x0440 + "_" + [char]0x6587 + ".lnk"

# Relative path -> what the zip must hold for it
$fixtureFiles = New-Object System.Collections.Generic.List[object]
function New-FixtureFile {
    param([string]$RelativePath, [byte[]]$Bytes, [object]$Modified = $null, [switch]$HiddenSystem)
    $path = Join-Path $sourceDir $RelativePath
    New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllBytes($path, $Bytes)
    if ($Modified) { [System.IO.File]::SetLastWriteTimeUtc($path, $Modified) }
    if ($HiddenSystem) { [System.IO.File]::SetAttributes($path, [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System) }
    $fixtureFiles.Add([PSCustomObject]@{
        Rel       = $RelativePath
        Path      = $path
        EntryName = "$folderName/" + $RelativePath.Replace('\', '/')
        Hash      = [System.BitConverter]::ToString($sha256.ComputeHash($Bytes)).Replace("-", "")
        Modified  = [System.IO.File]::GetLastWriteTimeUtc($path)
    })
    return $path
}
function New-RandomBytes {
    param([int]$Size)
    $bytes = New-Object byte[] $Size
    $random.NextBytes($bytes)
    return , $bytes
}

# Entries of a zip, with each file's SHA256 and time
function Get-ZipEntries {
    param([string]$Path)
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        foreach ($entry in $archive.Entries) {
            $hash = ""
            if (-not $entry.FullName.EndsWith('/') -and -not $entry.FullName.EndsWith('\')) {
                $stream = $entry.Open()
                try { $hash = [System.BitConverter]::ToString($sha256.ComputeHash($stream)).Replace("-", "") }
                finally { $stream.Dispose() }
            }
            [PSCustomObject]@{
                Name             = $entry.FullName
                Length           = $entry.Length
                CompressedLength = $entry.CompressedLength
                ModifiedUtc      = $entry.LastWriteTime.UtcDateTime
                Hash             = $hash
            }
        }
    } finally {
        $archive.Dispose()
    }
}

# Calls New-CollectionZip the way the collector does: inside try/catch,
# with the collector's error preference. Returns the error message, or ""
function Invoke-CollectionZip {
    param([string]$SourceDir, [string]$ZipPath)
    $ErrorActionPreference = "Continue"
    try {
        New-CollectionZip -SourceDir $SourceDir -ZipPath $ZipPath
        return ""
    } catch {
        return "$($_.Exception.Message)"
    }
}

function Get-SourceFileCount {
    return @(Get-ChildItem -LiteralPath $sourceDir -Recurse -Force -File).Count
}

$lock = $null
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

try {
    # --- Fixture: nested folders, an empty folder, a hidden system file
    # (hives are; the collector clears the attributes first, but the zip
    # must not depend on it), a non-ASCII name, [ ] in a name, an empty
    # file, an old file time, and text that compresses well ---
    $infoText = ('{"Mode":"Live","Collector":"triage-collector.ps1","Note":"compressible test text"}' + "`r`n") * 64
    $infoPath = New-FixtureFile "collection_info.json" ([System.Text.Encoding]::ASCII.GetBytes($infoText))
    $hiddenPath = New-FixtureFile "Registry\Users\TriageTest\NTUSER.DAT" (New-RandomBytes 12288) -HiddenSystem
    $oldPath = New-FixtureFile "FileSystem\Nested\Deeper\old_file.bin" (New-RandomBytes 3000) -Modified $oldModified
    $lockedPath = New-FixtureFile "FileSystem\Nested\Deeper\zz_locked.bin" (New-RandomBytes 2048)
    $nonAsciiPath = New-FixtureFile "UserActivity\RecentLNK\$nonAsciiName" (New-RandomBytes 1500)
    $null = New-FixtureFile "UserActivity\RecentLNK\[draft] notes.txt" ([System.Text.Encoding]::ASCII.GetBytes("bracket name"))
    $null = New-FixtureFile "FileSystem\zero_bytes.txt" ([byte[]]@())
    $emptyDirRel = "Registry\WsiAccount\RecentFiles"
    New-Item -ItemType Directory -Path (Join-Path $sourceDir $emptyDirRel) -Force | Out-Null
    $emptyDirEntry = "$folderName/" + $emptyDirRel.Replace('\', '/') + "/"
    $expectedNames = @($fixtureFiles | ForEach-Object { $_.EntryName }) + @($emptyDirEntry)
    $sourceFileCount = Get-SourceFileCount

    # --- Windows PowerShell 5.1: read the switch first, then the control ---
    if ($isWindowsPowerShell) {
        # The switch's value is cached on its first read; reading it here
        # (as CreateFromDirectory does) means turning it off later would no
        # longer help, while New-CollectionZip must still write '/'
        $problems = New-Object System.Collections.Generic.List[string]
        $info = ""
        $switchType = [System.IO.Compression.ZipFile].Assembly.GetType("System.LocalAppContextSwitches")
        $switchProperty = $null
        if ($switchType) { $switchProperty = $switchType.GetProperty("ZipFileUseBackslash", [System.Reflection.BindingFlags]"Static, Public, NonPublic") }
        if ($switchProperty) {
            $useBackslash = $switchProperty.GetValue($null, $null)
            if ($useBackslash -ne $true) { $problems.Add("ZipFileUseBackslash is '$useBackslash', expected True in powershell.exe") }
            $info = "ZipFileUseBackslash read: $useBackslash"
        } else {
            $info = "internal switch not found; the control zip reads it"
        }
        Add-Result "5.1: UseBackslash switch read first" $problems -Info $info

        # Control: the call the collector used before writes '\' here
        $problems = New-Object System.Collections.Generic.List[string]
        $controlZip = Join-Path $workDir "control.zip"
        [System.IO.Compression.ZipFile]::CreateFromDirectory($sourceDir, $controlZip, [System.IO.Compression.CompressionLevel]::Optimal, $true)
        $controlNames = @(Get-ZipEntries $controlZip | ForEach-Object { $_.Name })
        $withSlash = @($controlNames | Where-Object { $_.Contains('/') })
        $withBackslash = @($controlNames | Where-Object { $_.Contains('\') })
        if ($controlNames.Count -eq 0) { $problems.Add("control zip is empty") }
        if ($withSlash.Count -gt 0 -or $withBackslash.Count -ne $controlNames.Count) {
            $problems.Add("CreateFromDirectory wrote $($withBackslash.Count) of $($controlNames.Count) names with '\' and $($withSlash.Count) with '/'")
        }
        Add-Result "5.1 control: CreateFromDirectory writes '\'" $problems
    }

    # --- The zip the collector makes: <folder>.zip next to the folder,
    # replacing a file of that name left by an earlier run ---
    [System.IO.File]::WriteAllBytes($zipPath, [System.Text.Encoding]::ASCII.GetBytes("not a zip"))
    $problems = New-Object System.Collections.Generic.List[string]
    $zipError = Invoke-CollectionZip -SourceDir $sourceDir -ZipPath $zipPath
    $entries = @()
    if ($zipError) {
        $problems.Add("failed: $zipError")
    } else {
        try { $entries = @(Get-ZipEntries $zipPath) } catch { $problems.Add("zip does not open: $($_.Exception.Message)") }
    }
    Add-Result "zip made, old file at its path replaced" $problems
    # Names compare case-sensitively (a PowerShell hashtable does not)
    $byName = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    foreach ($entry in $entries) { $byName[$entry.Name] = $entry }

    if ($entries.Count -gt 0) {
        $problems = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $entries) {
            if ($entry.Name.Contains('\')) { $problems.Add("'\' in $($entry.Name)") }
        }
        Add-Result "no '\' in any entry name" $problems

        $problems = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $entries) {
            if (-not $entry.Name.StartsWith("$folderName/", [System.StringComparison]::Ordinal)) { $problems.Add("$($entry.Name) does not start with '$folderName/'") }
        }
        Add-Result "every name starts with '<folder>/'" $problems

        # Exactly the fixture: each file once, the empty folder, and no
        # entry for a folder that has content
        $problems = New-Object System.Collections.Generic.List[string]
        $names = @($entries | ForEach-Object { $_.Name })
        foreach ($name in $expectedNames) {
            if (-not $byName.ContainsKey($name)) { $problems.Add("missing: $name") }
        }
        foreach ($name in $names) {
            if ($expectedNames -cnotcontains $name) { $problems.Add("unexpected: $name") }
        }
        if ($names.Count -ne $expectedNames.Count) { $problems.Add("$($names.Count) entries, expected $($expectedNames.Count)") }
        Add-Result "entry names and count" $problems -Info "$($names.Count) entries"

        $problems = New-Object System.Collections.Generic.List[string]
        if (-not $byName.ContainsKey($emptyDirEntry)) { $problems.Add("no entry $emptyDirEntry") }
        elseif ($byName[$emptyDirEntry].Length -ne 0) { $problems.Add("folder entry has $($byName[$emptyDirEntry].Length) bytes") }
        Add-Result "empty folder has its own entry" $problems

        $problems = New-Object System.Collections.Generic.List[string]
        $hiddenFile = $fixtureFiles | Where-Object { $_.Path -eq $hiddenPath }
        if (-not $byName.ContainsKey($hiddenFile.EntryName)) { $problems.Add("no entry $($hiddenFile.EntryName)") }
        Add-Result "hidden system file included" $problems

        $problems = New-Object System.Collections.Generic.List[string]
        $nonAsciiFile = $fixtureFiles | Where-Object { $_.Path -eq $nonAsciiPath }
        if (-not $byName.ContainsKey($nonAsciiFile.EntryName)) { $problems.Add("no entry with the non-ASCII name") }
        Add-Result "non-ASCII name kept" $problems

        $problems = New-Object System.Collections.Generic.List[string]
        foreach ($file in $fixtureFiles) {
            if ($byName.ContainsKey($file.EntryName) -and $byName[$file.EntryName].Hash -ne $file.Hash) { $problems.Add("$($file.Rel) differs") }
        }
        Add-Result "SHA256 of every file matches" $problems

        # The zip format keeps local time in 2-second steps
        $problems = New-Object System.Collections.Generic.List[string]
        foreach ($file in $fixtureFiles) {
            if (-not $byName.ContainsKey($file.EntryName)) { continue }
            $seconds = [math]::Abs(($byName[$file.EntryName].ModifiedUtc - $file.Modified).TotalSeconds)
            if ($seconds -gt 2) { $problems.Add("$($file.Rel): $($byName[$file.EntryName].ModifiedUtc.ToString('o')) vs $($file.Modified.ToString('o'))") }
        }
        $oldFile = $fixtureFiles | Where-Object { $_.Path -eq $oldPath }
        if ($oldFile.Modified -ne $oldModified) { $problems.Add("fixture time of old_file.bin not set") }
        Add-Result "file times kept (within 2 s)" $problems

        $problems = New-Object System.Collections.Generic.List[string]
        $infoFile = $fixtureFiles | Where-Object { $_.Path -eq $infoPath }
        if ($byName.ContainsKey($infoFile.EntryName)) {
            $infoEntry = $byName[$infoFile.EntryName]
            if ($infoEntry.CompressedLength * 2 -gt $infoEntry.Length) { $problems.Add("$($infoEntry.Length) bytes stored as $($infoEntry.CompressedLength)") }
        }
        Add-Result "text compressed" $problems
    }

    # --- The folder path given with a trailing '\' ---
    $problems = New-Object System.Collections.Generic.List[string]
    $trailingZip = Join-Path $workDir "trailing.zip"
    $zipError = Invoke-CollectionZip -SourceDir "$sourceDir\" -ZipPath $trailingZip
    if ($zipError) {
        $problems.Add("failed: $zipError")
    } else {
        $trailingNames = @(Get-ZipEntries $trailingZip | ForEach-Object { $_.Name })
        $differences = @(Compare-Object -ReferenceObject $expectedNames -DifferenceObject $trailingNames -CaseSensitive)
        if ($differences.Count -gt 0) { $problems.Add("names differ: $(($differences | ForEach-Object { $_.InputObject }) -join ', ')") }
    }
    Add-Result "folder path ending in '\'" $problems

    # --- A zip path inside the folder: "<folder>\.zip", what an -OutputPath
    # ending in '\' used to give ---
    $problems = New-Object System.Collections.Generic.List[string]
    $insideZip = Join-Path $sourceDir ".zip"
    $zipError = Invoke-CollectionZip -SourceDir $sourceDir -ZipPath $insideZip
    if (-not $zipError) { $problems.Add("no error") }
    elseif ($zipError -notmatch 'inside the folder being zipped') { $problems.Add("error: $zipError") }
    if (Test-Path -LiteralPath $insideZip) { $problems.Add("a file was left at $insideZip") }
    if ((Get-SourceFileCount) -ne $sourceFileCount) { $problems.Add("files in the folder changed") }
    Add-Result "zip path inside the folder refused" $problems

    # --- A failure part way (a file another program holds open without
    # sharing): the error names the file and the partial zip is deleted ---
    $problems = New-Object System.Collections.Generic.List[string]
    $failedZip = Join-Path $workDir "failed.zip"
    $lock = [System.IO.File]::Open($lockedPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        $zipError = Invoke-CollectionZip -SourceDir $sourceDir -ZipPath $failedZip
    } finally {
        $lock.Dispose()
        $lock = $null
    }
    if (-not $zipError) { $problems.Add("no error") }
    elseif ($zipError.IndexOf("zz_locked.bin", [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { $problems.Add("error does not name the locked file: $zipError") }
    if (Test-Path -LiteralPath $failedZip) { $problems.Add("partial zip left at $failedZip") }
    if ((Get-SourceFileCount) -ne $sourceFileCount) { $problems.Add("files in the folder changed") }
    Add-Result "failed zip deleted" $problems
}
catch {
    $failures++
    Write-Host "FAIL: test setup or run error: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    if ($lock) { $lock.Dispose() }
    $sha256.Dispose()
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
foreach ($r in $results) {
    $color = if ($r.Result -eq "PASS") { "Green" } else { "Red" }
    $line = "  {0}  {1}" -f $r.Result, $r.Case
    if ($r.Note) { $line = "  {0}  {1,-44} -- {2}" -f $r.Result, $r.Case, $r.Note }
    Write-Host $line -ForegroundColor $color
    if ($r.Result -ne "PASS" -and $env:GITHUB_ACTIONS) {
        Write-Host "::error file=tests/Test-CollectionZip.ps1::$($r.Case): $($r.Note)"
    }
}
if ($failures -gt 0 -or $results.Count -eq 0) {
    Write-Host "FAIL: $failures check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: $($results.Count) check(s)" -ForegroundColor Green
exit 0

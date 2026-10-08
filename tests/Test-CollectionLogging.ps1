# =============================================================
# Collection logging test
# Checks what the collector (triage-collector.ps1) logs and counts for:
#  - Copy-HiveFile, used for Amcache.hve and its .LOG1/.LOG2, and for
#    NTUSER.DAT / UsrClass.dat when reg save does not apply: the shadow copy
#    first, then the direct copy (raw NTFS read for a locked file). Each
#    file gets one outcome line naming the method that collected it; an
#    empty file is info; a shadow copy failure that the direct copy
#    recovers is no error; a file that is not collected is a warning and
#    one error, even when the direct copy has logged and counted its own
#    failure.
#  - Copy-ForensicFileSet, which gives the Recent LNK, jump-list, Prefetch
#    and task XML counts from $script:fileCount: a file saved under a
#    shortened name, or with [ ] in its name, still counts; an empty one
#    does not.
# Folders stand in for the shadow copy and the target volume, and a
# stand-in replaces the raw NTFS read, so no snapshot is made and no admin
# rights are needed (Test-RawCopy.ps1 covers the raw NTFS read itself).
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-CollectionLogging.ps1
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
if (-not (Get-Command Copy-HiveFile -ErrorAction SilentlyContinue)) {
    Write-Host "FAIL: Copy-HiveFile not found in $collector" -ForegroundColor Red
    exit 1
}

# --- Collector state for a live collection, folders as snapshot and volume ---
$testId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) "TriageLoggingTest_$testId"
$snapshotDir = Join-Path $workDir "snapshot"
$targetDir = Join-Path $workDir "target"
$rawDir = Join-Path $workDir "raw"
$OutputPath = Join-Path $workDir "collection"
$logFile = Join-Path $workDir "collection_log.txt"
$manifestFile = Join-Path $OutputPath "collection_manifest.csv"

$script:IsLive = $true
$script:TargetRoot = "$targetDir\"
# A real shadow copy path is \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN;
# the \\?\ prefix sends the snapshot paths through the same .NET path handling
$script:shadowPath = "\\?\$snapshotDir"
$script:shadowId = $null
$script:shadowUnavailable = $false
# The raw NTFS read needs admin rights: switched off, so a locked live file
# ends at "shadow copy and raw NTFS read also failed", except in the cases
# that switch on the stand-in below (RawRead)
$script:rawFileReader = $null
$script:rawFileReaderUnavailable = $true
$script:logToFile = $true
$script:fileCount = 0
$script:errorCount = 0
$script:totalBytes = 0

# Stand-in for the collector's raw NTFS read (which reads the volume and
# needs admin rights): copies the locked live file's bytes from a folder
# the test filled before locking it, and records the copy as the collector
# does. Off (returns $false like the real one) unless the case switches it on
function Copy-TriageRawFile {
    param([string]$SourcePath, [string]$DestPath, $SourceTimes = $null)
    if (-not $script:IsLive -or $script:rawFileReaderUnavailable) { return $false }
    [System.IO.File]::Copy((Join-Path $rawDir (Get-TargetRelativePath $SourcePath)), $DestPath, $true)
    Record-Manifest -SourcePath $SourcePath -DestPath $DestPath -SourceTimes $SourceTimes
    return $true
}

$random = New-Object System.Random 20261008

# Hidden test file under Root (hive files and their logs are hidden);
# returns its SHA256, or "" for no file (Size -1)
function New-TestFile {
    param([string]$Root, [string]$RelativePath, [int]$Size)
    if ($Size -lt 0) { return "" }
    $path = Join-Path $Root $RelativePath
    New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force | Out-Null
    $bytes = New-Object byte[] $Size
    $random.NextBytes($bytes)
    [System.IO.File]::WriteAllBytes($path, $bytes)
    [System.IO.File]::SetAttributes($path, [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::Archive)
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

function Get-LogLines {
    if (-not (Test-Path -LiteralPath $logFile)) { return @() }
    return @(Get-Content -LiteralPath $logFile)
}

function Get-ManifestRows {
    param([string]$SourcePath)
    if (-not (Test-Path -LiteralPath $manifestFile)) { return @() }
    return @(Import-Csv -LiteralPath $manifestFile -Encoding UTF8 -Header SHA256, SourcePath, DestPath, SizeBytes, CollectedAt, RelativePath, SourceCreatedUtc, SourceModifiedUtc, SourceAccessedUtc |
        Where-Object { $_.SourcePath -eq $SourcePath })
}

# Text as the collector's log stores it: Log/Log-Warning write with
# Add-Content (ANSI in Windows PowerShell 5.1, UTF-8 in 7), so characters of
# the temp path outside the code page come back as "?" in 5.1
function ConvertTo-LoggedText {
    param([string]$Text)
    $logEncoding = [System.Text.Encoding]::Default
    return $logEncoding.GetString($logEncoding.GetBytes($Text))
}

$locks = New-Object System.Collections.Generic.List[System.IO.FileStream]
$failures = 0
$results = New-Object System.Collections.Generic.List[object]

try {
    New-Item -ItemType Directory -Path $snapshotDir, $targetDir, $OutputPath -Force | Out-Null

    # Snapshot / Live: file size in the stand-in snapshot / on the volume,
    # -1 for no file; Lock*: another handle allows no sharing, so a copy
    # fails; NoShadow: no shadow copy (image mode, or none could be made);
    # RawRead: the raw NTFS read stand-in is on, so a locked live file is
    # read anyway. From: where the collected copy must come from ("" = not
    # collected).
    # Lines: the log lines the call must add, in order (regex; <rel> and
    # <live> stand for the relative path and the live file's path); a
    # "(.+)" group is the shadow copy's reason, which must name the file.
    # Errors: how much the error count must go up
    $unreadable = '\(locked; shadow copy and raw NTFS read also failed\): <live>$'
    $rawRead = '\] Collected by raw NTFS read \(file in use, not available from a shadow copy\): <live>$'
    $cases = @(
        [PSCustomObject]@{ What = "in the snapshot"; Rel = "Windows\AppCompat\Programs\Amcache.hve"; Label = "Amcache.hve"
            Snapshot = 8192; Live = 8192; LockSnapshot = $false; LockLive = $false; NoShadow = $false; RawRead = $false; From = "shadow"
            Lines = @('\] OK: Collected Amcache\.hve via shadow copy$'); Errors = 0 }
        [PSCustomObject]@{ What = "empty in the snapshot and live"; Rel = "Windows\AppCompat\Programs\Amcache.hve.LOG2"; Label = "Amcache.hve.LOG2"
            Snapshot = 0; Live = 0; LockSnapshot = $false; LockLive = $false; NoShadow = $false; RawRead = $false; From = ""
            Lines = @('\] Skipped empty file \(0 bytes in the shadow copy\): <rel>$'); Errors = 0 }
        [PSCustomObject]@{ What = "empty in the snapshot, written since"; Rel = "Windows\AppCompat\Programs\Amcache.hve.LOG1"; Label = "Amcache.hve.LOG1"
            Snapshot = 0; Live = 4096; LockSnapshot = $false; LockLive = $false; NoShadow = $false; RawRead = $false; From = "live"
            Lines = @('\] OK: Collected Amcache\.hve\.LOG1 via direct copy$'); Errors = 0 }
        [PSCustomObject]@{ What = "not in the snapshot"; Rel = "Users\Case04\NTUSER.DAT"; Label = "NTUSER.DAT for Case04"
            Snapshot = -1; Live = 4096; LockSnapshot = $false; LockLive = $false; NoShadow = $false; RawRead = $false; From = "live"
            Lines = @('\] OK: Collected NTUSER\.DAT for Case04 via direct copy$'); Errors = 0 }
        [PSCustomObject]@{ What = "snapshot unreadable, direct copy works"; Rel = "Users\Case05\NTUSER.DAT"; Label = "NTUSER.DAT for Case05"
            Snapshot = 4096; Live = 4096; LockSnapshot = $true; LockLive = $false; NoShadow = $false; RawRead = $false; From = "live"
            Lines = @('\] OK: Collected NTUSER\.DAT for Case05 via direct copy \(shadow copy: (.+)\)$'); Errors = 0 }
        [PSCustomObject]@{ What = "snapshot unreadable, no live file"; Rel = "Users\Case06\AppData\Local\Microsoft\Windows\UsrClass.dat"; Label = "UsrClass.dat for Case06"
            Snapshot = 4096; Live = -1; LockSnapshot = $true; LockLive = $false; NoShadow = $false; RawRead = $false; From = ""
            Lines = @('\] WARNING: Could not collect UsrClass\.dat for Case06 -- shadow copy: (.+)$'); Errors = 1 }
        [PSCustomObject]@{ What = "snapshot unreadable, live file empty"; Rel = "Users\Case07\NTUSER.DAT"; Label = "NTUSER.DAT for Case07"
            Snapshot = 4096; Live = 0; LockSnapshot = $true; LockLive = $false; NoShadow = $false; RawRead = $false; From = ""
            Lines = @('\] WARNING: Could not collect NTUSER\.DAT for Case07 -- shadow copy: (.+)$'); Errors = 1 }
        [PSCustomObject]@{ What = "snapshot and live file locked"; Rel = "Users\Case08\NTUSER.DAT"; Label = "NTUSER.DAT for Case08"
            Snapshot = 4096; Live = 4096; LockSnapshot = $true; LockLive = $true; NoShadow = $false; RawRead = $false; From = ""
            Lines = @(('\] WARNING: Could not copy ' + $unreadable), '\] WARNING: Could not collect NTUSER\.DAT for Case08 -- shadow copy: (.+)$'); Errors = 1 }
        [PSCustomObject]@{ What = "no shadow copy, direct copy works"; Rel = "Users\Case09\NTUSER.DAT"; Label = "NTUSER.DAT for Case09"
            Snapshot = -1; Live = 4096; LockSnapshot = $false; LockLive = $false; NoShadow = $true; RawRead = $false; From = "live"
            Lines = @('\] OK: Collected NTUSER\.DAT for Case09 via direct copy$'); Errors = 0 }
        [PSCustomObject]@{ What = "no shadow copy, empty file"; Rel = "Users\Case10\AppData\Local\Microsoft\Windows\UsrClass.dat"; Label = "UsrClass.dat for Case10"
            Snapshot = -1; Live = 0; LockSnapshot = $false; LockLive = $false; NoShadow = $true; RawRead = $false; From = ""
            Lines = @('\] Skipped empty file \(0 bytes\): <rel>$'); Errors = 0 }
        [PSCustomObject]@{ What = "no shadow copy, live file locked"; Rel = "Users\Case11\NTUSER.DAT"; Label = "NTUSER.DAT for Case11"
            Snapshot = -1; Live = 4096; LockSnapshot = $false; LockLive = $true; NoShadow = $true; RawRead = $false; From = ""
            Lines = @(('\] WARNING: Could not copy ' + $unreadable), '\] WARNING: Could not collect NTUSER\.DAT for Case11$'); Errors = 1 }
        [PSCustomObject]@{ What = "in neither snapshot nor volume"; Rel = "Users\Case12\NTUSER.DAT"; Label = "NTUSER.DAT for Case12"
            Snapshot = -1; Live = -1; LockSnapshot = $false; LockLive = $false; NoShadow = $false; RawRead = $false; From = ""
            Lines = @('\] WARNING: NTUSER\.DAT for Case12 not found at <live>$'); Errors = 0 }
        [PSCustomObject]@{ What = "no shadow copy, locked, raw read works"; Rel = "Users\Case13\NTUSER.DAT"; Label = "NTUSER.DAT for Case13"
            Snapshot = -1; Live = 4096; LockSnapshot = $false; LockLive = $true; NoShadow = $true; RawRead = $true; From = "live"
            Lines = @($rawRead, '\] OK: Collected NTUSER\.DAT for Case13 via raw NTFS read$'); Errors = 0 }
        [PSCustomObject]@{ What = "both locked, raw read works"; Rel = "Users\Case14\AppData\Local\Microsoft\Windows\UsrClass.dat"; Label = "UsrClass.dat for Case14"
            Snapshot = 4096; Live = 4096; LockSnapshot = $true; LockLive = $true; NoShadow = $false; RawRead = $true; From = "live"
            Lines = @($rawRead, '\] OK: Collected UsrClass\.dat for Case14 via raw NTFS read \(shadow copy: (.+)\)$'); Errors = 0 }
    )

    # --- Collect each file the way the collector does ---
    $caseNumber = 0
    foreach ($case in $cases) {
        $caseNumber++
        Write-Host "Case: $($case.What) ($($case.Rel))"
        $livePath = $script:TargetRoot.TrimEnd('\') + '\' + $case.Rel
        $snapshotHash = New-TestFile -Root $snapshotDir -RelativePath $case.Rel -Size $case.Snapshot
        $liveHash = New-TestFile -Root $targetDir -RelativePath $case.Rel -Size $case.Live
        if ($case.RawRead) {
            # What the raw NTFS read stand-in reads for the locked live file
            $rawCopy = Join-Path $rawDir $case.Rel
            New-Item -ItemType Directory -Path (Split-Path $rawCopy -Parent) -Force | Out-Null
            [System.IO.File]::Copy($livePath, $rawCopy, $true)
        }
        if ($case.LockSnapshot) { $locks.Add([System.IO.File]::Open((Join-Path $snapshotDir $case.Rel), "Open", "Read", "None")) }
        if ($case.LockLive) { $locks.Add([System.IO.File]::Open($livePath, "Open", "Read", "None")) }
        $destDir = Join-Path $OutputPath "Registry\Case$caseNumber"
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null

        $logBefore = Get-LogLines
        $errorsBefore = $script:errorCount
        $filesBefore = $script:fileCount
        $savedShadowPath = $script:shadowPath
        if ($case.NoShadow) {
            $script:shadowPath = $null
            $script:shadowUnavailable = $true
        }
        if ($case.RawRead) { $script:rawFileReaderUnavailable = $false }

        # The collector's own error preference: with Stop, Windows
        # PowerShell 5.1 turns stderr of the "cmd /c copy" fallback into a
        # terminating error, which never happens in a collection
        $ErrorActionPreference = "Continue"
        try {
            $returned = @(Copy-HiveFile -RelativePath $case.Rel -DestDir $destDir -Label $case.Label)
        } finally {
            $ErrorActionPreference = "Stop"
            $script:shadowPath = $savedShadowPath
            $script:shadowUnavailable = $false
            $script:rawFileReaderUnavailable = $true
        }

        $logNew = @(Get-LogLines | Select-Object -Skip $logBefore.Count)
        $dest = Join-Path $destDir ([System.IO.Path]::GetFileName($case.Rel))
        $shadowRows = @(Get-ManifestRows "(shadow)$($case.Rel)")
        $liveRows = @(Get-ManifestRows $livePath)
        $problems = New-Object System.Collections.Generic.List[string]

        if ($returned.Count -gt 0) { $problems.Add("returned output: $($returned -join ', ')") }
        if (($script:errorCount - $errorsBefore) -ne $case.Errors) {
            $problems.Add("error count went up by $($script:errorCount - $errorsBefore), expected $($case.Errors)")
        }

        # Log: exactly the expected lines, in order
        $patterns = @(foreach ($line in $case.Lines) {
            $line.Replace('<rel>', [regex]::Escape($case.Rel)).Replace('<live>', [regex]::Escape((ConvertTo-LoggedText $livePath)))
        })
        if ($logNew.Count -ne $patterns.Count) {
            $problems.Add("log: expected $($patterns.Count) line(s), got: $($logNew -join ' | ')")
        } else {
            for ($i = 0; $i -lt $patterns.Count; $i++) {
                if ($logNew[$i] -notmatch $patterns[$i]) {
                    $problems.Add("log line $($i + 1) does not match '$($patterns[$i])': $($logNew[$i])")
                } elseif ($Matches.Count -gt 1 -and $Matches[1].IndexOf([System.IO.Path]::GetFileName($case.Rel), [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
                    # The reason is the copy exception's message, which names
                    # the file, not a generic text
                    $problems.Add("shadow copy reason is not the copy error: $($Matches[1])")
                }
            }
        }

        # Collected: the copy from the expected source, its one manifest row
        # and one more file counted; otherwise nothing left behind
        if ($case.From) {
            $expectHash = $liveHash
            $expectShadowRows = 0
            if ($case.From -eq "shadow") { $expectHash = $snapshotHash; $expectShadowRows = 1 }
            if (-not (Test-Path -LiteralPath $dest)) {
                $problems.Add("no copy in the collection")
            } elseif ((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -ne $expectHash) {
                $problems.Add("copy differs from the $($case.From) file (SHA256)")
            }
            if ($shadowRows.Count -ne $expectShadowRows -or $liveRows.Count -ne (1 - $expectShadowRows)) {
                $problems.Add("manifest: $($shadowRows.Count) shadow and $($liveRows.Count) live row(s), expected one $($case.From) row")
            }
            if (($script:fileCount - $filesBefore) -ne 1) { $problems.Add("file count went up by $($script:fileCount - $filesBefore)") }
        } else {
            if (Test-Path -LiteralPath $dest) { $problems.Add("a file was left in the collection") }
            if ($shadowRows.Count + $liveRows.Count -gt 0) { $problems.Add("manifest row written") }
            if ($script:fileCount -ne $filesBefore) { $problems.Add("file count changed") }
        }

        if ($problems.Count -gt 0) { $failures++ }
        $results.Add([PSCustomObject]@{
            Result = $(if ($problems.Count -gt 0) { "FAIL" } else { "PASS" })
            Case   = $case.What
            Expect = $(if ($case.From) { "from $($case.From)" } else { "$($case.Errors) error(s)" })
            Note   = ($problems -join "; ")
        })
    }

    # --- Recent LNK count (Copy-ForensicFileSet) ---
    # A name over 100 characters is saved shortened (name~hash.lnk), [ ] are
    # no wildcards, and an empty file is skipped. The long name is kept
    # just over the cap: Windows PowerShell 5.1 cannot create its source
    # file once the whole path passes MAX_PATH (deep TEMP folders)
    Write-Host "Case: Recent LNK count"
    $recentRel = "Users\Case15\Recent"
    $recentSource = Join-Path $targetDir $recentRel
    $longName = "Search results for " + ("a" * 80) + ".lnk"
    $null = New-TestFile -Root $targetDir -RelativePath "$recentRel\$longName" -Size 512
    $null = New-TestFile -Root $targetDir -RelativePath "$recentRel\Report [draft].lnk" -Size 512
    $null = New-TestFile -Root $targetDir -RelativePath "$recentRel\Plain.lnk" -Size 512
    $null = New-TestFile -Root $targetDir -RelativePath "$recentRel\Empty.lnk" -Size 0
    $recentDest = Join-Path $OutputPath "UserActivity\Case15\RecentFiles"
    New-Item -ItemType Directory -Path $recentDest -Force | Out-Null

    $logBefore = Get-LogLines
    $errorsBefore = $script:errorCount
    $filesBefore = $script:fileCount
    $problems = New-Object System.Collections.Generic.List[string]
    $ErrorActionPreference = "Continue"
    try {
        $lnkFiles = Get-ChildItem -LiteralPath $recentSource -Filter "*.lnk" -Force -ErrorAction SilentlyContinue
        $returned = @(Copy-ForensicFileSet -Files $lnkFiles -DestDir $recentDest)
    } finally {
        $ErrorActionPreference = "Stop"
    }
    $saved = @(Get-ChildItem -LiteralPath $recentDest -Force -File)
    if ($returned.Count -ne 1 -or $returned[0] -isnot [int] -or $returned[0] -ne 3) { $problems.Add("returned '$($returned -join ', ')' instead of 3") }
    if (($script:fileCount - $filesBefore) -ne 3) { $problems.Add("file count went up by $($script:fileCount - $filesBefore)") }
    if ($saved.Count -ne 3) { $problems.Add("$($saved.Count) file(s) saved, expected 3") }
    if (Test-Path -LiteralPath (Join-Path $recentDest $longName)) { $problems.Add("long name saved unshortened") }
    if (@($saved | Where-Object { $_.Name -match '^Search.*~[0-9A-F]{8}\.lnk$' -and $_.Name.Length -le 100 }).Count -ne 1) {
        $problems.Add("no shortened copy of the long name: $($saved.Name -join ', ')")
    }
    if (-not (Test-Path -LiteralPath (Join-Path $recentDest "Report [draft].lnk"))) { $problems.Add("[ ] name not saved under its own name") }
    if ($script:errorCount -ne $errorsBefore) { $problems.Add("error count changed") }
    $logNew = @(Get-LogLines | Select-Object -Skip $logBefore.Count)
    if ($logNew.Count -gt 0) { $problems.Add("logged: $($logNew -join ' | ')") }
    if ($problems.Count -gt 0) { $failures++ }
    $results.Add([PSCustomObject]@{
        Result = $(if ($problems.Count -gt 0) { "FAIL" } else { "PASS" })
        Case   = "Recent LNK count"
        Expect = "3 counted"
        Note   = ($problems -join "; ")
    })
}
catch {
    $failures++
    Write-Host "FAIL: test setup or run error: $($_.Exception.Message)" -ForegroundColor Red
    if (Test-Path -LiteralPath $logFile) { Get-Content -LiteralPath $logFile | ForEach-Object { Write-Host "  | $_" } }
}
finally {
    foreach ($lock in $locks) { $lock.Dispose() }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

foreach ($r in $results) {
    $color = if ($r.Result -eq "PASS") { "Green" } else { "Red" }
    $line = "  {0}  {1,-38} expected: {2}" -f $r.Result, $r.Case, $r.Expect
    if ($r.Note) { $line += " -- $($r.Note)" }
    Write-Host $line -ForegroundColor $color
    if ($r.Result -ne "PASS" -and $env:GITHUB_ACTIONS) {
        Write-Host "::error file=tests/Test-CollectionLogging.ps1::$($r.Case): $($r.Note)"
    }
}
if ($failures -gt 0 -or $results.Count -eq 0) {
    Write-Host "FAIL: $failures case(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: $($results.Count) case(s)" -ForegroundColor Green
exit 0

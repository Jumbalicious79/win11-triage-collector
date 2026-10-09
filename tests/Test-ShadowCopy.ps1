# =============================================================
# Shadow copy outcome test
# Checks how Copy-FromShadow (triage-collector.ps1) reports each outcome of
# a copy from the Volume Shadow Copy: a non-empty file is copied and listed
# in the manifest; a file that is 0 bytes in the snapshot (like an unused
# hive .LOG2) is logged as skipped and is not an error; a file missing from
# the snapshot is "Not present"; a failed copy is a warning that gives the
# reason and counts one error; -Quiet leaves all reporting to the caller.
# Also checks $script:lastShadowCopyResult for every case, and the SRUM
# collection (Copy-TriageSrumFiles), which reports each outcome itself: an
# empty snapshot file is an info line, not an error, and a failed copy
# gives the reason. A folder stands in for the shadow copy, so no snapshot
# is made and no admin rights are needed. Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-ShadowCopy.ps1
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
if (-not (Get-Command Copy-FromShadow -ErrorAction SilentlyContinue)) {
    Write-Host "FAIL: Copy-FromShadow not found in $collector" -ForegroundColor Red
    exit 1
}

# --- Collector state for a live collection, a folder as the shadow copy ---
$testId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) "TriageShadowCopyTest_$testId"
$snapshotDir = Join-Path $workDir "snapshot"
$targetDir = Join-Path $workDir "target"
$OutputPath = Join-Path $workDir "collection"
$destDir = Join-Path $OutputPath "Registry"
$logFile = Join-Path $workDir "collection_log.txt"
$manifestFile = Join-Path $OutputPath "collection_manifest.csv"

$script:IsLive = $true
$script:TargetRoot = "$targetDir\"
# A real shadow copy path is \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN;
# the \\?\ prefix sends the snapshot paths through the same .NET path handling
$script:shadowPath = "\\?\$snapshotDir"
$script:shadowId = $null
$script:shadowUnavailable = $false
$script:logToFile = $true
$script:fileCount = 0
$script:errorCount = 0
$script:totalBytes = 0

$random = New-Object System.Random 20261008
$snapshotModified = New-Object DateTime 2026, 1, 2, 3, 4, 5, ([DateTimeKind]::Utc)

# Hidden test file in the stand-in snapshot (hive files and their logs are
# hidden; hidden copies were once deleted as "empty")
function New-SnapshotFile {
    param([string]$RelativePath, [int]$Size)
    $path = Join-Path $snapshotDir $RelativePath
    New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force | Out-Null
    $bytes = New-Object byte[] $Size
    $random.NextBytes($bytes)
    [System.IO.File]::WriteAllBytes($path, $bytes)
    [System.IO.File]::SetLastWriteTimeUtc($path, $snapshotModified)
    [System.IO.File]::SetAttributes($path, [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::Archive)
    return $path
}

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

$locks = New-Object System.Collections.Generic.List[System.IO.FileStream]
$failures = 0
$results = New-Object System.Collections.Generic.List[object]

try {
    New-Item -ItemType Directory -Path $snapshotDir, $targetDir, $destDir -Force | Out-Null

    # --- Test files in the stand-in snapshot ---
    $copiedRel = "Windows\AppCompat\Programs\Amcache.hve.LOG1"
    $copiedHash = (Get-FileHash -LiteralPath (New-SnapshotFile $copiedRel 49152) -Algorithm SHA256).Hash
    $emptyRel = "Windows\AppCompat\Programs\Amcache.hve.LOG2"
    $null = New-SnapshotFile $emptyRel 0
    $emptyQuietRel = "Windows\System32\config\SOFTWARE.LOG2"
    $null = New-SnapshotFile $emptyQuietRel 0
    $missingRel = "Users\TriageTest\AppData\Local\Microsoft\Windows\UsrClass.dat"
    $lockedRel = "Users\TriageTest\NTUSER.DAT"
    $lockedPath = New-SnapshotFile $lockedRel 8192
    $noShadowRel = "Windows\AppCompat\Programs\Amcache.hve"
    $null = New-SnapshotFile $noShadowRel 4096

    # The copy fails while another handle allows no sharing
    $locks.Add([System.IO.File]::Open($lockedPath, "Open", "Read", "None"))

    # Expect: lastShadowCopyResult; Log: the one log line the call must add
    # (regex), none if empty; Errors: how much the error count must go up
    $cases = @(
        [PSCustomObject]@{ What = "non-empty hidden file"; Rel = $copiedRel; Quiet = $false; NoShadow = $false; Expect = "Copied"
            Log = ""; Errors = 0 }
        [PSCustomObject]@{ What = "empty hidden file"; Rel = $emptyRel; Quiet = $false; NoShadow = $false; Expect = "Empty"
            Log = '\] Skipped empty file \(0 bytes in the shadow copy\): ' + [regex]::Escape($emptyRel) + '$'; Errors = 0 }
        [PSCustomObject]@{ What = "file not in the snapshot"; Rel = $missingRel; Quiet = $false; NoShadow = $false; Expect = "NotFound"
            Log = '\] Not present in shadow copy: ' + [regex]::Escape($missingRel) + '$'; Errors = 0 }
        [PSCustomObject]@{ What = "locked file (copy fails)"; Rel = $lockedRel; Quiet = $false; NoShadow = $false; Expect = "Failed"
            Log = '\] WARNING: Shadow copy of ' + [regex]::Escape($lockedRel) + ' did not produce output file -- (.+)$'; Errors = 1 }
        [PSCustomObject]@{ What = "empty hidden file, -Quiet"; Rel = $emptyQuietRel; Quiet = $true; NoShadow = $false; Expect = "Empty"
            Log = ""; Errors = 0 }
        [PSCustomObject]@{ What = "file not in the snapshot, -Quiet"; Rel = $missingRel; Quiet = $true; NoShadow = $false; Expect = "NotFound"
            Log = ""; Errors = 0 }
        [PSCustomObject]@{ What = "locked file, -Quiet"; Rel = $lockedRel; Quiet = $true; NoShadow = $false; Expect = "Failed"
            Log = ""; Errors = 0 }
        [PSCustomObject]@{ What = "no shadow copy available"; Rel = $noShadowRel; Quiet = $true; NoShadow = $true; Expect = "Failed"
            Log = ""; Errors = 0 }
    )

    # --- Copy each file the way the collector does ---
    foreach ($case in $cases) {
        Write-Host "Case: $($case.What) ($($case.Rel))"
        $logBefore = Get-LogLines
        $errorsBefore = $script:errorCount
        $filesBefore = $script:fileCount
        $savedShadowPath = $script:shadowPath
        if ($case.NoShadow) {
            # As after a failed shadow copy creation, or in mounted image mode
            $script:shadowPath = $null
            $script:shadowUnavailable = $true
        }

        # The collector's own error preference: with Stop, Windows
        # PowerShell 5.1 turns stderr of the "cmd /c copy" fallback into a
        # terminating error, which never happens in a collection
        $ErrorActionPreference = "Continue"
        try {
            $returned = @(Copy-FromShadow -RelativePath $case.Rel -DestDir $destDir -Quiet:$case.Quiet)
        } finally {
            $ErrorActionPreference = "Stop"
            $script:shadowPath = $savedShadowPath
            $script:shadowUnavailable = $false
        }

        $logNew = @(Get-LogLines | Select-Object -Skip $logBefore.Count)
        $dest = Join-Path $destDir ([System.IO.Path]::GetFileName($case.Rel))
        $rows = @(Get-ManifestRows "(shadow)$($case.Rel)")
        $problems = New-Object System.Collections.Generic.List[string]

        $expectReturn = ($case.Expect -eq "Copied")
        if ($returned.Count -ne 1 -or $returned[0] -isnot [bool] -or $returned[0] -ne $expectReturn) {
            $problems.Add("returned '$($returned -join ', ')' instead of $expectReturn")
        }
        if ($script:lastShadowCopyResult -ne $case.Expect) {
            $problems.Add("lastShadowCopyResult is '$($script:lastShadowCopyResult)'")
        }
        if ($case.Expect -eq "Failed") {
            if (-not $script:lastShadowCopyReason) { $problems.Add("lastShadowCopyReason is empty") }
        } elseif ($script:lastShadowCopyReason) {
            $problems.Add("lastShadowCopyReason is set: $($script:lastShadowCopyReason)")
        }
        if (($script:errorCount - $errorsBefore) -ne $case.Errors) {
            $problems.Add("error count went up by $($script:errorCount - $errorsBefore), expected $($case.Errors)")
        }

        # Log: exactly the expected line, or nothing
        if ($case.Log) {
            if ($logNew.Count -ne 1 -or $logNew[0] -notmatch $case.Log) {
                $problems.Add("log: expected one line matching '$($case.Log)', got: $($logNew -join ' | ')")
            } elseif ($case.Expect -eq "Failed") {
                # The warning gives the reason: the copy exception's message,
                # which names the file, not a generic text. Log-Warning writes
                # with Add-Content (ANSI in Windows PowerShell 5.1, UTF-8 in
                # 7): compare with the reason as that encoding stores it, as
                # characters of the temp path outside the code page come back
                # as "?" in 5.1
                $reason = $Matches[1]
                $logEncoding = [System.Text.Encoding]::Default
                $loggedReason = $logEncoding.GetString($logEncoding.GetBytes($script:lastShadowCopyReason))
                if ($reason -ne $loggedReason) { $problems.Add("warning reason differs from lastShadowCopyReason") }
                if ($reason.IndexOf([System.IO.Path]::GetFileName($case.Rel), [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
                    $problems.Add("warning reason is not the copy error: $reason")
                }
            }
        } elseif ($logNew.Count -gt 0) {
            $problems.Add("logged: $($logNew -join ' | ')")
        }

        # Collected: the copy, its manifest row with the snapshot's hash and
        # times, and one more file counted; otherwise nothing left behind
        if ($case.Expect -eq "Copied") {
            if (-not (Test-Path -LiteralPath $dest)) {
                $problems.Add("no copy in the collection")
            } elseif ((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -ne $copiedHash) {
                $problems.Add("copy differs from the snapshot file (SHA256)")
            }
            if ($rows.Count -ne 1) {
                $problems.Add("$($rows.Count) manifest row(s) instead of 1")
            } else {
                $row = $rows[0]
                if ($row.SHA256 -ne $copiedHash) { $problems.Add("manifest hash differs from the snapshot file") }
                if ($row.SizeBytes -ne "49152") { $problems.Add("manifest size is $($row.SizeBytes)") }
                if ($row.RelativePath -ne "Registry\Amcache.hve.LOG1") { $problems.Add("manifest RelativePath is $($row.RelativePath)") }
                if ($row.SourceModifiedUtc -ne $snapshotModified.ToString("o")) { $problems.Add("manifest SourceModifiedUtc is $($row.SourceModifiedUtc), not the snapshot file's time") }
            }
            if (($script:fileCount - $filesBefore) -ne 1) { $problems.Add("file count went up by $($script:fileCount - $filesBefore)") }
        } else {
            if (Test-Path -LiteralPath $dest) { $problems.Add("a file was left in the collection") }
            if ($rows.Count -gt 0) { $problems.Add("manifest row written") }
            if ($script:fileCount -ne $filesBefore) { $problems.Add("file count changed") }
        }

        if ($problems.Count -gt 0) { $failures++ }
        $results.Add([PSCustomObject]@{
            Result = $(if ($problems.Count -gt 0) { "FAIL" } else { "PASS" })
            Case   = $case.What
            Expect = $case.Expect
            Note   = ($problems -join "; ")
        })
    }

    # --- A caller that reports the outcome itself: the SRUM collection ---
    # When SRUDB.dat can be read from the shadow copy, Copy-TriageSrumFiles
    # takes every SRUM file from there with -Quiet and logs each outcome: a
    # file that is 0 bytes in the snapshot is an info line, not an error; a
    # failed copy is a warning with the reason. When SRUDB.dat itself cannot
    # be read there, the info line gives the reason and the files come from
    # the volume (where an empty file is skipped silently)
    function Add-SrumResult {
        param([string]$What, [string]$Expect, [System.Collections.Generic.List[string]]$Problems)
        if ($Problems.Count -gt 0) { $script:failures++ }
        $results.Add([PSCustomObject]@{
            Result = $(if ($Problems.Count -gt 0) { "FAIL" } else { "PASS" })
            Case   = $What
            Expect = $Expect
            Note   = ($Problems -join "; ")
        })
    }
    # Runs Copy-TriageSrumFiles on the volume's sru folder; returns the log
    # lines it added, how much the error count went up and the files copied
    function Invoke-SrumCopy {
        param([string]$DestDir)
        $logBefore = Get-LogLines
        $errorsBefore = $script:errorCount
        # As above: the collector's own error preference
        $ErrorActionPreference = "Continue"
        Copy-TriageSrumFiles -SourceDir $volumeSru -DestDir $DestDir -MaxBytes 16GB
        $names = [string[]]@(Get-ChildItem -LiteralPath $DestDir -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        [System.Array]::Sort($names, [System.StringComparer]::Ordinal)
        return [PSCustomObject]@{
            Log    = @(Get-LogLines | Select-Object -Skip $logBefore.Count)
            Errors = $script:errorCount - $errorsBefore
            Files  = ($names -join ", ")
        }
    }

    # The same SRUM file names in the snapshot and on the volume;
    # SRUtmp.log is empty in both, SRU.log is locked in the snapshot
    $sruRel = "Windows\System32\sru"
    $volumeSru = Join-Path $targetDir $sruRel
    New-Item -ItemType Directory -Path $volumeSru -Force | Out-Null
    $sruSizes = [ordered]@{ "SRUDB.dat" = 65536; "SRU.chk" = 8192; "SRU.log" = 16384; "SRUtmp.log" = 0 }
    foreach ($name in $sruSizes.Keys) {
        $null = New-SnapshotFile "$sruRel\$name" $sruSizes[$name]
        $bytes = New-Object byte[] $sruSizes[$name]
        $random.NextBytes($bytes)
        [System.IO.File]::WriteAllBytes((Join-Path $volumeSru $name), $bytes)
    }
    $locks.Add([System.IO.File]::Open((Join-Path $snapshotDir "$sruRel\SRU.log"), "Open", "Read", "None"))

    Write-Host "Case: SRUM collection from the snapshot ($sruRel)"
    $srum = Invoke-SrumCopy (Join-Path $OutputPath "Execution\SRUM")

    $problems = New-Object System.Collections.Generic.List[string]
    $emptyPattern = '\] Skipped empty file \(0 bytes in the shadow copy\): ' + [regex]::Escape("$sruRel\SRUtmp.log") + '$'
    if (@($srum.Log | Where-Object { $_ -match $emptyPattern }).Count -ne 1) { $problems.Add("no info line for the empty SRUtmp.log") }
    $emptyWarnings = @($srum.Log | Where-Object { $_ -match 'WARNING' -and $_ -match 'SRUtmp\.log' })
    if ($emptyWarnings.Count -gt 0) { $problems.Add("warning: $($emptyWarnings -join ' | ')") }
    Add-SrumResult -What "SRUM: empty file in the snapshot" -Expect "info, no error" -Problems $problems

    $problems = New-Object System.Collections.Generic.List[string]
    $lockedPattern = '\] WARNING: Could not copy SRUM file SRU\.log from the shadow copy -- (.+)$'
    $lockedLines = @($srum.Log | Where-Object { $_ -match $lockedPattern })
    if ($lockedLines.Count -ne 1) {
        $problems.Add("log: expected one line matching '$lockedPattern', got: $($srum.Log -join ' | ')")
    } elseif ($lockedLines[0] -match $lockedPattern -and $Matches[1].IndexOf("SRU.log", [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        $problems.Add("warning reason is not the copy error: $($Matches[1])")
    }
    if ($srum.Errors -ne 1) { $problems.Add("error count went up by $($srum.Errors), expected 1 (the locked file only)") }
    Add-SrumResult -What "SRUM: locked file in the snapshot" -Expect "warning with reason" -Problems $problems

    $problems = New-Object System.Collections.Generic.List[string]
    if ($srum.Files -ne "SRU.chk, SRUDB.dat") { $problems.Add("collected: $($srum.Files)") }
    if (@($srum.Log | Where-Object { $_ -match 'OK: Collected 2 SRUM file\(s\) \(from the shadow copy\)\.$' }).Count -ne 1) { $problems.Add("no 'Collected 2 SRUM file(s) (from the shadow copy)' line") }
    Add-SrumResult -What "SRUM: non-empty files copied" -Expect "Copied" -Problems $problems

    # SRUDB.dat locked in the snapshot too: everything from the volume
    $locks.Add([System.IO.File]::Open((Join-Path $snapshotDir "$sruRel\SRUDB.dat"), "Open", "Read", "None"))
    Write-Host "Case: SRUM collection, SRUDB.dat locked in the snapshot"
    $srum = Invoke-SrumCopy (Join-Path $OutputPath "Execution2\SRUM")
    $problems = New-Object System.Collections.Generic.List[string]
    $dbPattern = '\] SRUDB\.dat could not be read from the shadow copy \((.+)\) -- the SRUM files are copied from the volume '
    $dbLines = @($srum.Log | Where-Object { $_ -match $dbPattern })
    if ($dbLines.Count -ne 1) {
        $problems.Add("log: expected one line matching '$dbPattern', got: $($srum.Log -join ' | ')")
    } elseif ($dbLines[0] -match $dbPattern -and $Matches[1].IndexOf("SRUDB.dat", [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        $problems.Add("reason is not the copy error: $($Matches[1])")
    }
    $warnings = @($srum.Log | Where-Object { $_ -match 'WARNING' })
    if ($warnings.Count -gt 0 -or $srum.Errors -ne 0) { $problems.Add("$($srum.Errors) error(s), warnings: $($warnings -join ' | ')") }
    if ($srum.Files -ne "SRU.chk, SRU.log, SRUDB.dat") { $problems.Add("collected: $($srum.Files)") }
    if (@($srum.Log | Where-Object { $_ -match 'OK: Collected 3 SRUM file\(s\) \(from the volume\)\.$' }).Count -ne 1) { $problems.Add("no 'Collected 3 SRUM file(s) (from the volume)' line") }
    Add-SrumResult -What "SRUM: SRUDB.dat locked" -Expect "reason, from the volume" -Problems $problems
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
    $line = "  {0}  {1,-34} expected: {2}" -f $r.Result, $r.Case, $r.Expect
    if ($r.Note) { $line += " -- $($r.Note)" }
    Write-Host $line -ForegroundColor $color
    if ($r.Result -ne "PASS" -and $env:GITHUB_ACTIONS) {
        Write-Host "::error file=tests/Test-ShadowCopy.ps1::$($r.Case): $($r.Note)"
    }
}
if ($failures -gt 0 -or $results.Count -eq 0) {
    Write-Host "FAIL: $failures case(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: $($results.Count) case(s)" -ForegroundColor Green
exit 0

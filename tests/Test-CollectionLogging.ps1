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
#  - Copy-TriageFilesWithinCap and Copy-TriageCappedFile (browser session
#    files, history snapshots, extension manifests), which count the same
#    way: a copy saved under a shortened name counts, and its size counts
#    toward the total cap.
#  - Record-Manifest when Get-FileHash is not there (Windows PowerShell
#    started from PowerShell 7 through cmd.exe): the file is still recorded
#    and counted, with its SHA-256.
#  - Find-WindowsRoot on a drive letter that does not exist
#    (Run-TriageCollector.bat E without an E: drive): nothing, no error.
#  - Get-TriageVolumeSerial: a serial for the temp folder's drive, none for
#    a missing drive letter, and the volume's serial for a subst drive of a
#    folder on it (subst needs no admin rights; removed afterwards), so the
#    memory prompt never offers the system volume under another letter.
#  - The collector's provenance: the git commit read from .git without
#    git.exe (a .git folder, a worktree's .git file with an absolute or
#    relative gitdir and its commondir, packed-refs, a detached HEAD;
#    nothing and no error without a checkout, with an unreadable HEAD or a
#    branch with no commit), compared with git itself for this repository
#    when git.exe is there; the log lines (version, SHA-256 of the script,
#    commit); collection_info.json's CollectorVersion,
#    CollectorScriptSha256 and CollectorGitCommit (after SchemaVersion,
#    null when unknown, the other fields unchanged).
#  - The Run key log lines: values counted per hive (HKLM, loaded user
#    hives) and the users whose hive is not loaded named; ProfileList read
#    on this machine (read only).
#  - USBSTOR (with a stand-in for the registry read): a result line and
#    usb_storage_devices.txt with the devices, or with a note when there is
#    no USBSTOR key, no device under it, or it cannot be read (a warning).
#  - AppCompatCache read with .NET: the file is byte for byte the one
#    "reg query" gives on this machine (both written as Save-CommandOutput
#    writes them; reg.exe takes up to a minute here), with the value's hex
#    as the timeline builder reads it; reg.exe's output (a stand-in) when
#    the .NET read fails.
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

    # --- Browser file copies within a total cap (Copy-TriageFilesWithinCap,
    # Copy-TriageCappedFile) ---
    # The copy saved under a shortened name counts, with its size, toward
    # the cap: of 600 + 600 + 300 bytes under a 1000-byte cap the second file
    # is skipped. Counted by the original name, the first copy was missed,
    # so the second was copied too and the cap overrun
    Write-Host "Case: browser copies within a cap"
    $browserRel = "Users\Case16\Browser"
    $browserSource = Join-Path $targetDir $browserRel
    $longBrowserName = "Snapshot of " + ("b" * 88) + ".dat"
    $null = New-TestFile -Root $targetDir -RelativePath "$browserRel\$longBrowserName" -Size 600
    $null = New-TestFile -Root $targetDir -RelativePath "$browserRel\Plain.dat" -Size 600
    $null = New-TestFile -Root $targetDir -RelativePath "$browserRel\Report [x].dat" -Size 300
    $longManifestName = "Manifest " + ("m" * 88) + ".json"
    $null = New-TestFile -Root $targetDir -RelativePath "$browserRel\$longManifestName" -Size 200
    $browserDest = Join-Path $OutputPath "Browser\Case16"
    $cappedDest = Join-Path $OutputPath "Browser\Case16Capped"

    $logBefore = Get-LogLines
    $errorsBefore = $script:errorCount
    $filesBefore = $script:fileCount
    $problems = New-Object System.Collections.Generic.List[string]
    $ErrorActionPreference = "Continue"
    try {
        $browserFiles = @(foreach ($name in @($longBrowserName, "Plain.dat", "Report [x].dat")) {
            Get-Item -LiteralPath (Join-Path $browserSource $name) -Force
        })
        $returned = @(Copy-TriageFilesWithinCap -Files $browserFiles -SourceRoot $browserSource -DestRoot $browserDest -MaxTotalBytes 1000 -Label "test file")
        $cappedReturned = @(Copy-TriageCappedFile -SourcePath (Join-Path $browserSource $longManifestName) -DestDir $cappedDest -DestName $longManifestName -MaxBytes 1MB)
    } finally {
        $ErrorActionPreference = "Stop"
    }
    $saved = @(Get-ChildItem -LiteralPath $browserDest -Force -File -ErrorAction SilentlyContinue)
    if ($returned.Count -ne 1 -or $returned[0] -isnot [int] -or $returned[0] -ne 2) { $problems.Add("returned '$($returned -join ', ')' instead of 2") }
    if ($saved.Count -ne 2) { $problems.Add("$($saved.Count) file(s) saved, expected 2: $($saved.Name -join ', ')") }
    if (@($saved | Where-Object { $_.Name -match '^Snapshot.*~[0-9A-F]{8}\.dat$' -and $_.Name.Length -le 100 }).Count -ne 1) {
        $problems.Add("no shortened copy of the long name: $($saved.Name -join ', ')")
    }
    if (Test-Path -LiteralPath (Join-Path $browserDest "Plain.dat")) { $problems.Add("file over the cap copied") }
    if (-not (Test-Path -LiteralPath (Join-Path $browserDest "Report [x].dat"))) { $problems.Add("[ ] name not saved under its own name") }
    if ($cappedReturned.Count -ne 1 -or $cappedReturned[0] -isnot [bool] -or -not $cappedReturned[0]) {
        $problems.Add("Copy-TriageCappedFile returned '$($cappedReturned -join ', ')' instead of True for a copy saved under a shortened name")
    }
    if (($script:fileCount - $filesBefore) -ne 3) { $problems.Add("file count went up by $($script:fileCount - $filesBefore), expected 3") }
    if ($script:errorCount -ne $errorsBefore) { $problems.Add("error count changed") }
    $logNew = @(Get-LogLines | Select-Object -Skip $logBefore.Count)
    if ($logNew.Count -ne 1 -or $logNew[0] -notmatch '\] Skipped 1 test file\(s\) in .* total cap\): Plain\.dat \(0 MB\)$') {
        $problems.Add("log: expected one 'Skipped 1 test file(s) ... Plain.dat' line, got: $($logNew -join ' | ')")
    }
    if ($problems.Count -gt 0) { $failures++ }
    $results.Add([PSCustomObject]@{
        Result = $(if ($problems.Count -gt 0) { "FAIL" } else { "PASS" })
        Case   = "Browser copies within a cap"
        Expect = "2 counted, 1 skipped"
        Note   = ($problems -join "; ")
    })

    # --- Record-Manifest without Get-FileHash: Windows PowerShell started
    # from PowerShell 7 through cmd.exe can load PowerShell 7's Utility
    # module, which has no Get-FileHash for it. The file is still recorded,
    # with its SHA-256 ---
    $problems = New-Object System.Collections.Generic.List[string]
    $filesBefore = $script:fileCount
    $noHashDest = Join-Path $OutputPath "NoHash\file.bin"
    $noHashExpected = New-TestFile -Root $OutputPath -RelativePath "NoHash\file.bin" -Size 4096
    # A stand-in that fails as the missing command would, found before the
    # cmdlet (functions come first in command lookup)
    Set-Item -Path Function:\Get-FileHash -Value { throw "The term 'Get-FileHash' is not recognized (test stand-in)" }
    try { Record-Manifest -SourcePath "C:\NoHash\file.bin" -DestPath $noHashDest }
    finally { Remove-Item -Path Function:\Get-FileHash }
    $noHashRows = @(Get-ManifestRows -SourcePath "C:\NoHash\file.bin")
    if ($noHashRows.Count -ne 1) { $problems.Add("$($noHashRows.Count) manifest row(s), expected 1") }
    elseif ($noHashRows[0].SHA256 -cne $noHashExpected) { $problems.Add("SHA256 '$($noHashRows[0].SHA256)', expected '$noHashExpected'") }
    if (($script:fileCount - $filesBefore) -ne 1) { $problems.Add("file count went up by $($script:fileCount - $filesBefore), expected 1") }
    if ($problems.Count -gt 0) { $failures++ }
    $results.Add([PSCustomObject]@{
        Result = $(if ($problems.Count -gt 0) { "FAIL" } else { "PASS" })
        Case   = "Record-Manifest without Get-FileHash"
        Expect = "recorded, SHA-256 as Get-FileHash"
        Note   = ($problems -join "; ")
    })

    # --- Find-WindowsRoot on a drive that does not exist (Run-TriageCollector.bat
    # E with no E:): no parameter-binding error from Get-ChildItem -Directory ---
    $problems = New-Object System.Collections.Generic.List[string]
    $usedLetters = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
    $freeLetter = @("QRSTUVWXYZ".ToCharArray() | ForEach-Object { "$_" } | Where-Object { $usedLetters -notcontains $_ }) | Select-Object -First 1
    if ($freeLetter) {
        # $ErrorActionPreference is Stop here: any error inside throws
        $foundRoot = "not run"
        try { $foundRoot = Find-WindowsRoot -DrivePath "${freeLetter}:\" }
        catch { $problems.Add("error: $($_.Exception.Message)") }
        if ($null -ne $foundRoot) { $problems.Add("returned '$foundRoot' instead of nothing") }
    }
    if ($problems.Count -gt 0) { $failures++ }
    $results.Add([PSCustomObject]@{
        Result = $(if ($problems.Count -gt 0) { "FAIL" } else { "PASS" })
        Case   = "Find-WindowsRoot on a missing drive"
        Expect = "nothing, no error$(if (-not $freeLetter) { ' (skipped: no free drive letter)' })"
        Note   = ($problems -join "; ")
    })

    # --- Get-TriageVolumeSerial (the memory prompt does not offer the
    # system volume under another letter): the temp folder's drive has a
    # serial, a missing drive letter none, and a subst drive of a folder on
    # it the same serial (subst needs no admin rights; removed afterwards) ---
    Write-Host "Case: volume serial numbers"
    $problems = New-Object System.Collections.Generic.List[string]
    $tempDriveRoot = [System.IO.Path]::GetPathRoot($workDir)
    $tempSerial = Get-TriageVolumeSerial $tempDriveRoot
    if ($tempSerial -notmatch '^[0-9A-F]{8}$') { $problems.Add("serial of ${tempDriveRoot}: '$tempSerial'") }
    $serialInfo = "$tempDriveRoot $tempSerial"
    if ($freeLetter) {
        $missingSerial = Get-TriageVolumeSerial "${freeLetter}:\"
        if ($missingSerial) { $problems.Add("serial '$missingSerial' for the missing drive ${freeLetter}:") }
        $substFolder = Join-Path $workDir "subst"
        New-Item -ItemType Directory -Path $substFolder -Force | Out-Null
        $ErrorActionPreference = "Continue"
        try {
            $null = & subst.exe "${freeLetter}:" $substFolder 2>&1
            if (Test-Path -LiteralPath "${freeLetter}:\") {
                $substSerial = Get-TriageVolumeSerial "${freeLetter}:\"
                if ($substSerial -cne $tempSerial) { $problems.Add("subst drive ${freeLetter}: has serial '$substSerial', its volume '$tempSerial'") }
                $serialInfo += ", subst ${freeLetter}: $substSerial"
            } else {
                $serialInfo += " (subst not possible here)"
            }
        } finally {
            $null = & subst.exe "${freeLetter}:" /d 2>&1
            $ErrorActionPreference = "Stop"
        }
    }
    if ($problems.Count -gt 0) { $failures++ }
    $results.Add([PSCustomObject]@{
        Result = $(if ($problems.Count -gt 0) { "FAIL" } else { "PASS" })
        Case   = "Volume serial numbers"
        Expect = "subst drive = its volume"
        Note   = $(if ($problems.Count -gt 0) { $problems -join "; " } else { $serialInfo })
    })

    # --- The collector's provenance: the git commit read from .git without
    # git.exe (a folder, a worktree's .git file with a relative or absolute
    # gitdir and commondir, packed-refs, a detached HEAD), nothing (and no
    # error) without a checkout or with an unreadable HEAD ---
    Write-Host "Case: git commit without git.exe"
    $problems = New-Object System.Collections.Generic.List[string]
    $gitRoot = Join-Path $workDir "git"
    $sha1 = "0123456789abcdef0123456789abcdef01234567"
    $sha2 = "89ABCDEF0123456789ABCDEF0123456789ABCDEF"
    $sha3 = "fedcba9876543210fedcba9876543210fedcba98"
    function New-TestTextFile {
        param([string]$Path, [string]$Text)
        New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
        [System.IO.File]::WriteAllText($Path, $Text)
    }
    # a: a .git folder, the branch in refs\heads
    New-TestTextFile (Join-Path $gitRoot "a\.git\HEAD") "ref: refs/heads/phase3/r2`n"
    New-TestTextFile (Join-Path $gitRoot "a\.git\refs\heads\phase3\r2") "$sha1`n"
    # b: the branch only in packed-refs (after git gc), with a peeled tag line
    New-TestTextFile (Join-Path $gitRoot "b\.git\HEAD") "ref: refs/heads/main`n"
    New-TestTextFile (Join-Path $gitRoot "b\.git\packed-refs") "# pack-refs with: peeled fully-peeled sorted`n$sha3 refs/heads/mainline`n$sha2 refs/heads/main`n^$sha3`n"
    # c: a detached HEAD
    New-TestTextFile (Join-Path $gitRoot "c\.git\HEAD") "$sha2`n"
    # d: a worktree: .git is a file naming the worktree's git folder
    # (absolute), whose commondir leads to the main repository's refs
    New-TestTextFile (Join-Path $gitRoot "main\.git\refs\heads\wt-branch") "$sha3`n"
    New-TestTextFile (Join-Path $gitRoot "main\.git\worktrees\wt\HEAD") "ref: refs/heads/wt-branch`n"
    New-TestTextFile (Join-Path $gitRoot "main\.git\worktrees\wt\commondir") "../..`n"
    New-TestTextFile (Join-Path $gitRoot "d\.git") ("gitdir: " + (Join-Path $gitRoot "main\.git\worktrees\wt").Replace('\', '/') + "`n")
    # e: the same with a relative gitdir
    New-TestTextFile (Join-Path $gitRoot "e\.git") "gitdir: ../main/.git/worktrees/wt`n"
    # f: no checkout; g: HEAD not readable as a ref or commit; h: a branch
    # with no commit yet; i: .git file naming a folder that does not exist
    New-Item -ItemType Directory -Path (Join-Path $gitRoot "f") -Force | Out-Null
    New-TestTextFile (Join-Path $gitRoot "g\.git\HEAD") "not a ref`n"
    New-TestTextFile (Join-Path $gitRoot "h\.git\HEAD") "ref: refs/heads/unborn`n"
    New-TestTextFile (Join-Path $gitRoot "i\.git") "gitdir: C:/no/such/folder/.git`n"
    $gitCases = @(
        @{ Folder = "a"; Commit = $sha1; Branch = "phase3/r2" }
        @{ Folder = "b"; Commit = $sha2.ToLowerInvariant(); Branch = "main" }
        @{ Folder = "c"; Commit = $sha2.ToLowerInvariant(); Branch = "" }
        @{ Folder = "d"; Commit = $sha3; Branch = "wt-branch" }
        @{ Folder = "e"; Commit = $sha3; Branch = "wt-branch" }
        @{ Folder = "f"; Commit = $null }
        @{ Folder = "g"; Commit = $null }
        @{ Folder = "h"; Commit = $null }
        @{ Folder = "i"; Commit = $null }
    )
    foreach ($gitCase in $gitCases) {
        $got = "not run"
        try { $got = Get-CollectorGitCommit -Folder (Join-Path $gitRoot $gitCase.Folder) }
        catch { $problems.Add("$($gitCase.Folder): error $($_.Exception.Message)"); continue }
        if ($null -eq $gitCase.Commit) {
            if ($null -ne $got) { $problems.Add("$($gitCase.Folder): '$($got.Commit)' instead of nothing") }
        } elseif ($null -eq $got -or $got.Commit -cne $gitCase.Commit -or $got.Branch -cne $gitCase.Branch) {
            $problems.Add("$($gitCase.Folder): '$($got.Commit)' on '$($got.Branch)', expected '$($gitCase.Commit)' on '$($gitCase.Branch)'")
        }
    }
    # This repository, when it is a git checkout and git.exe is there: the
    # commit git itself names
    $repoInfo = "repository: not a checkout"
    if ((Test-Path -LiteralPath (Join-Path $repoRoot ".git")) -and (Get-Command git -ErrorAction SilentlyContinue)) {
        $ErrorActionPreference = "Continue"
        try { $gitHead = (& git -C $repoRoot rev-parse HEAD 2>$null | Select-Object -First 1) } finally { $ErrorActionPreference = "Stop" }
        $repoCommit = Get-CollectorGitCommit -Folder $repoRoot
        if ($gitHead -and ($null -eq $repoCommit -or $repoCommit.Commit -cne "$gitHead".Trim())) { $problems.Add("this repository: '$($repoCommit.Commit)', git says '$gitHead'") }
        $repoInfo = "repository at $("$gitHead".Trim().Substring(0, [Math]::Min(7, "$gitHead".Trim().Length)))"
    }
    if ($problems.Count -gt 0) { $failures++ }
    $results.Add([PSCustomObject]@{
        Result = $(if ($problems.Count -gt 0) { "FAIL" } else { "PASS" })
        Case   = "Git commit read without git.exe"
        Expect = "$($gitCases.Count) layouts, $repoInfo"
        Note   = ($problems -join "; ")
    })

    # --- Provenance in the log and in collection_info.json: version, the
    # script's SHA-256, the git commit (separate top-level fields; null when
    # unknown) ---
    Write-Host "Case: provenance in the log and collection_info.json"
    $problems = New-Object System.Collections.Generic.List[string]
    $scriptCopy = Join-Path $gitRoot "a\triage-collector.ps1"
    [System.IO.File]::WriteAllText($scriptCopy, "# synthetic collector`r`n")
    $scriptSha = (Get-FileHash -LiteralPath $scriptCopy -Algorithm SHA256).Hash
    $prov = Get-CollectorProvenance -ScriptPath $scriptCopy -Version "2099.01.02"
    if ($prov.Version -cne "2099.01.02" -or $prov.ScriptSha256 -cne $scriptSha -or $prov.GitCommit -cne $sha1 -or $prov.GitBranch -cne "phase3/r2") {
        $problems.Add("provenance: $($prov.Version), $($prov.ScriptSha256), $($prov.GitCommit), $($prov.GitBranch)")
    }
    $provLines = @(Get-CollectorProvenanceLines $prov)
    $expectedLines = @(
        "Collector: version 2099.01.02, triage-collector.ps1 SHA-256 $scriptSha",
        "Collector git commit: $sha1 (branch phase3/r2; uncommitted changes show only in the SHA-256)"
    )
    if (($provLines -join "|") -cne ($expectedLines -join "|")) { $problems.Add("log lines: $($provLines -join ' | ')") }
    $noGit = Get-CollectorProvenance -ScriptPath (Join-Path $gitRoot "f\missing.ps1") -Version "2099.01.02"
    $noGitLines = @(Get-CollectorProvenanceLines $noGit)
    if ($noGit.ScriptSha256 -or $noGit.GitCommit -or ($noGitLines -join "|") -cne "Collector: version 2099.01.02, triage-collector.ps1 SHA-256 unknown (the script file could not be read)|Collector git commit: none (not run from a git checkout)") {
        $problems.Add("no file, no checkout: '$($noGit.ScriptSha256)', '$($noGit.GitCommit)', $($noGitLines -join ' | ')")
    }
    $detached = @(Get-CollectorProvenanceLines (Get-CollectorProvenance -ScriptPath (Join-Path $gitRoot "c\x.ps1") -Version "1"))
    if ($detached[1] -cne "Collector git commit: $($sha2.ToLowerInvariant()) (detached HEAD; uncommitted changes show only in the SHA-256)") { $problems.Add("detached: $($detached[1])") }

    # collection_info.json: the three fields after SchemaVersion, the other
    # fields as before; null when not known
    $script:startTime = Get-Date
    $script:TargetDrive = "C"
    $script:IncludeSecrets = $false
    $script:IncludeThunderbirdIndex = $false
    $infoPath = Join-Path $OutputPath "collection_info.json"
    foreach ($infoCase in @(@{ Prov = $prov; Version = "2099.01.02"; Sha = $scriptSha; Commit = $sha1 }, @{ Prov = $noGit; Version = "2099.01.02"; Sha = $null; Commit = $null }, @{ Prov = $null; Version = $null; Sha = $null; Commit = $null })) {
        $script:collectorProvenance = $infoCase.Prov
        Remove-Item -LiteralPath $infoPath -Force -ErrorAction SilentlyContinue
        $ErrorActionPreference = "Continue"
        try { Write-CollectionInfo } finally { $ErrorActionPreference = "Stop" }
        if (-not (Test-Path -LiteralPath $infoPath)) { $problems.Add("collection_info.json not written"); continue }
        $infoText = [System.IO.File]::ReadAllText($infoPath)
        $info = $infoText | ConvertFrom-Json
        $names = @($info.PSObject.Properties | ForEach-Object { $_.Name })
        # CollectorProcesses last: this is a live run (Test-CollectorProcesses
        # checks that field, and that the provenance fields stay when the
        # file is written again after a memory capture)
        $expectedNames = "SchemaVersion,CollectorVersion,CollectorScriptSha256,CollectorGitCommit,ComputerName,CollectorUser,Mode,TargetDrive,TargetRoot,CollectionStartUtc,CollectorTimeZoneId,CollectorCulture,TargetTimeZoneId,SecretsIncluded,ThunderbirdIndexIncluded,CollectorProcesses"
        if (($names -join ",") -cne $expectedNames) { $problems.Add("fields: $($names -join ',')") }
        if ($info.SchemaVersion -ne 1) { $problems.Add("SchemaVersion $($info.SchemaVersion)") }
        if ($info.CollectorVersion -cne $infoCase.Version -or $info.CollectorScriptSha256 -cne $infoCase.Sha -or $info.CollectorGitCommit -cne $infoCase.Commit) {
            $problems.Add("provenance fields '$($info.CollectorVersion)', '$($info.CollectorScriptSha256)', '$($info.CollectorGitCommit)'")
        }
        if ($null -eq $infoCase.Commit -and $infoText -notmatch '"CollectorGitCommit":\s*null') { $problems.Add("CollectorGitCommit is not null when unknown") }
    }
    $script:collectorProvenance = $null
    if ($problems.Count -gt 0) { $failures++ }
    $results.Add([PSCustomObject]@{
        Result = $(if ($problems.Count -gt 0) { "FAIL" } else { "PASS" })
        Case   = "Provenance: log lines, collection_info"
        Expect = "version, SHA-256, commit; null if unknown"
        Note   = ($problems -join "; ")
    })

    # --- Run keys: values counted per hive (HKLM, loaded user hives), and the
    # user profiles whose hive is not loaded named (their Run values are only
    # in the collected NTUSER.DAT) ---
    Write-Host "Case: Run key log lines"
    $problems = New-Object System.Collections.Generic.List[string]
    $sidA = "S-1-5-21-1-2-3-1001"
    $sidB = "S-1-5-21-1-2-3-1002"
    $sidC = "S-1-12-1-4-5-6-7"
    $runRows = @(
        [PSCustomObject]@{ Hive = "HKLM"; User = "" }
        [PSCustomObject]@{ Hive = "HKU\$sidA"; User = "Alice" }
        [PSCustomObject]@{ Hive = "HKU\$sidA"; User = "Alice" }
    )
    $profiles = @(
        [PSCustomObject]@{ Sid = $sidA; User = "Alice"; HasNtUser = $true }
        [PSCustomObject]@{ Sid = $sidB; User = "Bob"; HasNtUser = $true }
        [PSCustomObject]@{ Sid = $sidC; User = "Carol"; HasNtUser = $true }
        [PSCustomObject]@{ Sid = "S-1-5-21-1-2-3-1009"; User = "NoHive"; HasNtUser = $false }
    )
    $runCases = @(
        @{ Rows = $runRows; Loaded = @($sidA); Profiles = $profiles; Registry = $true
           Lines = @("Run keys: 1 value(s) in HKLM, 2 value(s) in 1 loaded user hive(s).",
               "Run keys not read live for 2 user(s) whose hive is not loaded: Bob, Carol (their Run values are in the collected Registry\<user>\NTUSER.DAT, which the timeline builder reads).") }
        @{ Rows = $runRows; Loaded = @($sidA, $sidB, $sidC); Profiles = $profiles; Registry = $true
           Lines = @("Run keys: 1 value(s) in HKLM, 2 value(s) in 3 loaded user hive(s).") }
        @{ Rows = @(); Loaded = @(); Profiles = @($profiles[1]); Registry = $false
           Lines = @("Run keys: 0 value(s) in HKLM, 0 value(s) in 0 loaded user hive(s).",
               "Run keys not read live for 1 user(s) whose hive is not loaded: Bob (their NTUSER.DAT is collected only with the Registry category).") }
    )
    foreach ($runCase in $runCases) {
        $got = @(Get-TriageRunKeyLogLines -Rows $runCase.Rows -LoadedSids $runCase.Loaded -Profiles $runCase.Profiles -RegistryCollected $runCase.Registry)
        if (($got -join "|") -cne ($runCase.Lines -join "|")) { $problems.Add("got: $($got -join ' | ')") }
    }
    # ProfileList on this machine (read only): every entry a local or Entra
    # ID account, with a name
    $liveProfiles = @(Get-TriageProfileListUsers)
    foreach ($liveProfile in $liveProfiles) {
        if ($liveProfile.Sid -notmatch '^S-1-(5-21|12-1)-' -or -not $liveProfile.User -or $liveProfile.HasNtUser -isnot [bool]) { $problems.Add("ProfileList entry '$($liveProfile.Sid)', '$($liveProfile.User)', $($liveProfile.HasNtUser)") }
    }
    if ($problems.Count -gt 0) { $failures++ }
    $results.Add([PSCustomObject]@{
        Result = $(if ($problems.Count -gt 0) { "FAIL" } else { "PASS" })
        Case   = "Run key log lines"
        Expect = "per hive; unloaded hives named"
        Note   = ($problems -join "; ")
    })

    # --- USBSTOR: usb_storage_devices.txt and a result line, also when there
    # is no device (no key, an empty key) or it cannot be read ---
    Write-Host "Case: USBSTOR result line"
    $problems = New-Object System.Collections.Generic.List[string]
    $usbDir = Join-Path $OutputPath "USB"
    $usbFile = Join-Path $usbDir "usb_storage_devices.txt"
    $usbCases = @(
        @{ Mode = "devices"; Count = 2; Line = '\] USBSTOR: 2 USB storage device\(s\) recorded in the registry \(usb_storage_devices\.txt\)\.$'; File = '^FriendlyName\s*:\s*Test Disk 1 USB Device$' }
        @{ Mode = "missing"; Count = 0; Line = '\] USBSTOR: no USB storage devices recorded in the registry \(no USBSTOR key\)\.$'; File = '^\(no USB storage devices recorded in the registry; there is no HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR key\)$' }
        @{ Mode = "empty"; Count = 0; Line = '\] USBSTOR: no USB storage devices recorded in the registry \(the USBSTOR key has no device\)\.$'; File = '^\(no USB storage devices recorded in the registry; HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR has no device\)$' }
        @{ Mode = "denied"; Count = 0; Line = '\] WARNING: USBSTOR: no USB storage device could be read from the registry -- Access is denied \(test\)$'; File = '^\(no USB storage device could be read from HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR -- Access is denied \(test\)\)$' }
    )
    foreach ($usbCase in $usbCases) {
        Remove-Item -LiteralPath $usbFile -Force -ErrorAction SilentlyContinue
        $logBefore = Get-LogLines
        $script:usbMode = $usbCase.Mode
        $ErrorActionPreference = "Continue"
        try {
            $returned = @(& {
                # Stand-in for the registry read, in this block only (a
                # function comes before the cmdlet)
                Set-Item -Path function:Get-ItemProperty -Value {
                    [CmdletBinding()]
                    param([Parameter(Position = 0)][string]$Path)
                    Write-Verbose "Stand-in read of $Path"
                    switch ($script:usbMode) {
                        "devices" {
                            [PSCustomObject]@{ FriendlyName = "Test Disk 1 USB Device"; HardwareID = @("USBSTOR\DiskTest1", "GenDisk"); Mfg = "(Standard disk drives)"; Service = "disk"; ContainerID = "{00000000-0000-0000-0000-000000000001}"; PSChildName = "SERIAL1&0" }
                            [PSCustomObject]@{ FriendlyName = "Test Disk 2 USB Device"; HardwareID = @("USBSTOR\DiskTest2"); Mfg = "(Standard disk drives)"; Service = "disk"; ContainerID = "{00000000-0000-0000-0000-000000000002}"; PSChildName = "SERIAL2&0" }
                        }
                        "missing" { Write-Error -Exception (New-Object System.Management.Automation.ItemNotFoundException "Cannot find path (test)") }
                        "denied" { Write-Error -Exception (New-Object System.UnauthorizedAccessException "Access is denied (test)") }
                    }
                }
                Save-TriageUsbStorDevices -UsbDir $usbDir
            })
        } finally { $ErrorActionPreference = "Stop" }
        $logNew = @(Get-LogLines | Select-Object -Skip $logBefore.Count)
        if ($returned.Count -ne 1 -or $returned[0] -ne $usbCase.Count) { $problems.Add("$($usbCase.Mode): returned '$($returned -join ',')'") }
        if ($logNew.Count -ne 1 -or $logNew[0] -notmatch $usbCase.Line) { $problems.Add("$($usbCase.Mode): log '$($logNew -join ' | ')'") }
        $fileLines = @()
        if (Test-Path -LiteralPath $usbFile) { $fileLines = @(Get-Content -LiteralPath $usbFile) }
        if (@($fileLines | Where-Object { $_ -match $usbCase.File }).Count -ne 1) { $problems.Add("$($usbCase.Mode): usb_storage_devices.txt '$($fileLines -join ' / ')'") }
        if (@(Get-ManifestRows -SourcePath "(command: USB storage devices)" | Where-Object { $_.DestPath -eq $usbFile }).Count -lt 1) { $problems.Add("$($usbCase.Mode): not in the manifest") }
    }
    if ($problems.Count -gt 0) { $failures++ }
    $results.Add([PSCustomObject]@{
        Result = $(if ($problems.Count -gt 0) { "FAIL" } else { "PASS" })
        Case   = "USBSTOR result line"
        Expect = "count, or a note in the file"
        Note   = ($problems -join "; ")
    })

    # --- AppCompatCache read with .NET: byte for byte the file "reg query"
    # gave (both written as Save-CommandOutput writes them), on this
    # machine; reg.exe still used when the .NET read fails ---
    Write-Host "Case: AppCompatCache through .NET and reg query (reg query takes up to a minute)"
    $problems = New-Object System.Collections.Generic.List[string]
    $shimNet = Join-Path $workDir "shim\net\appcompat_cache.reg"
    $shimReg = Join-Path $workDir "shim\reg\appcompat_cache.reg"
    $shimInfo = ""
    $ErrorActionPreference = "Continue"
    try {
        $script:appCompatCacheMethod = ""
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        Save-CommandOutput -Description "AppCompatCache (.NET)" -DestPath $shimNet -Command { Get-TriageAppCompatCacheText }
        $netMs = $watch.ElapsedMilliseconds
        $netMethod = $script:appCompatCacheMethod
        $watch.Restart()
        Save-CommandOutput -Description "AppCompatCache (reg query)" -DestPath $shimReg -Command {
            reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v AppCompatCache 2>&1
        }
        $regMs = $watch.ElapsedMilliseconds
    } finally { $ErrorActionPreference = "Stop" }
    if ($netMethod -notmatch '^\d+ bytes read from the registry$') {
        $shimInfo = "skipped: the .NET read failed here ($netMethod)"
    } else {
        $netBytes = [System.IO.File]::ReadAllBytes($shimNet)
        $regBytes = [System.IO.File]::ReadAllBytes($shimReg)
        if ([System.Convert]::ToBase64String($netBytes) -cne [System.Convert]::ToBase64String($regBytes)) {
            $problems.Add(".NET file ($($netBytes.Length) bytes) differs from the reg query file ($($regBytes.Length) bytes)")
        }
        # What the timeline builder takes from it: the hex of the value
        $netText = [System.IO.File]::ReadAllText($shimNet)
        $valueBytes = [long]($netMethod -replace ' .*$', '')
        if ($netText -notmatch 'AppCompatCache\s+REG_BINARY\s+([0-9A-Fa-f]+)' -or $Matches[1].Length -ne $valueBytes * 2) { $problems.Add("the hex of the value is not $valueBytes bytes") }
        $shimInfo = "$($netBytes.Length) bytes identical; .NET $netMs ms, reg query $regMs ms"
    }

    # The fallback: no key through .NET -> reg.exe's output (a stand-in)
    $savedOpen = ${function:Open-TriageRegKey}
    Set-Item -Path function:Open-TriageRegKey -Value { return $null }
    try {
        $fallback = @(& {
            function reg { "stand-in reg $($args -join ' ')" }
            Get-TriageAppCompatCacheText
        })
    } finally { Set-Item -Path function:Open-TriageRegKey -Value $savedOpen }
    if (($fallback -join "|") -cne 'stand-in reg query HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache /v AppCompatCache') { $problems.Add("fallback output: $($fallback -join ' | ')") }
    if ($script:appCompatCacheMethod -cne "read with reg query (the .NET read failed: the key could not be opened)") { $problems.Add("fallback method: $($script:appCompatCacheMethod)") }
    if ($problems.Count -gt 0) { $failures++ }
    $results.Add([PSCustomObject]@{
        Result = $(if ($problems.Count -gt 0) { "FAIL" } else { "PASS" })
        Case   = "AppCompatCache .NET = reg query"
        Expect = "byte for byte; reg.exe fallback"
        Note   = $(if ($problems.Count -gt 0) { $problems -join "; " } else { $shimInfo })
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

# =============================================================
# SRUM collection test
# Builds a fake mounted image (a folder with Windows\System32 and a
# Windows\System32\sru folder holding a placeholder SRUDB.dat with its
# checkpoint, logs, reserve logs and flush map, a file over the 16 GB size
# cap -- sparse, so it takes no disk space -- and a subfolder), maps it to a
# free drive letter with subst and runs triage-collector.ps1 -TargetDrive
# <letter> -Categories Execution -Unattended -NoCompress on it. Checks that
# every SRUM file is in Execution\SRUM\ byte for byte, with a manifest row
# (hash, source path, original modified time), that the oversize file and
# the subfolder were not collected and the skip was logged. A second run
# with -SkipLargeFiles must apply the lower 2 GB cap, and a third run on an
# image without an sru folder must log that as information only.
#
# The live-system path needs a shadow copy, so it is checked with the
# collector's own functions (loaded from the script, as Test-RawCopy.ps1
# does) and a folder standing in for the shadow copy: when SRUDB.dat is in
# the shadow copy, every file must come from there (a log deleted since is
# collected, a newer log on the volume is not); without it, the files come
# from the volume. A sru folder that cannot be listed must be a warning.
#
# Needs Administrator rights, like the collector (GitHub Actions Windows
# runners are elevated). For a local run without them, pass -CollectorPath
# with a copy of the collector that has no admin check, kept inside the
# repository (e.g. under the git-ignored reports\ folder). subst needs no
# rights; the drive letter is removed again at the end.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-CollectSrum.ps1
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
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-CollectSrum.ps1::$Message" }
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

# Runs a console tool; returns its exit code and output. Error action
# Continue: with Stop, Windows PowerShell 5.1 turns any stderr line into a
# terminating error.
function Invoke-NativeTool {
    param([string]$FilePath, [string[]]$Arguments)
    $ErrorActionPreference = "Continue"
    $output = & $FilePath @Arguments 2>&1
    return [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Output = @($output | ForEach-Object { "$_" }) }
}

# First drive letter from Z: down that is not in use
function Get-FreeDriveLetter {
    $used = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
    foreach ($code in 90..68) {
        $letter = [string][char]$code
        if ($used -notcontains $letter -and -not (Test-Path -LiteralPath "${letter}:\")) { return $letter }
    }
    return $null
}

# Runs the collector on the image mapped to $Letter (with -SkipLargeFiles
# when asked); returns the text of its collection_log.txt
function Invoke-Collector {
    param([string]$Letter, [string]$OutputPath, [switch]$SkipLargeFiles)
    $ErrorActionPreference = "Continue"
    $collectorArgs = @("-TargetDrive", $Letter, "-Categories", "Execution", "-Unattended", "-NoCompress", "-OutputPath", $OutputPath)
    if ($SkipLargeFiles) { $collectorArgs += "-SkipLargeFiles" }
    $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $collector @collectorArgs 2>&1
    $log = Join-Path $OutputPath "collection_log.txt"
    if (-not (Test-Path -LiteralPath $log)) {
        $output | ForEach-Object { Write-Host "  | $_" }
        throw "the collector wrote no collection_log.txt to $OutputPath"
    }
    return [System.IO.File]::ReadAllText($log)
}

# Writes a file with the given bytes and a known modified time (UTC)
function New-TestFile {
    param([string]$Path, [byte[]]$Bytes, [datetime]$ModifiedUtc)
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
    [System.IO.File]::SetLastWriteTimeUtc($Path, $ModifiedUtc)
}

# An empty sparse file of the given size (no disk space used); $false if
# the volume does not support sparse files
function New-SparseFile {
    param([string]$Path, [long]$Size)
    [System.IO.File]::WriteAllBytes($Path, [byte[]]@())
    $sparse = Invoke-NativeTool "fsutil.exe" @("sparse", "setflag", $Path)
    if ($sparse.ExitCode -ne 0) {
        Remove-Item -LiteralPath $Path -Force
        Write-Host "SKIPPED: oversize file case (fsutil sparse setflag failed: $($sparse.Output -join ' '))" -ForegroundColor Yellow
        return $false
    }
    $stream = [System.IO.File]::Open($Path, "Open", "ReadWrite", "None")
    try { $stream.SetLength($Size) } finally { $stream.Dispose() }
    return $true
}

$random = New-Object System.Random 20261007
function New-RandomBytes {
    param([int]$Count)
    $bytes = New-Object byte[] $Count
    $random.NextBytes($bytes)
    return , $bytes
}

# Checks that every expected file is in the collection's Execution\SRUM
# byte for byte with its manifest row, and nothing else is there.
# SourceFor: the expected manifest SourcePath of a file name.
function Test-CollectedSrum {
    param([string]$Collection, [System.Collections.IDictionary]$Expected, [scriptblock]$SourceFor, [string]$Label)
    $manifest = @(Import-Csv -LiteralPath (Join-Path $Collection "collection_manifest.csv"))
    $srumOut = Join-Path $Collection "Execution\SRUM"
    foreach ($name in $Expected.Keys) {
        $dest = Join-Path $srumOut $name
        $expectedHash = (Get-FileHash -LiteralPath $Expected[$name] -Algorithm SHA256).Hash
        if (-not (Test-Path -LiteralPath $dest)) {
            Write-TestResult -Succeeded $false -Message "${Label}: $name collected to Execution\SRUM"
            continue
        }
        $problems = @()
        if ((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -ne $expectedHash) { $problems += "copy differs from the original (SHA256)" }
        $row = $manifest | Where-Object { $_.RelativePath -eq "Execution\SRUM\$name" } | Select-Object -First 1
        if (-not $row) { $problems += "no manifest row" }
        else {
            if ($row.SHA256 -ne $expectedHash) { $problems += "manifest SHA256 $($row.SHA256)" }
            $expectedSource = & $SourceFor $name
            if ($row.SourcePath -ne $expectedSource) { $problems += "manifest SourcePath $($row.SourcePath) (expected $expectedSource)" }
            $expectedModified = [System.IO.File]::GetLastWriteTimeUtc($Expected[$name]).ToString("o")
            if ($row.SourceModifiedUtc -ne $expectedModified) { $problems += "manifest SourceModifiedUtc $($row.SourceModifiedUtc) (expected $expectedModified)" }
        }
        Write-TestResult -Succeeded ($problems.Count -eq 0) -Message ("${Label}: $name collected to Execution\SRUM with its manifest row" + $(if ($problems) { " -- " + ($problems -join "; ") } else { "" }))
    }
    $extra = @(Get-ChildItem -LiteralPath $srumOut -Force -ErrorAction SilentlyContinue | Where-Object { $Expected.Keys -notcontains $_.Name } | ForEach-Object { $_.Name })
    Write-TestResult -Succeeded ($extra.Count -eq 0) -Message "${Label}: nothing else in Execution\SRUM$(if ($extra) { ' -- found: ' + ($extra -join ', ') })"
}

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("srum-collect-test-" + [guid]::NewGuid().ToString("N"))
$letter = $null
$deniedDir = $null
$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
try {
    New-Item -ItemType Directory -Path $workDir | Out-Null
    $image = Join-Path $workDir "image"
    $sruDir = Join-Path $image "Windows\System32\sru"
    New-Item -ItemType Directory -Path $sruDir -Force | Out-Null

    # --- Fake sru folder ---
    # SRUDB.dat: a placeholder with the ESE database header magic (the
    # collector copies it without reading it)
    $dbBytes = New-RandomBytes (3MB + 517)
    [Array]::Copy([byte[]](0xEF, 0xCD, 0xAB, 0x89), 0, $dbBytes, 4, 4)
    $modified = [datetime]::SpecifyKind([datetime]"2026-03-01 10:00:00", [System.DateTimeKind]::Utc)
    $fileBytes = [ordered]@{
        "SRUDB.dat"       = $dbBytes
        "SRUDB.jfm"       = (New-RandomBytes 16384)
        "SRU.chk"         = (New-RandomBytes 8192)
        "SRU.log"         = (New-RandomBytes 65536)
        "SRU0000A.log"    = (New-RandomBytes 65536)
        "SRUtmp.log"      = (New-RandomBytes 65536)
        "SRUres00001.jrs" = (New-RandomBytes 65536)
        "SRUres00002.jrs" = (New-RandomBytes 65536)
    }
    $expectedFiles = [ordered]@{}
    $i = 0
    foreach ($name in $fileBytes.Keys) {
        $expectedFiles[$name] = Join-Path $sruDir $name
        New-TestFile -Path $expectedFiles[$name] -Bytes $fileBytes[$name] -ModifiedUtc $modified.AddMinutes($i)
        $i++
    }
    # A subfolder: only the folder's own files are collected
    New-TestFile -Path (Join-Path $sruDir "sub\nested.dat") -Bytes (New-RandomBytes 100) -ModifiedUtc $modified

    # Over the size cap (16 GB; 2 GB with -SkipLargeFiles)
    $oversize = Join-Path $sruDir "SRUoversize.dat"
    $oversizeCase = New-SparseFile -Path $oversize -Size (16GB + 1)

    # --- Map the image to a drive letter and collect ---
    $letter = Get-FreeDriveLetter
    if (-not $letter) { throw "no free drive letter for subst" }
    $subst = Invoke-NativeTool "subst.exe" @("${letter}:", $image)
    if ($subst.ExitCode -ne 0) { throw "subst ${letter}: failed: $($subst.Output -join ' ')" }
    Write-Host "Fake image $image mapped to ${letter}:"
    $imageSource = { param($Name) "${letter}:\Windows\System32\sru\$Name" }

    $out1 = Join-Path $workDir "collection1"
    Write-Host "Running the collector ($powershellExe) on ${letter}: ..."
    $logText1 = Invoke-Collector -Letter $letter -OutputPath $out1
    Write-TestResult -Succeeded ($logText1 -match 'Mode: MOUNTED IMAGE') -Message "the collector ran in mounted-image mode on ${letter}:"
    Test-CollectedSrum -Collection $out1 -Expected $expectedFiles -SourceFor $imageSource -Label "image"
    Write-TestResult -Succeeded ($logText1 -match [regex]::Escape("Collected $($expectedFiles.Count) SRUM file(s).")) -Message "the log reports $($expectedFiles.Count) SRUM files collected"
    if ($oversizeCase) {
        Write-TestResult -Succeeded ($logText1 -match 'Skipped SRUM file .*SRUoversize\.dat .*larger than the 16384 MB size cap') -Message "the file over 16 GB is skipped and the reason logged"
    }
    Write-TestResult -Succeeded ($logText1 -match 'Skipping RecentApps, BAM, AppCompatCache \(mounted image') -Message "the live-only execution steps are skipped in image mode"

    # --- -SkipLargeFiles: a 2 GB cap ---
    if ($oversizeCase) {
        Remove-Item -LiteralPath $oversize -Force
        $null = New-SparseFile -Path $oversize -Size (2GB + 1)
        $out2 = Join-Path $workDir "collection2"
        Write-Host "Running the collector with -SkipLargeFiles ..."
        $logText2 = Invoke-Collector -Letter $letter -OutputPath $out2 -SkipLargeFiles
        Write-TestResult -Succeeded ($logText2 -match 'SkipLargeFiles: True') -Message "SkipLargeFiles: the collector ran with -SkipLargeFiles"
        Write-TestResult -Succeeded ($logText2 -match 'Skipped SRUM file .*SRUoversize\.dat .*larger than the 2048 MB size cap') -Message "SkipLargeFiles: the file over 2 GB is skipped and the reason logged"
        Test-CollectedSrum -Collection $out2 -Expected $expectedFiles -SourceFor $imageSource -Label "SkipLargeFiles"
        Remove-Item -LiteralPath $oversize -Force
    }

    # --- An image without an sru folder: information only ---
    Remove-Item -LiteralPath $sruDir -Recurse -Force
    $out3 = Join-Path $workDir "collection3"
    Write-Host "Running the collector again without an sru folder ..."
    $logLines3 = @((Invoke-Collector -Letter $letter -OutputPath $out3) -split "`r?`n")
    $missingLine = @($logLines3 | Where-Object { $_ -match 'SRUM folder not found' })
    Write-TestResult -Succeeded ($missingLine.Count -eq 1 -and $missingLine[0] -notmatch 'WARNING|ERROR') -Message "a missing sru folder is logged as information"
    Write-TestResult -Succeeded (-not (Test-Path -LiteralPath (Join-Path $out3 "Execution\SRUM"))) -Message "no Execution\SRUM folder without an sru folder"
    $srumProblems = @($logLines3 | Where-Object { $_ -match 'SRUM' -and $_ -match 'WARNING|ERROR' })
    Write-TestResult -Succeeded ($srumProblems.Count -eq 0) -Message "no SRUM warnings or errors without an sru folder"

    # =========================================================
    # Live system, with a folder standing in for the shadow copy
    # =========================================================
    # Load the collector's functions without running a collection: every
    # function definition that is not inside another function (many sit
    # inside the collector's main try block)
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($collector, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw "$collector does not parse: $($parseErrors[0].Message)" }
    $definitions = New-Object System.Collections.Generic.List[string]
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        $nested = $false
        for ($parent = $node.Parent; $parent; $parent = $parent.Parent) {
            if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $nested = $true; break }
        }
        if (-not $nested) { $definitions.Add($node.Extent.Text) }
    }
    . ([scriptblock]::Create($definitions -join "`r`n"))
    if (-not (Get-Command Copy-TriageSrumFiles -ErrorAction SilentlyContinue)) { throw "Copy-TriageSrumFiles not found in $collector" }

    # Collector state for a live collection; the "volume" and the "shadow
    # copy" are plain folders
    $liveRoot = Join-Path $workDir "live"
    $shadowRoot = Join-Path $workDir "shadow"
    $liveSru = Join-Path $liveRoot "Windows\System32\sru"
    $shadowSru = Join-Path $shadowRoot "Windows\System32\sru"
    $script:TargetRoot = "$liveRoot\"
    $script:IsLive = $true
    $script:shadowPath = $shadowRoot
    $script:shadowUnavailable = $false
    $script:logToFile = $true
    $script:fileCount = 0
    $script:errorCount = 0
    $script:totalBytes = 0

    # Volume: the database and logs as they are now, with a newer log
    # (SRU0000B.log); shadow copy: an older state of the same files, with a
    # log deleted on the volume since (SRU00009.log)
    $volumeFiles = [ordered]@{ "SRUDB.dat" = $dbBytes; "SRU.chk" = (New-RandomBytes 8192); "SRU.log" = (New-RandomBytes 65536); "SRU0000B.log" = (New-RandomBytes 65536) }
    $shadowFiles = [ordered]@{ "SRUDB.dat" = (New-RandomBytes 1MB); "SRU.chk" = (New-RandomBytes 8192); "SRU.log" = (New-RandomBytes 65536); "SRU00009.log" = (New-RandomBytes 65536) }
    foreach ($name in $volumeFiles.Keys) { New-TestFile -Path (Join-Path $liveSru $name) -Bytes $volumeFiles[$name] -ModifiedUtc $modified.AddHours(2) }
    foreach ($name in $shadowFiles.Keys) { New-TestFile -Path (Join-Path $shadowSru $name) -Bytes $shadowFiles[$name] -ModifiedUtc $modified.AddHours(1) }

    # Runs Copy-TriageSrumFiles into a new collection folder (the
    # collector's $OutputPath, $logFile and $manifestFile); returns the
    # folder, the log lines it wrote and its error count
    function Invoke-SrumCopy {
        param([string]$Name, [string]$SourceDir)
        $script:OutputPath = Join-Path $workDir $Name
        New-Item -ItemType Directory -Path $script:OutputPath | Out-Null
        $script:logFile = Join-Path $script:OutputPath "collection_log.txt"
        $script:manifestFile = Join-Path $script:OutputPath "collection_manifest.csv"
        [System.IO.File]::WriteAllText($script:manifestFile, "SHA256,SourcePath,DestPath,SizeBytes,CollectedAt,RelativePath,SourceCreatedUtc,SourceModifiedUtc,SourceAccessedUtc`r`n")
        $script:errorCount = 0
        Copy-TriageSrumFiles -SourceDir $SourceDir -DestDir (Join-Path $script:OutputPath "Execution\SRUM") -MaxBytes 16GB 6>$null
        $lines = @()
        if (Test-Path -LiteralPath $script:logFile) { $lines = @(Get-Content -LiteralPath $script:logFile) }
        return [PSCustomObject]@{ Path = $script:OutputPath; Log = $lines; Errors = $script:errorCount }
    }

    # SRUDB.dat in the shadow copy: everything from the shadow copy
    $shadowRun = Invoke-SrumCopy -Name "live-shadow" -SourceDir $liveSru
    $shadowExpected = [ordered]@{}
    foreach ($name in $shadowFiles.Keys) { $shadowExpected[$name] = Join-Path $shadowSru $name }
    Test-CollectedSrum -Collection $shadowRun.Path -Expected $shadowExpected -SourceFor { param($Name) "(shadow)Windows\System32\sru\$Name" } -Label "live, shadow copy"
    Write-TestResult -Succeeded (@($shadowRun.Log | Where-Object { $_ -match 'OK: Collected 4 SRUM file\(s\) \(from the shadow copy\)\.' }).Count -eq 1) -Message "live, shadow copy: the log reports 4 SRUM files from the shadow copy"
    Write-TestResult -Succeeded ($shadowRun.Errors -eq 0 -and -not ($shadowRun.Log -match 'WARNING|ERROR')) -Message "live, shadow copy: no warnings or errors"

    # The newer log is skipped when the shadow copy cannot be listed (the
    # volume's file names are used then)
    $savedListing = ${function:Get-ShadowFileNames}
    try {
        ${function:Get-ShadowFileNames} = { param([string]$RelativePath) Write-Verbose "not listed: $RelativePath"; return $null }
        $unlistedRun = Invoke-SrumCopy -Name "live-unlisted" -SourceDir $liveSru
    }
    finally { ${function:Get-ShadowFileNames} = $savedListing }
    $unlistedExpected = [ordered]@{}
    foreach ($name in @("SRUDB.dat", "SRU.chk", "SRU.log")) { $unlistedExpected[$name] = Join-Path $shadowSru $name }
    Test-CollectedSrum -Collection $unlistedRun.Path -Expected $unlistedExpected -SourceFor { param($Name) "(shadow)Windows\System32\sru\$Name" } -Label "live, shadow copy not listable"
    Write-TestResult -Succeeded (@($unlistedRun.Log | Where-Object { $_ -match 'SRUM file not in the shadow copy .* skipped: SRU0000B\.log' -and $_ -notmatch 'WARNING' }).Count -eq 1) -Message "live, shadow copy not listable: the newer log is skipped with an information line"

    # No SRUDB.dat in the shadow copy: everything from the volume
    Remove-Item -LiteralPath (Join-Path $shadowSru "SRUDB.dat") -Force
    $volumeRun = Invoke-SrumCopy -Name "live-volume" -SourceDir $liveSru
    $volumeExpected = [ordered]@{}
    foreach ($name in $volumeFiles.Keys) { $volumeExpected[$name] = Join-Path $liveSru $name }
    Test-CollectedSrum -Collection $volumeRun.Path -Expected $volumeExpected -SourceFor { param($Name) "$liveSru\$Name" } -Label "live, no database in the shadow copy"
    Write-TestResult -Succeeded (@($volumeRun.Log | Where-Object { $_ -match 'SRUDB\.dat could not be read from the shadow copy' }).Count -eq 1) -Message "live, no database in the shadow copy: the fallback to the volume is logged"
    Write-TestResult -Succeeded (@($volumeRun.Log | Where-Object { $_ -match 'OK: Collected 4 SRUM file\(s\) \(from the volume\)\.' }).Count -eq 1) -Message "live, no database in the shadow copy: the log reports 4 SRUM files from the volume"

    # A sru folder that cannot be listed (mounted image): a warning and an
    # error count, not an information line
    $script:IsLive = $false
    $script:shadowPath = $null
    $deniedDir = $liveSru
    $deny = Invoke-NativeTool "icacls.exe" @($deniedDir, "/deny", "*${userSid}:(RD)")
    if ($deny.ExitCode -ne 0) {
        $deniedDir = $null
        Write-Host "SKIPPED: unreadable sru folder case (icacls /deny failed: $($deny.Output -join ' '))" -ForegroundColor Yellow
    }
    else {
        $deniedRun = Invoke-SrumCopy -Name "denied" -SourceDir $liveSru
        Write-TestResult -Succeeded (@($deniedRun.Log | Where-Object { $_ -match 'WARNING: Could not list the SRUM folder' }).Count -eq 1) -Message "unreadable sru folder: a warning is logged"
        Write-TestResult -Succeeded ($deniedRun.Errors -gt 0) -Message "unreadable sru folder: counted as an error"
        Write-TestResult -Succeeded (-not ($deniedRun.Log -match 'SRUM folder is empty')) -Message "unreadable sru folder: not reported as empty"
    }
}
catch {
    Write-TestResult -Succeeded $false -Message "test setup or run error: $($_.Exception.Message)"
}
finally {
    if ($deniedDir) { $null = Invoke-NativeTool "icacls.exe" @($deniedDir, "/remove:d", "*$userSid") }
    if ($letter) { $null = Invoke-NativeTool "subst.exe" @("${letter}:", "/d") }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all SRUM collection checks passed" -ForegroundColor Green
exit 0

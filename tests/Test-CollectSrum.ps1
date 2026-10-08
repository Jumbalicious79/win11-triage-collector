# =============================================================
# SRUM collection test
# Builds a fake mounted image (a folder with Windows\System32 and a
# Windows\System32\sru folder holding a placeholder SRUDB.dat with its
# checkpoint, logs, reserve logs and flush map, a file over the 2 GB size
# cap -- sparse, so it takes no disk space -- and a subfolder), maps it to a
# free drive letter with subst and runs triage-collector.ps1 -TargetDrive
# <letter> -Categories Execution -Unattended -NoCompress on it. Checks that
# every SRUM file is in Execution\SRUM\ byte for byte, with a manifest row
# (hash, source path, original modified time), that the oversize file and
# the subfolder were not collected and the skip was logged. A second run on
# an image without an sru folder must log that as information only.
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

# Runs the collector on the image mapped to $Letter; returns its output
function Invoke-Collector {
    param([string]$Letter, [string]$OutputPath)
    $ErrorActionPreference = "Continue"
    $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $collector `
        -TargetDrive $Letter -Categories Execution -Unattended -NoCompress -OutputPath $OutputPath 2>&1
    return , @($output | ForEach-Object { "$_" })
}

# Writes a file with the given bytes and a known modified time (UTC)
function New-TestFile {
    param([string]$Path, [byte[]]$Bytes, [datetime]$ModifiedUtc)
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
    [System.IO.File]::SetLastWriteTimeUtc($Path, $ModifiedUtc)
}

$random = New-Object System.Random 20261007
function New-RandomBytes {
    param([int]$Count)
    $bytes = New-Object byte[] $Count
    $random.NextBytes($bytes)
    return , $bytes
}

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("srum-collect-test-" + [guid]::NewGuid().ToString("N"))
$letter = $null
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
    $expectedFiles = [ordered]@{
        "SRUDB.dat"       = $dbBytes
        "SRUDB.jfm"       = (New-RandomBytes 16384)
        "SRU.chk"         = (New-RandomBytes 8192)
        "SRU.log"         = (New-RandomBytes 65536)
        "SRU0000A.log"    = (New-RandomBytes 65536)
        "SRUtmp.log"      = (New-RandomBytes 65536)
        "SRUres00001.jrs" = (New-RandomBytes 65536)
        "SRUres00002.jrs" = (New-RandomBytes 65536)
    }
    $i = 0
    foreach ($name in $expectedFiles.Keys) {
        New-TestFile -Path (Join-Path $sruDir $name) -Bytes $expectedFiles[$name] -ModifiedUtc $modified.AddMinutes($i)
        $i++
    }
    # A subfolder: only the folder's own files are collected
    New-TestFile -Path (Join-Path $sruDir "sub\nested.dat") -Bytes (New-RandomBytes 100) -ModifiedUtc $modified

    # Over the size cap (2 GB): a sparse file, so no disk space is used
    $oversize = Join-Path $sruDir "SRUoversize.dat"
    [System.IO.File]::WriteAllBytes($oversize, [byte[]]@())
    $sparse = Invoke-NativeTool "fsutil.exe" @("sparse", "setflag", $oversize)
    $oversizeCase = $sparse.ExitCode -eq 0
    if ($oversizeCase) {
        $stream = [System.IO.File]::Open($oversize, "Open", "ReadWrite", "None")
        try { $stream.SetLength(2GB + 1) } finally { $stream.Dispose() }
    } else {
        Remove-Item -LiteralPath $oversize -Force
        Write-Host "SKIPPED: oversize file case (fsutil sparse setflag failed: $($sparse.Output -join ' '))" -ForegroundColor Yellow
    }

    # --- Map the image to a drive letter and collect ---
    $letter = Get-FreeDriveLetter
    if (-not $letter) { throw "no free drive letter for subst" }
    $subst = Invoke-NativeTool "subst.exe" @("${letter}:", $image)
    if ($subst.ExitCode -ne 0) { throw "subst ${letter}: failed: $($subst.Output -join ' ')" }
    Write-Host "Fake image $image mapped to ${letter}:"

    $out1 = Join-Path $workDir "collection1"
    Write-Host "Running the collector ($powershellExe) on ${letter}: ..."
    $output1 = Invoke-Collector -Letter $letter -OutputPath $out1
    $log1 = Join-Path $out1 "collection_log.txt"
    if (-not (Test-Path -LiteralPath $log1)) {
        $output1 | ForEach-Object { Write-Host "  | $_" }
        throw "the collector wrote no collection_log.txt to $out1"
    }
    $logText1 = [System.IO.File]::ReadAllText($log1)
    Write-TestResult -Succeeded ($logText1 -match 'Mode: MOUNTED IMAGE') -Message "the collector ran in mounted-image mode on ${letter}:"

    $manifest = @(Import-Csv -LiteralPath (Join-Path $out1 "collection_manifest.csv"))
    $srumOut = Join-Path $out1 "Execution\SRUM"
    foreach ($name in $expectedFiles.Keys) {
        $dest = Join-Path $srumOut $name
        $source = Join-Path $sruDir $name
        $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        if (-not (Test-Path -LiteralPath $dest)) {
            Write-TestResult -Succeeded $false -Message "$name collected to Execution\SRUM"
            continue
        }
        $problems = @()
        if ((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -ne $sourceHash) { $problems += "copy differs from the original (SHA256)" }
        $row = $manifest | Where-Object { $_.RelativePath -eq "Execution\SRUM\$name" } | Select-Object -First 1
        if (-not $row) { $problems += "no manifest row" }
        else {
            if ($row.SHA256 -ne $sourceHash) { $problems += "manifest SHA256 $($row.SHA256)" }
            if ($row.SourcePath -ne "${letter}:\Windows\System32\sru\$name") { $problems += "manifest SourcePath $($row.SourcePath)" }
            $expectedModified = [System.IO.File]::GetLastWriteTimeUtc($source).ToString("o")
            if ($row.SourceModifiedUtc -ne $expectedModified) { $problems += "manifest SourceModifiedUtc $($row.SourceModifiedUtc) (expected $expectedModified)" }
        }
        Write-TestResult -Succeeded ($problems.Count -eq 0) -Message ("$name collected to Execution\SRUM with its manifest row" + $(if ($problems) { " -- " + ($problems -join "; ") } else { "" }))
    }
    $extra = @(Get-ChildItem -LiteralPath $srumOut -Force -ErrorAction SilentlyContinue | Where-Object { $expectedFiles.Keys -notcontains $_.Name } | ForEach-Object { $_.Name })
    Write-TestResult -Succeeded ($extra.Count -eq 0) -Message "nothing else in Execution\SRUM (no subfolder, no oversize file)$(if ($extra) { ' -- found: ' + ($extra -join ', ') })"
    Write-TestResult -Succeeded ($logText1 -match [regex]::Escape("Collected $($expectedFiles.Count) SRUM file(s).")) -Message "the log reports $($expectedFiles.Count) SRUM files collected"
    if ($oversizeCase) {
        Write-TestResult -Succeeded ($logText1 -match 'Skipped SRUM file .*SRUoversize\.dat .*larger than the 2048 MB size cap') -Message "the oversize file is skipped and the reason logged"
        Write-TestResult -Succeeded (-not ($manifest | Where-Object { $_.SourcePath -like "*SRUoversize.dat" })) -Message "the oversize file has no manifest row"
    }
    Write-TestResult -Succeeded ($logText1 -match 'Skipping RecentApps, BAM, AppCompatCache \(mounted image') -Message "the live-only execution steps are skipped in image mode"

    # --- An image without an sru folder: information only ---
    Remove-Item -LiteralPath $sruDir -Recurse -Force
    $out2 = Join-Path $workDir "collection2"
    Write-Host "Running the collector again without an sru folder ..."
    $output2 = Invoke-Collector -Letter $letter -OutputPath $out2
    $log2 = Join-Path $out2 "collection_log.txt"
    if (-not (Test-Path -LiteralPath $log2)) {
        $output2 | ForEach-Object { Write-Host "  | $_" }
        throw "the second collector run wrote no collection_log.txt"
    }
    $logLines2 = @(Get-Content -LiteralPath $log2)
    $missingLine = @($logLines2 | Where-Object { $_ -match 'SRUM folder not found' })
    Write-TestResult -Succeeded ($missingLine.Count -eq 1 -and $missingLine[0] -notmatch 'WARNING|ERROR') -Message "a missing sru folder is logged as information"
    Write-TestResult -Succeeded (-not (Test-Path -LiteralPath (Join-Path $out2 "Execution\SRUM"))) -Message "no Execution\SRUM folder without an sru folder"
    $srumProblems = @($logLines2 | Where-Object { $_ -match 'SRUM' -and $_ -match 'WARNING|ERROR' })
    Write-TestResult -Succeeded ($srumProblems.Count -eq 0) -Message "no SRUM warnings or errors without an sru folder"
}
catch {
    Write-TestResult -Succeeded $false -Message "test setup or run error: $($_.Exception.Message)"
}
finally {
    if ($letter) { $null = Invoke-NativeTool "subst.exe" @("${letter}:", "/d") }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all SRUM collection checks passed" -ForegroundColor Green
exit 0

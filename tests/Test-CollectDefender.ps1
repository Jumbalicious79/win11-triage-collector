# =============================================================
# Defender collection test (DetectionHistory and quarantine metadata)
# Builds a fake mounted image (a folder with Windows\System32 and a
# ProgramData\Microsoft\Windows Defender tree of made-up files: no real
# detections, no malware), maps it to a free drive letter with subst, runs
# triage-collector.ps1 on it in mounted-image mode (-Categories AntiVirus
# -Unattended -NoCompress) and checks that:
#   - every DetectionHistory file (in its numbered subfolder) and every
#     Quarantine\Entries file is collected byte for byte, with a manifest row
#     that has the original path and the original creation and last write
#     times
#   - a file over the 1 MB cap and an empty file are not collected, and the
#     skipped file is named in the log
#   - nothing from Quarantine\ResourceData (the quarantined files) or
#     Quarantine\Resources is collected: no such path in the collection or
#     the manifest, and their canary content is in no collected file
#   - the Defender support log is still collected as before
#   - an image without these folders logs an info line for each and no error
#   - a DetectionHistory folder the account may not open (deny entries for
#     the current user on the test's own temporary folders, removed again
#     afterwards) gives an "access denied" warning, not a "no folder" line
#   - of 2001 DetectionHistory files only the newest 2000 are collected (with
#     manifest rows), the oldest is not, and the log says so
# The subst drive letter is removed in a finally block.
# Needs Administrator rights, like the collector (GitHub Actions Windows
# runners are elevated). For a local run without them, pass -CollectorPath
# with a copy of the collector that has no admin check, kept inside the
# repository (e.g. under the git-ignored reports\ folder).
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-CollectDefender.ps1
#   ... -CollectorPath <copy>   test another copy of triage-collector.ps1
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
$script:checks = 0

function Write-TestResult {
    param([string]$Name, [bool]$Passed, [string]$Message = "")
    $script:checks++
    if ($Passed) {
        Write-Host "PASS: $Name" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Name" -ForegroundColor Red
    if ($Message) { Write-Host "  $($Message -replace "`n", "`n  ")" }
    if ($env:GITHUB_ACTIONS) {
        $oneLine = ($Message -replace "`r?`n", " / ")
        Write-Host "::error file=tests/Test-CollectDefender.ps1::$Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
    }
}

function Assert-Equal {
    param([string]$Name, $Expected, $Actual)
    Write-TestResult -Name $Name -Passed ("$Expected" -ceq "$Actual") -Message "expected: $Expected`nactual  : $Actual"
}

# The collector refuses to run without Administrator rights (a -CollectorPath
# copy may not)
if (-not $CollectorPath) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-TestResult -Name "Administrator rights" -Passed $false -Message "the collector needs them. Run elevated, or pass -CollectorPath with a collector copy without the admin check."
        exit 1
    }
}

# Run a console tool; returns its exit code. Error action Continue: with Stop,
# Windows PowerShell 5.1 turns any stderr line into a terminating error.
function Invoke-NativeTool {
    param([string]$FilePath, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $null = & $FilePath @Arguments 2>&1 }
    finally { $ErrorActionPreference = $previous }
    return $LASTEXITCODE
}

# Runs the collector on drive $Letter (AntiVirus only, no prompts, no zip);
# returns its exit code
function Invoke-Collector {
    param([string]$Letter, [string]$OutputPath)
    $powershellExe = (Get-Process -Id $PID).Path
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $null = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $collector -TargetDrive $Letter -Categories AntiVirus `
            -Unattended -NoCompress -OutputPath $OutputPath 2>&1
    }
    finally { $ErrorActionPreference = $previous }
    return $LASTEXITCODE
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

# Writes a file with the given bytes and fixed original times (last write
# $Utc, creation one hour earlier)
function New-TestFile {
    param([string]$Path, [byte[]]$Bytes, [datetime]$Utc)
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
    [System.IO.File]::SetCreationTimeUtc($Path, $Utc.AddHours(-1))
    [System.IO.File]::SetLastWriteTimeUtc($Path, $Utc)
}

$random = New-Object System.Random 20261007
function New-RandomBytes {
    param([int]$Count)
    $bytes = New-Object byte[] $Count
    $random.NextBytes($bytes)
    return , $bytes
}

# Free drive letter for subst (Z down to G)
$letter = $null
$usedLetters = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
foreach ($candidate in [char[]]"ZYXWVUTSRQPONMLKJIHG") {
    if ($usedLetters -notcontains [string]$candidate) { $letter = [string]$candidate; break }
}
if (-not $letter) {
    Write-TestResult -Name "free drive letter" -Passed $false -Message "no free drive letter for subst"
    exit 1
}

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("collect-defender-test-" + [guid]::NewGuid().ToString("N"))
$imageDir = Join-Path $workDir "image"
$emptyImageDir = Join-Path $workDir "image-empty"
$deniedImageDir = Join-Path $workDir "image-denied"
$deniedHistory = Join-Path $deniedImageDir "ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory"
$denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule([System.Security.Principal.WindowsIdentity]::GetCurrent().User,
    ([System.Security.AccessControl.FileSystemRights]"ListDirectory, ReadAttributes, ReadExtendedAttributes"), ([System.Security.AccessControl.AccessControlType]::Deny))
$deniedDirs = @()
$mapped = $false
# Canary content of the files that must never be collected
$canary = "TRIAGE-TEST-QUARANTINED-CONTENT-MUST-NOT-BE-COLLECTED"
try {
    # --- Fake image ---
    $defender = Join-Path $imageDir "ProgramData\Microsoft\Windows Defender"
    $history = Join-Path $defender "Scans\History\Service\DetectionHistory"
    $quarantine = Join-Path $defender "Quarantine"
    New-Item -ItemType Directory -Path (Join-Path $imageDir "Windows\System32") -Force | Out-Null
    $fileTime = [datetime]::SpecifyKind([datetime]"2026-03-01 10:00:00", [System.DateTimeKind]::Utc)
    $expected = @(
        @{ Rel = "Scans\History\Service\DetectionHistory\02\{0D1E2F30-4152-4637-8899-AABBCCDDEE01}"; Dest = "AntiVirus\Defender\DetectionHistory\02\{0D1E2F30-4152-4637-8899-AABBCCDDEE01}"; Size = 4264 },
        @{ Rel = "Scans\History\Service\DetectionHistory\07\{0D1E2F30-4152-4637-8899-AABBCCDDEE02}"; Dest = "AntiVirus\Defender\DetectionHistory\07\{0D1E2F30-4152-4637-8899-AABBCCDDEE02}"; Size = 3016 },
        @{ Rel = "Quarantine\Entries\{0000A1B2-0000-0000-0000-000000000001}"; Dest = "AntiVirus\Defender\Quarantine\Entries\{0000A1B2-0000-0000-0000-000000000001}"; Size = 612 }
    )
    foreach ($file in $expected) {
        New-TestFile -Path (Join-Path $defender $file.Rel) -Bytes (New-RandomBytes $file.Size) -Utc $fileTime
    }
    $bigFile = Join-Path $history "02\{0D1E2F30-4152-4637-8899-AABBCCDDEE03}"
    New-TestFile -Path $bigFile -Bytes (New-RandomBytes (1MB + 1)) -Utc $fileTime
    $emptyFile = Join-Path $history "02\{0D1E2F30-4152-4637-8899-AABBCCDDEE04}"
    New-TestFile -Path $emptyFile -Bytes ([byte[]]@()) -Utc $fileTime
    $canaryBytes = [System.Text.Encoding]::ASCII.GetBytes($canary)
    New-TestFile -Path (Join-Path $quarantine "ResourceData\AB\AB0123456789ABCDEF0123456789ABCDEF012345") -Bytes $canaryBytes -Utc $fileTime
    New-TestFile -Path (Join-Path $quarantine "Resources\AB\AB0123456789ABCDEF0123456789ABCDEF012345") -Bytes $canaryBytes -Utc $fileTime
    # Support log: collected before this change, must still be
    $supportLog = "Support\MPLog-20260301-100000.log"
    New-TestFile -Path (Join-Path $defender $supportLog) -Bytes ([System.Text.Encoding]::Unicode.GetBytes("2026-03-01T10:00:00.000Z Engine: test line`r`n")) -Utc $fileTime
    New-Item -ItemType Directory -Path (Join-Path $emptyImageDir "Windows\System32") -Force | Out-Null

    # --- Run 1: image with Defender data ---
    if ((Invoke-NativeTool "subst.exe" @("${letter}:", $imageDir)) -ne 0) { throw "subst ${letter}: $imageDir failed" }
    $mapped = $true
    $output = Join-Path $workDir "out1"
    Write-Host "Running the collector on ${letter}: (fake image with Defender data) ..."
    $exitCode = Invoke-Collector -Letter $letter -OutputPath $output
    Assert-Equal -Name "collector exit code" -Expected 0 -Actual $exitCode
    $null = Invoke-NativeTool "subst.exe" @("${letter}:", "/d")
    $mapped = $false

    $logText = ""
    $logPath = Join-Path $output "collection_log.txt"
    if (Test-Path -LiteralPath $logPath) { $logText = [System.IO.File]::ReadAllText($logPath) }
    $manifest = @()
    $manifestPath = Join-Path $output "collection_manifest.csv"
    if (Test-Path -LiteralPath $manifestPath) { $manifest = @(Import-Csv -LiteralPath $manifestPath) }

    foreach ($file in $expected) {
        $source = Join-Path $defender $file.Rel
        $dest = Join-Path $output $file.Dest
        $name = Split-Path $file.Dest -Leaf
        if (-not (Test-Path -LiteralPath $dest)) {
            Write-TestResult -Name "collected: $($file.Dest)" -Passed $false -Message "not in the collection"
            continue
        }
        Assert-Equal -Name "collected byte for byte: $name" -Expected (Get-Sha256 $source) -Actual (Get-Sha256 $dest)
        $row = @($manifest | Where-Object { $_.RelativePath -eq $file.Dest })
        $originalPath = "${letter}:\ProgramData\Microsoft\Windows Defender\$($file.Rel)"
        Assert-Equal -Name "manifest row: $name" -Expected "1 $originalPath $($fileTime.AddHours(-1).ToString('o')) $($fileTime.ToString('o'))" `
            -Actual ("$($row.Count) $(@($row | ForEach-Object { $_.SourcePath }) -join ',') $(@($row | ForEach-Object { $_.SourceCreatedUtc }) -join ',') " +
                "$(@($row | ForEach-Object { $_.SourceModifiedUtc }) -join ',')")
    }

    $collected = @(Get-ChildItem -LiteralPath $output -File -Recurse -Force -ErrorAction SilentlyContinue)
    $defenderFiles = @($collected | Where-Object { $_.FullName -match '\\AntiVirus\\Defender\\(DetectionHistory|Quarantine)\\' })
    Assert-Equal -Name "only the expected DetectionHistory and Entries files" -Expected $expected.Count -Actual $defenderFiles.Count
    Assert-Equal -Name "file over 1 MB not collected" -Expected $false -Actual (@($collected | Where-Object { $_.Name -like "*EE03}" }).Count -gt 0)
    Write-TestResult -Name "file over 1 MB named in the log" -Passed ($logText -match ('Skipped Defender DetectionHistory file over 1 MB \(1048577 bytes\): ' + [regex]::Escape($bigFile.Replace($imageDir, "${letter}:")))) `
        -Message "log line not found"
    Assert-Equal -Name "empty file not collected" -Expected $false -Actual (@($collected | Where-Object { $_.Name -like "*EE04}" }).Count -gt 0)
    Assert-Equal -Name "nothing from ResourceData or Resources in the collection" -Expected 0 -Actual @($collected | Where-Object { $_.FullName -match '\\(ResourceData|Resources)\\' }).Count
    Assert-Equal -Name "nothing from ResourceData or Resources in the manifest" -Expected 0 -Actual @($manifest | Where-Object { $_.SourcePath -match '\\Quarantine\\(ResourceData|Resources)\\' }).Count
    $withCanary = @($collected | Where-Object { [System.Text.Encoding]::GetEncoding(28591).GetString([System.IO.File]::ReadAllBytes($_.FullName)).Contains($canary) })
    Assert-Equal -Name "quarantined content in no collected file" -Expected 0 -Actual $withCanary.Count
    Assert-Equal -Name "support log still collected" -Expected $true -Actual (Test-Path -LiteralPath (Join-Path $output "AntiVirus\Defender\MPLog-20260301-100000.log"))
    Assert-Equal -Name "log: DetectionHistory count" -Expected $true -Actual ($logText -match 'OK: Collected 2 Defender DetectionHistory file\(s\)\.')
    Assert-Equal -Name "log: quarantine entry count" -Expected $true -Actual ($logText -match 'OK: Collected 1 Defender quarantine entry file\(s\)\.')
    $errorLines = @($logText -split "`r?`n" | Where-Object { $_ -match '\] (ERROR|WARNING): ' -and $_ -notmatch 'target time zone could not be read' })
    Write-TestResult -Name "log: no errors or warnings" -Passed ($errorLines.Count -eq 0) -Message ($errorLines -join "`n")

    # --- Run 2: image without Defender data ---
    if ((Invoke-NativeTool "subst.exe" @("${letter}:", $emptyImageDir)) -ne 0) { throw "subst ${letter}: $emptyImageDir failed" }
    $mapped = $true
    $output2 = Join-Path $workDir "out2"
    Write-Host "Running the collector on ${letter}: (fake image without Defender data) ..."
    $exitCode = Invoke-Collector -Letter $letter -OutputPath $output2
    Assert-Equal -Name "collector exit code (no Defender data)" -Expected 0 -Actual $exitCode
    $null = Invoke-NativeTool "subst.exe" @("${letter}:", "/d")
    $mapped = $false
    $logText2 = ""
    if (Test-Path -LiteralPath (Join-Path $output2 "collection_log.txt")) { $logText2 = [System.IO.File]::ReadAllText((Join-Path $output2 "collection_log.txt")) }
    Assert-Equal -Name "log: no DetectionHistory folder (info line)" -Expected $true -Actual ($logText2 -match '\] No Defender DetectionHistory folder on the target')
    Assert-Equal -Name "log: no Quarantine\Entries folder (info line)" -Expected $true -Actual ($logText2 -match '\] No Defender Quarantine\\Entries folder on the target')
    $errorLines2 = @($logText2 -split "`r?`n" | Where-Object { $_ -match '\] (ERROR|WARNING): ' -and $_ -notmatch 'target time zone could not be read' })
    Write-TestResult -Name "log: no errors or warnings (no Defender data)" -Passed ($errorLines2.Count -eq 0) -Message ($errorLines2 -join "`n")
    Assert-Equal -Name "no Defender folder in the collection (no Defender data)" -Expected $false -Actual (Test-Path -LiteralPath (Join-Path $output2 "AntiVirus\Defender"))

    # --- Run 3: a DetectionHistory folder this account may not open ---
    # (deny entries for the current user on the test's own folders, removed
    # again in the finally block)
    New-Item -ItemType Directory -Path (Join-Path $deniedImageDir "Windows\System32"), (Join-Path $deniedHistory "02") -Force | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $deniedHistory "02\{0D1E2F30-4152-4637-8899-AABBCCDDEE05}"), (New-RandomBytes 100))
    foreach ($deniedDir in @($deniedHistory, (Split-Path $deniedHistory -Parent))) {
        $acl = Get-Acl -LiteralPath $deniedDir
        $acl.AddAccessRule($denyRule)
        Set-Acl -LiteralPath $deniedDir -AclObject $acl
        $deniedDirs += $deniedDir
    }
    if ((Invoke-NativeTool "subst.exe" @("${letter}:", $deniedImageDir)) -ne 0) { throw "subst ${letter}: $deniedImageDir failed" }
    $mapped = $true
    $output3 = Join-Path $workDir "out3"
    Write-Host "Running the collector on ${letter}: (DetectionHistory folder not readable) ..."
    $exitCode = Invoke-Collector -Letter $letter -OutputPath $output3
    Assert-Equal -Name "collector exit code (folder not readable)" -Expected 0 -Actual $exitCode
    $null = Invoke-NativeTool "subst.exe" @("${letter}:", "/d")
    $mapped = $false
    $logText3 = ""
    if (Test-Path -LiteralPath (Join-Path $output3 "collection_log.txt")) { $logText3 = [System.IO.File]::ReadAllText((Join-Path $output3 "collection_log.txt")) }
    Write-TestResult -Name "log: DetectionHistory folder not readable (warning, not 'no folder')" -Message ($logText3 -split "`r?`n" | Where-Object { $_ -match 'Defender' } | Out-String) -Passed (
        $logText3 -match '\] WARNING: Could not open the Defender DetectionHistory folder \(access denied\): ' -and $logText3 -notmatch 'No Defender DetectionHistory folder')
    Assert-Equal -Name "nothing collected from the folder that is not readable" -Expected $false -Actual (Test-Path -LiteralPath (Join-Path $output3 "AntiVirus\Defender\DetectionHistory"))

    # --- Run 4: more DetectionHistory files than the cap (the newest 2000) ---
    # 2001 tiny files in two subfolders, one minute apart; file 0 is the oldest
    $capImageDir = Join-Path $workDir "image-cap"
    $capHistory = Join-Path $capImageDir "ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory"
    New-Item -ItemType Directory -Path (Join-Path $capImageDir "Windows\System32"), (Join-Path $capHistory "02"), (Join-Path $capHistory "03") -Force | Out-Null
    $capNames = @()
    for ($n = 0; $n -le 2000; $n++) {
        $capName = "0$(2 + $n % 2)\{0D1E2F30-4152-4637-8899-" + $n.ToString("X12") + "}"
        $capPath = Join-Path $capHistory $capName
        [System.IO.File]::WriteAllBytes($capPath, [BitConverter]::GetBytes([int]$n))
        [System.IO.File]::SetLastWriteTimeUtc($capPath, $fileTime.AddMinutes($n))
        $capNames += $capName
    }
    if ((Invoke-NativeTool "subst.exe" @("${letter}:", $capImageDir)) -ne 0) { throw "subst ${letter}: $capImageDir failed" }
    $mapped = $true
    $output4 = Join-Path $workDir "out4"
    Write-Host "Running the collector on ${letter}: (2001 DetectionHistory files) ..."
    $exitCode = Invoke-Collector -Letter $letter -OutputPath $output4
    Assert-Equal -Name "collector exit code (2001 files)" -Expected 0 -Actual $exitCode
    $null = Invoke-NativeTool "subst.exe" @("${letter}:", "/d")
    $mapped = $false
    $logText4 = ""
    if (Test-Path -LiteralPath (Join-Path $output4 "collection_log.txt")) { $logText4 = [System.IO.File]::ReadAllText((Join-Path $output4 "collection_log.txt")) }
    $capDest = Join-Path $output4 "AntiVirus\Defender\DetectionHistory"
    Assert-Equal -Name "cap: 2000 DetectionHistory files collected" -Expected 2000 -Actual @(Get-ChildItem -LiteralPath $capDest -File -Recurse -Force -ErrorAction SilentlyContinue).Count
    Assert-Equal -Name "cap: the oldest file not collected" -Expected $false -Actual (Test-Path -LiteralPath (Join-Path $capDest $capNames[0]))
    Assert-Equal -Name "cap: the newest file collected" -Expected $true -Actual (Test-Path -LiteralPath (Join-Path $capDest $capNames[2000]))
    $capManifest = @()
    if (Test-Path -LiteralPath (Join-Path $output4 "collection_manifest.csv")) { $capManifest = @(Import-Csv -LiteralPath (Join-Path $output4 "collection_manifest.csv")) }
    Assert-Equal -Name "cap: 2000 manifest rows" -Expected 2000 -Actual @($capManifest | Where-Object { $_.RelativePath -like "AntiVirus\Defender\DetectionHistory\*" }).Count
    Assert-Equal -Name "log: cap skip line" -Expected $true -Actual (
        $logText4 -match '\] Skipped the 1 oldest Defender DetectionHistory file\(s\): only the newest 2000 are collected\.')
    Assert-Equal -Name "log: DetectionHistory count (2001 files)" -Expected $true -Actual ($logText4 -match 'OK: Collected 2000 Defender DetectionHistory file\(s\)\.')
}
catch {
    Write-TestResult -Name "test run" -Passed $false -Message "$($_.Exception.Message) ($($_.InvocationInfo.PositionMessage))"
}
finally {
    if ($mapped) { $null = Invoke-NativeTool "subst.exe" @("${letter}:", "/d") }
    # Parent first: until its entry is gone, the folder below cannot be opened by path
    [array]::Reverse($deniedDirs)
    foreach ($deniedDir in $deniedDirs) {
        try {
            $acl = Get-Acl -LiteralPath $deniedDir
            $null = $acl.RemoveAccessRule($denyRule)
            Set-Acl -LiteralPath $deniedDir -AclObject $acl
        }
        catch { Write-TestResult -Name "cleanup" -Passed $false -Message "could not remove the deny entry from ${deniedDir}: $($_.Exception.Message)" }
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $workDir) { Write-TestResult -Name "cleanup" -Passed $false -Message "could not remove $workDir" }
}

if ($script:failures -gt 0 -or $script:checks -eq 0) {
    Write-Host "FAIL: $($script:failures) of $($script:checks) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all $($script:checks) checks passed" -ForegroundColor Green
exit 0

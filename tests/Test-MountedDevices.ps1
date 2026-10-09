# =============================================================
# Mounted devices test
# Checks how the collector (triage-collector.ps1) writes MountedDevices.
# ConvertFrom-TriageMountedDeviceValue decodes synthetic values: a GPT
# partition, MBR disk signatures with partition offsets (one above 4 GiB),
# UTF-16 device paths ("_??_USBSTOR#...SD#MMC..." with and without a
# trailing NUL, "\??\SCSI#...") and values that are none of these (Other).
# Save-TriageMountedDevices then reads the same values from a test key
# under HKCU (removed afterwards) and must write mounted_devices.csv with
# the columns the timeline builder reads, the key's last-write time, a
# mounted_devices.txt with every value whole on one line, both files in the
# manifest and one log line with the count of each kind; a missing key
# gives a header-only CSV and a warning. Last, the collector's own
# statements around its main try block must lift $FormatEnumerationLimit
# (which cut lists in usb_storage_devices.txt to 4 items) also when run in
# a child scope, and restore it afterwards. No admin rights needed. Exit
# code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MountedDevices.ps1
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
foreach ($name in @("ConvertFrom-TriageMountedDeviceValue", "Get-TriageMountedDeviceRows", "Save-TriageMountedDevices")) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Host "FAIL: $name not found in $collector" -ForegroundColor Red
        exit 1
    }
}

# --- Collector state: log, manifest and counters ---
$testId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) "TriageMountedDevicesTest_$testId"
$OutputPath = Join-Path $workDir "collection"
$usbDir = Join-Path $OutputPath "USB"
$missingUsbDir = Join-Path $OutputPath "USB_missing_key"
$logFile = Join-Path $workDir "collection_log.txt"
$manifestFile = Join-Path $OutputPath "collection_manifest.csv"
$script:logToFile = $true
$script:fileCount = 0
$script:errorCount = 0
$script:totalBytes = 0
$script:regLastWriteReady = $null

# The test key, read through HKU\<SID> as the collector reads HKLM
$testKeyPath = "Software\TriageMountedDevicesTest_$testId"
$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# The columns the timeline builder reads from mounted_devices.csv
$contractColumns = @("Name", "Kind", "DiskSignature", "PartitionOffset", "PartitionGuid", "DevicePath",
    "DataLength", "HexData", "KeyLastWriteUtc")
$decodedFields = @($contractColumns | Where-Object { $_ -ne "KeyLastWriteUtc" })

function ConvertFrom-HexText {
    param([string]$Hex)
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [System.Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }
    return , $bytes
}
# UTF-16LE bytes of a text, as the registry stores a device path
function Get-Utf16Bytes {
    param([string]$Text, [switch]$TrailingNul)
    if ($TrailingNul) { $Text += [char]0 }
    return , [System.Text.Encoding]::Unicode.GetBytes($Text)
}
# Bytes as hex text, built byte by byte (not with the BitConverter call
# the decoder uses)
function Get-HexText {
    param([byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString("X2") }) -join "")
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

# The collector's error preference for each call into its functions
function Invoke-Collector {
    param([scriptblock]$Call)
    $ErrorActionPreference = "Continue"
    & $Call
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

# --- Synthetic values (no real serials, disk signatures or volume GUIDs) ---
# GPT: "DMIO:ID:" + the partition GUID in .NET byte order (the first three
# fields little-endian)
# MBR: the disk signature little-endian, then the partition offset as a
# 64-bit little-endian number. 0A0B0C0D needs its leading zero and its
# letters upper case; DEADBEEF has the high bit set
$gptHex = "444D494F3A49443A" + "1D2C3B4A5F6E7D8C9BAAB9C8D7E6F504"
# An SD card reader: the product name "SD/MMC" is stored as SD#MMC
$usbPath = "_??_USBSTOR#Disk&Ven_Generic-&Prod_SD#MMC&Rev_1.00#TRIAGETEST0001&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
$scsiPath = "\??\SCSI#Disk&Ven_TRIAGE&Prod_TEST_DISK#4&2b3c4d5e&0&000100#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
$usbNulBytes = Get-Utf16Bytes $usbPath -TrailingNul
$usbBytes = Get-Utf16Bytes $usbPath
$scsiBytes = Get-Utf16Bytes $scsiPath
$labelBytes = Get-Utf16Bytes "TriageTest"
$text = "TriageTest text value"

# What: case name; Name: value name; Data: value data; the other fields:
# the decoded fields that must not be blank (DataLength 0 if not given)
$caseSpecs = @(
    @{ What = "GPT partition"; Name = "\DosDevices\C:"; Data = (ConvertFrom-HexText $gptHex); Kind = "GPT"
        PartitionGuid = "{4a3b2c1d-6e5f-8c7d-9baa-b9c8d7e6f504}"; DataLength = 24; HexData = $gptHex }
    @{ What = "MBR 0D 0C 0B 0A 00 7E 00..."; Name = "\DosDevices\H:"; Data = (ConvertFrom-HexText "0D0C0B0A007E000000000000"); Kind = "MBR"
        DiskSignature = "0A0B0C0D"; PartitionOffset = "32256"; DataLength = 12; HexData = "0D0C0B0A007E000000000000" }
    @{ What = "MBR, offset above 4 GiB"; Name = "\DosDevices\I:"; Data = (ConvertFrom-HexText "EFBEADDE0000104001000000"); Kind = "MBR"
        DiskSignature = "DEADBEEF"; PartitionOffset = "5369757696"; DataLength = 12; HexData = "EFBEADDE0000104001000000" }
    @{ What = "USB SD#MMC path, trailing NUL"; Name = "\??\Volume{6c0f8a52-3d41-4b7e-9c2a-51e0d3b4a601}"; Data = $usbNulBytes; Kind = "DevicePath"
        DevicePath = $usbPath; DataLength = $usbNulBytes.Length; HexData = (Get-HexText $usbNulBytes) }
    @{ What = "USB SD#MMC path, no NUL"; Name = "\??\Volume{6c0f8a52-3d41-4b7e-9c2a-51e0d3b4a602}"; Data = $usbBytes; Kind = "DevicePath"
        DevicePath = $usbPath; DataLength = $usbBytes.Length; HexData = (Get-HexText $usbBytes) }
    @{ What = "\??\ device path"; Name = "\DosDevices\E:"; Data = $scsiBytes; Kind = "DevicePath"
        DevicePath = $scsiPath; DataLength = $scsiBytes.Length; HexData = (Get-HexText $scsiBytes) }
    @{ What = "8 bytes, not UTF-16"; Name = "\DosDevices\J:"; Data = (ConvertFrom-HexText "0102030405060708"); Kind = "Other"
        DataLength = 8; HexData = "0102030405060708" }
    @{ What = "UTF-16 text, no device prefix"; Name = "\DosDevices\K:"; Data = $labelBytes; Kind = "Other"
        DataLength = $labelBytes.Length; HexData = (Get-HexText $labelBytes) }
    @{ What = "24 bytes, not DMIO:ID:"; Name = "\DosDevices\L:"; Data = (ConvertFrom-HexText ("444D494F3A58583A" + "1D2C3B4A5F6E7D8C9BAAB9C8D7E6F504")); Kind = "Other"
        DataLength = 24; HexData = ("444D494F3A58583A" + "1D2C3B4A5F6E7D8C9BAAB9C8D7E6F504") }
    @{ What = "empty value"; Name = "\DosDevices\M:"; Data = (New-Object byte[] 0); Kind = "Other" }
    @{ What = "text value (REG_SZ)"; Name = "\DosDevices\N:"; Data = $text; Kind = "Other"; HexData = $text }
)
$cases = foreach ($spec in $caseSpecs) {
    $expected = [ordered]@{}
    foreach ($field in $decodedFields) { $expected[$field] = "" }
    $expected.Name = $spec.Name
    $expected.DataLength = "0"
    foreach ($key in $spec.Keys) {
        if ($expected.Contains($key)) { $expected[$key] = [string]$spec[$key] }
    }
    [PSCustomObject]@{ What = $spec.What; Name = $spec.Name; Data = $spec.Data; Expected = $expected }
}
# Every value but the text one must reach the decoder (and the registry)
# as binary: an empty text value would decode like an empty binary one
foreach ($case in $cases) {
    if (($case.Data -is [byte[]]) -ne ($case.What -notmatch 'REG_SZ')) {
        Write-Host "FAIL: test value '$($case.What)' has the wrong type" -ForegroundColor Red
        exit 1
    }
}

# Field-by-field differences between a decoded row and a case. Ordinal:
# -ceq compares by culture, which ignores a NUL character
function Compare-DecodedRow {
    param($Row, $Case, [System.Collections.Generic.List[string]]$Problems)
    foreach ($field in $decodedFields) {
        $actual = [string]$Row.$field
        if (-not [string]::Equals($actual, [string]$Case.Expected[$field], [System.StringComparison]::Ordinal)) {
            $Problems.Add("$($Case.What): $field is '$actual', expected '$($Case.Expected[$field])'")
        }
    }
}

# The formatter reads $FormatEnumerationLimit from the global scope only
function Get-GlobalEnumerationLimit {
    return (Get-Variable -Name FormatEnumerationLimit -Scope Global -ValueOnly)
}
function Set-GlobalEnumerationLimit {
    param($Value)
    Set-Variable -Name FormatEnumerationLimit -Scope Global -Value $Value
}

$savedLimit = Get-GlobalEnumerationLimit
$testKey = $null
try {
    New-Item -ItemType Directory -Path $usbDir, $missingUsbDir -Force | Out-Null

    # --- 1. The decoder, value by value ---
    foreach ($case in $cases) {
        $problems = New-Object System.Collections.Generic.List[string]
        $row = Invoke-Collector { ConvertFrom-TriageMountedDeviceValue -Name $case.Name -Data $case.Data }
        $names = @($row.PSObject.Properties | ForEach-Object { $_.Name })
        if (($names -join ",") -cne ($decodedFields -join ",")) { $problems.Add("properties: $($names -join ', ')") }
        Compare-DecodedRow -Row $row -Case $case -Problems $problems
        Add-Result "decode: $($case.What)" $problems -Info ((@($row.Kind, $row.DiskSignature, $row.PartitionOffset, $row.PartitionGuid) | Where-Object { $_ }) -join " ")
    }

    # --- 2. The same values in the test key, saved the way the collector
    # saves HKLM\SYSTEM\MountedDevices ---
    $testKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($testKeyPath)
    foreach ($case in $cases) {
        if ($case.Data -is [byte[]]) {
            $testKey.SetValue($case.Name, [byte[]]$case.Data, [Microsoft.Win32.RegistryValueKind]::Binary)
        } else {
            $testKey.SetValue($case.Name, [string]$case.Data, [Microsoft.Win32.RegistryValueKind]::String)
        }
    }
    $writtenUtc = [DateTime]::UtcNow
    $logBefore = Get-LogLines
    $errorsBefore = $script:errorCount
    $filesBefore = $script:fileCount
    Invoke-Collector { Save-TriageMountedDevices -UsbDir $usbDir -Hive "HKU" -KeyPath "$userSid\$testKeyPath" }
    $logNew = @(Get-LogLines | Select-Object -Skip $logBefore.Count)
    $csvPath = Join-Path $usbDir "mounted_devices.csv"
    $txtPath = Join-Path $usbDir "mounted_devices.txt"

    $problems = New-Object System.Collections.Generic.List[string]
    $expectedHeader = '"' + ($contractColumns -join '","') + '"'
    $header = ""
    if (Test-Path -LiteralPath $csvPath) { $header = [string](Get-Content -LiteralPath $csvPath -Encoding UTF8 -TotalCount 1) }
    if ($header -cne $expectedHeader) { $problems.Add("header is '$header'") }
    Add-Result "CSV columns are the builder's" $problems

    $problems = New-Object System.Collections.Generic.List[string]
    $csvRows = @()
    if (Test-Path -LiteralPath $csvPath) { $csvRows = @(Import-Csv -LiteralPath $csvPath -Encoding UTF8) }
    if ($csvRows.Count -ne $cases.Count) { $problems.Add("$($csvRows.Count) rows, expected $($cases.Count)") }
    foreach ($case in $cases) {
        $matching = @($csvRows | Where-Object { $_.Name -ceq $case.Name })
        if ($matching.Count -ne 1) { $problems.Add("$($matching.Count) rows named $($case.Name)"); continue }
        Compare-DecodedRow -Row $matching[0] -Case $case -Problems $problems
    }
    Add-Result "every value in the CSV, decoded" $problems -Info "$($csvRows.Count) rows"

    # The key's last-write time: one value for all rows, UTC round-trip
    # text, at the time the test wrote the values
    $problems = New-Object System.Collections.Generic.List[string]
    $times = @($csvRows | ForEach-Object { $_.KeyLastWriteUtc } | Sort-Object -Unique)
    if ($times.Count -ne 1) {
        $problems.Add("$($times.Count) different KeyLastWriteUtc values: $($times -join ', ')")
    } elseif ($times[0] -notmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z$') {
        $problems.Add("KeyLastWriteUtc '$($times[0])' is not UTC round-trip text")
    } else {
        $keyTime = [DateTime]::ParseExact($times[0], "o", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $seconds = ($keyTime - $writtenUtc).TotalSeconds
        if ($seconds -gt 5 -or $seconds -lt -60) { $problems.Add("KeyLastWriteUtc $($times[0]) is $([math]::Round($seconds)) s from when the values were written") }
    }
    Add-Result "KeyLastWriteUtc of the key" $problems -Info "$($times -join ', ')"

    # mounted_devices.txt: each row, each value whole on one line (Out-File
    # in Windows PowerShell wraps at the console width), nothing cut
    $problems = New-Object System.Collections.Generic.List[string]
    $txtLines = @()
    if (Test-Path -LiteralPath $txtPath) { $txtLines = @(Get-Content -LiteralPath $txtPath -Encoding UTF8) } else { $problems.Add("no mounted_devices.txt") }
    $kindLines = @($txtLines | Where-Object { $_ -match '^Kind\s+: ' })
    if ($kindLines.Count -ne $cases.Count) { $problems.Add("$($kindLines.Count) rows, expected $($cases.Count)") }
    foreach ($case in $cases) {
        foreach ($field in @("Name", "PartitionGuid", "DevicePath", "HexData")) {
            $value = $case.Expected[$field]
            if (-not $value) { continue }
            $line = '^' + $field + '\s+: ' + [regex]::Escape($value) + '$'
            if (@($txtLines | Where-Object { $_ -cmatch $line }).Count -eq 0) { $problems.Add("$($case.What): no line '$field : $value'") }
        }
    }
    $cut = @($txtLines | Where-Object { $_.Contains("...") -or $_.Contains([string][char]0x2026) })
    if ($cut.Count -gt 0) { $problems.Add("cut: $($cut[0])") }
    Add-Result "mounted_devices.txt complete" $problems -Info "longest line $(($txtLines | Measure-Object -Property Length -Maximum).Maximum) characters"

    $problems = New-Object System.Collections.Generic.List[string]
    foreach ($expect in @(
            @{ Source = "(command: Mounted devices (decoded))"; Rel = "USB\mounted_devices.csv" },
            @{ Source = "(command: Mounted devices)"; Rel = "USB\mounted_devices.txt" })) {
        $rows = @(Get-ManifestRows $expect.Source)
        if ($rows.Count -ne 1) { $problems.Add("$($rows.Count) manifest row(s) for $($expect.Source)") }
        elseif ($rows[0].RelativePath -ne $expect.Rel) { $problems.Add("$($expect.Source) recorded as $($rows[0].RelativePath)") }
    }
    if (($script:fileCount - $filesBefore) -ne 2) { $problems.Add("file count went up by $($script:fileCount - $filesBefore), expected 2") }
    if ($script:errorCount -ne $errorsBefore) { $problems.Add("error count went up by $($script:errorCount - $errorsBefore)") }
    Add-Result "both files in the manifest, no error" $problems

    $problems = New-Object System.Collections.Generic.List[string]
    $countLine = '\] OK: Collected 11 mounted device value\(s\): 1 GPT, 2 MBR, 3 DevicePath, 5 Other\.$'
    if ($logNew.Count -ne 1 -or $logNew[0] -notmatch $countLine) { $problems.Add("log: $($logNew -join ' | ')") }
    Add-Result "one log line, count of each kind" $problems

    # --- 3. A key that does not exist ---
    $problems = New-Object System.Collections.Generic.List[string]
    $logBefore = Get-LogLines
    $errorsBefore = $script:errorCount
    Invoke-Collector { Save-TriageMountedDevices -UsbDir $missingUsbDir -Hive "HKU" -KeyPath "$userSid\$testKeyPath\Missing" }
    $logNew = @(Get-LogLines | Select-Object -Skip $logBefore.Count)
    $missingCsv = Join-Path $missingUsbDir "mounted_devices.csv"
    $missingLines = @()
    if (Test-Path -LiteralPath $missingCsv) { $missingLines = @(Get-Content -LiteralPath $missingCsv -Encoding UTF8) }
    if ($missingLines.Count -ne 1 -or $missingLines[0] -cne $expectedHeader) { $problems.Add("CSV: $($missingLines -join ' | ')") }
    if (-not (Test-Path -LiteralPath (Join-Path $missingUsbDir "mounted_devices.txt"))) { $problems.Add("no mounted_devices.txt") }
    if ($logNew.Count -ne 1 -or $logNew[0] -notmatch '\] WARNING: No mounted devices found \(.+ missing, empty or not readable\)\.$') { $problems.Add("log: $($logNew -join ' | ')") }
    if ($script:errorCount -ne $errorsBefore) { $problems.Add("error count went up by $($script:errorCount - $errorsBefore)") }
    Add-Result "missing key: header only, a warning" $problems

    # --- 4. $FormatEnumerationLimit: the collector's statements before its
    # main try block (the one whose finally block runs the cleanup) and in
    # that finally block, run in a child scope as when the script is
    # started from an open PowerShell window ---
    $mainTry = @($ast.EndBlock.Statements | Where-Object {
            $_ -is [System.Management.Automation.Language.TryStatementAst] -and $_.Finally -and $_.Finally.Extent.Text -match 'Invoke-CollectionCleanup' })
    $limitStatements = @($ast.FindAll({ param($node)
                $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Extent.Text -match 'FormatEnumerationLimit' }, $true) |
        Where-Object { -not (Test-InsideFunction $_) })
    $setText = ""
    $restoreText = ""
    if ($mainTry.Count -eq 1) {
        $setText = (@($limitStatements | Where-Object { $_.Extent.EndOffset -le $mainTry[0].Extent.StartOffset }) |
            ForEach-Object { $_.Extent.Text }) -join "`r`n"
        $finallyExtent = $mainTry[0].Finally.Extent
        $restoreText = (@($limitStatements | Where-Object { $_.Extent.StartOffset -ge $finallyExtent.StartOffset -and $_.Extent.EndOffset -le $finallyExtent.EndOffset }) |
            ForEach-Object { $_.Extent.Text }) -join "`r`n"
    }
    # Seven items, as in a HardwareID list; 3 is not the default, so a
    # restore that writes a fixed 4 is caught
    $listItems = @(1..7 | ForEach-Object { "USBSTOR\DiskTriage_Test_Item$_" })
    $listCommand = { [PSCustomObject]@{ HardwareID = $listItems } | Format-List }
    function Get-ListItemCount {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { return -1 }
        $content = [System.IO.File]::ReadAllText($Path)
        return @($listItems | Where-Object { $content.Contains($_) }).Count
    }
    Set-GlobalEnumerationLimit 3

    $problems = New-Object System.Collections.Generic.List[string]
    $controlPath = Join-Path $workDir "list_control.txt"
    & { Invoke-Collector { Save-CommandOutput -Description "list control" -DestPath $controlPath -Command $listCommand } }
    $controlCount = Get-ListItemCount $controlPath
    if ($controlCount -ne 3) { $problems.Add("$controlCount of 7 items written at limit 3") }
    Add-Result "control: list cut at the global limit" $problems -Info "$controlCount of 7 items"

    $problems = New-Object System.Collections.Generic.List[string]
    $limitPath = Join-Path $workDir "list_collector.txt"
    $limitInRun = $null
    if ($mainTry.Count -ne 1) { $problems.Add("$($mainTry.Count) top-level try blocks with Invoke-CollectionCleanup in finally") }
    elseif (-not $setText) { $problems.Add("no FormatEnumerationLimit assignment before the main try block") }
    elseif (-not $restoreText) { $problems.Add("no FormatEnumerationLimit assignment in the main finally block") }
    else {
        & {
            . ([scriptblock]::Create($setText))
            $script:limitInRun = Get-GlobalEnumerationLimit
            Invoke-Collector { Save-CommandOutput -Description "list collector" -DestPath $limitPath -Command $listCommand }
            . ([scriptblock]::Create($restoreText))
        }
        $limitCount = Get-ListItemCount $limitPath
        if ($limitCount -ne 7) { $problems.Add("$limitCount of 7 items written during the run (limit $limitInRun)") }
    }
    Add-Result "collector lifts the limit (child scope)" $problems -Info "limit during the run: $limitInRun"

    $problems = New-Object System.Collections.Generic.List[string]
    if (-not $setText -or -not $restoreText) { $problems.Add("statements not found") }
    elseif ((Get-GlobalEnumerationLimit) -ne 3) { $problems.Add("limit after the finally block is '$(Get-GlobalEnumerationLimit)', expected 3") }
    Add-Result "collector restores the old limit" $problems
}
catch {
    $failures++
    Write-Host "FAIL: test setup or run error: $($_.Exception.Message)" -ForegroundColor Red
    if (Test-Path -LiteralPath $logFile) { Get-Content -LiteralPath $logFile | ForEach-Object { Write-Host "  | $_" } }
}
finally {
    Set-GlobalEnumerationLimit $savedLimit
    if ($testKey) { $testKey.Close() }
    try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testKeyPath, $false) } catch { Write-Host "Could not delete HKCU\$testKeyPath -- $($_.Exception.Message)" -ForegroundColor Yellow }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
foreach ($r in $results) {
    $color = if ($r.Result -eq "PASS") { "Green" } else { "Red" }
    $line = "  {0}  {1}" -f $r.Result, $r.Case
    if ($r.Note) { $line = "  {0}  {1,-44} -- {2}" -f $r.Result, $r.Case, $r.Note }
    Write-Host $line -ForegroundColor $color
    if ($r.Result -ne "PASS" -and $env:GITHUB_ACTIONS) {
        Write-Host "::error file=tests/Test-MountedDevices.ps1::$($r.Case): $($r.Note)"
    }
}
if ($failures -gt 0 -or $results.Count -eq 0) {
    Write-Host "FAIL: $failures check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: $($results.Count) check(s)" -ForegroundColor Green
exit 0

# =============================================================
# Windows Forensic Triage Collection Script
# Lightweight, dependency-free alternative to KAPE
# Use Run-TriageCollector.bat to launch (handles elevation + policy)
# =============================================================

param(
    [string]$OutputPath = "",
    [switch]$SkipLargeFiles,
    [switch]$NoCompress,
    [ValidatePattern('^[A-Za-z]$')]
    [string]$TargetDrive = "",
    [ValidateSet("Memory","FileSystem","Registry","EventLogs","Execution","Network","UserActivity","Browser","USB","Persistence","AntiVirus")]
    [string[]]$Categories = @("FileSystem","Registry","EventLogs","Execution","Network","UserActivity","Browser","USB","Persistence","AntiVirus")
)

# --- Require Administrator ---
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "  Option 1: Double-click Run-TriageCollector.bat (recommended)" -ForegroundColor Yellow
    Write-Host "  Option 2: powershell -ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`"" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

$ErrorActionPreference = "Continue"
$script:startTime = Get-Date
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"

# --- Helper: detect Windows installation root on a drive ---
# Handles both direct (G:\Windows\System32) and nested triage formats
# (G:\C\Windows\System32, G:\disk1\Windows\System32, etc.)
function Find-WindowsRoot {
    param([string]$DrivePath)

    # Check direct root first
    if (Test-Path "${DrivePath}Windows\System32") {
        return $DrivePath
    }

    # Check one level of subfolders (triage image formats: G:\C\, G:\disk1\, etc.)
    $subDirs = Get-ChildItem -Path $DrivePath -Directory -ErrorAction SilentlyContinue | Select-Object -First 20
    foreach ($sub in $subDirs) {
        if (Test-Path (Join-Path $sub.FullName "Windows\System32")) {
            return "$($sub.FullName)\"
        }
    }

    return $null
}

# --- Resolve target drive: interactive menu if not specified ---
if (-not $TargetDrive) {
    # Detect available drives that look like Windows volumes
    $systemDriveLetter = ($env:SystemDrive)[0]
    $availableDrives = @()

    # Always offer the live system drive first
    $availableDrives += [PSCustomObject]@{
        Letter   = $systemDriveLetter
        Label    = "Live system -- $env:SystemDrive (this machine)"
        IsLive   = $true
        WinRoot  = "$env:SystemDrive\"
    }

    # Find other drives that contain a Windows installation (mounted images)
    $otherDrives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Where-Object { $_.Name.Length -eq 1 -and $_.Name -ne $systemDriveLetter -and $_.Root } |
        Sort-Object Name
    foreach ($drv in $otherDrives) {
        $drvRoot = "$($drv.Name):\"
        $winRoot = Find-WindowsRoot -DrivePath $drvRoot
        if ($winRoot) {
            $volLabel = ""
            try {
                $vol = Get-Volume -DriveLetter $drv.Name -ErrorAction SilentlyContinue
                if ($vol.FileSystemLabel) { $volLabel = " ($($vol.FileSystemLabel))" }
            } catch { Write-Verbose "Reading volume label of drive $($drv.Name): $($_.Exception.Message)" }
            $sizeGB = [math]::Round($drv.Used / 1GB + $drv.Free / 1GB, 0)
            $nestedNote = ""
            if ($winRoot -ne $drvRoot) {
                $nestedNote = " [nested: $winRoot]"
            }
            $availableDrives += [PSCustomObject]@{
                Letter   = $drv.Name
                Label    = "Mounted image -- $($drv.Name):$volLabel (~${sizeGB} GB)$nestedNote"
                IsLive   = $false
                WinRoot  = $winRoot
            }
        }
    }

    if ($availableDrives.Count -eq 1) {
        # Only the live system drive available -- use it without prompting
        $TargetDrive = $systemDriveLetter
        $script:TargetRootOverride = $null
    } else {
        # Multiple options -- let the user choose
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  Select Target Drive" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""

        for ($i = 0; $i -lt $availableDrives.Count; $i++) {
            $drv = $availableDrives[$i]
            if ($drv.IsLive) {
                Write-Host "  [$($i + 1)] $($drv.Label)" -ForegroundColor Green
                Write-Host "       Full collection: registry, event logs, network, processes, etc." -ForegroundColor DarkGray
            } else {
                Write-Host "  [$($i + 1)] $($drv.Label)" -ForegroundColor White
                Write-Host "       File-copy only: hives, .evtx, prefetch, browser, user artifacts" -ForegroundColor DarkGray
                Write-Host "       (network, live registry, WMI, Defender queries skipped)" -ForegroundColor DarkGray
            }
        }

        Write-Host ""
        Write-Host "  [0] Cancel" -ForegroundColor DarkGray
        Write-Host ""

        do {
            $selection = Read-Host "Select a drive (1-$($availableDrives.Count))"
            if ($selection -eq "0") {
                Write-Host "Cancelled." -ForegroundColor Yellow
                exit 0
            }
        } while (-not ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $availableDrives.Count))

        $selectedDrive = $availableDrives[[int]$selection - 1]
        $TargetDrive = $selectedDrive.Letter
        $script:TargetRootOverride = $selectedDrive.WinRoot
        Write-Host ""
        Write-Host "Selected: $($selectedDrive.Label)" -ForegroundColor Cyan
        Write-Host ""
    }
}
$TargetDrive = $TargetDrive.ToUpper()

# Resolve TargetRoot -- use override from menu if available, otherwise auto-detect
if ($script:TargetRootOverride) {
    $script:TargetRoot = $script:TargetRootOverride
} else {
    $drvRoot = "${TargetDrive}:\"
    $winRoot = Find-WindowsRoot -DrivePath $drvRoot
    if ($winRoot) {
        $script:TargetRoot = $winRoot
    } else {
        $script:TargetRoot = $drvRoot
    }
}
$script:IsLive = ("${TargetDrive}:" -eq $env:SystemDrive)

# Validate target drive
if (-not (Test-Path $script:TargetRoot)) {
    Write-Host "ERROR: Drive ${TargetDrive}: does not exist or is not accessible." -ForegroundColor Red
    pause
    exit 1
}
if (-not (Test-Path "${script:TargetRoot}Windows\System32")) {
    Write-Host "WARNING: ${script:TargetRoot} does not appear to contain a Windows installation." -ForegroundColor Yellow
    Write-Host "  Expected to find ${script:TargetRoot}Windows\System32" -ForegroundColor Yellow
    Write-Host "  Collection will proceed but may find few artifacts." -ForegroundColor Yellow
}

# --- Optional tools directory ---
$script:ToolsDir = Join-Path $PSScriptRoot "tools"

# --- Memory capture tool (user-provided, in tools\) ---
# Machine type of this OS (PE header values): 0x8664 x64, 0xAA64 ARM64, 0x14C x86
function Get-NativeMachineType {
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        "AMD64" { return 0x8664 }
        "ARM64" { return 0xAA64 }
        "x86"   { return 0x14C }
        default { return 0 }
    }
}

# Machine type from an executable's PE header, or 0 if it can't be read
function Get-PeMachineType {
    param([string]$Path)
    try {
        $bytes = New-Object byte[] 4096
        $stream = [System.IO.File]::OpenRead($Path)
        try { $read = $stream.Read($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
        if ($read -lt 0x40) { return 0 }
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        if ($peOffset -lt 0 -or $peOffset + 6 -gt $read) { return 0 }
        return [int][BitConverter]::ToUInt16($bytes, $peOffset + 4)
    }
    catch {
        Write-Verbose "Could not read PE header of ${Path}: $($_.Exception.Message)"
        return 0
    }
}

# First usable capture tool in tools\, preferring DumpIt (native x86, x64 and
# ARM64 builds, extracted as tools\dumpit\<x86|x64|ARM64>\DumpIt.exe). A
# capture tool loads a kernel driver, so on ARM64 Windows only ARM64 builds
# can work (x64 drivers do not load there); other builds are skipped and
# listed in $script:skippedMemTools.
function Find-MemoryCaptureTool {
    $native = Get-NativeMachineType
    $archFolder = switch ($native) { 0x8664 { "x64" } 0xAA64 { "ARM64" } 0x14C { "x86" } default { "" } }
    $candidates = @(
        @{ Name = "DumpIt";    Paths = @("dumpit\$archFolder\DumpIt.exe", "dumpit\DumpIt.exe", "DumpIt.exe") },
        @{ Name = "WinPmem";   Paths = @("winpmem\winpmem.exe", "winpmem.exe") },
        @{ Name = "MagnetRAM"; Paths = @("magnetram\MagnetRAMCapture.exe", "MagnetRAMCapture.exe") }
    )
    $script:skippedMemTools = @()
    foreach ($tool in $candidates) {
        foreach ($relPath in $tool.Paths) {
            $toolPath = Join-Path $script:ToolsDir $relPath
            if (-not [System.IO.File]::Exists($toolPath)) { continue }
            if ($native -eq 0xAA64 -and (Get-PeMachineType $toolPath) -ne 0xAA64) {
                $script:skippedMemTools += "$($tool.Name) (tools\$relPath) is not an ARM64 build"
                continue
            }
            return [PSCustomObject]@{ Name = $tool.Name; Path = $toolPath; RelPath = "tools\$relPath" }
        }
    }
    return $null
}

# --- Interactive memory capture prompt ---
# Only show if: live system, Memory not already in Categories, and a tool exists
if ($script:IsLive -and ($Categories -notcontains "Memory")) {
    $memCaptureTool = Find-MemoryCaptureTool
    foreach ($skipped in $script:skippedMemTools) {
        Write-Host "Memory capture: $skipped -- skipped (this is an ARM64 machine)." -ForegroundColor DarkGray
    }

    if ($memCaptureTool) {
        $memToolInfo = "$($memCaptureTool.Name) ($($memCaptureTool.RelPath))"
        $ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 0)
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  Memory Capture" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Memory capture tool found: $memToolInfo" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Captures a full RAM dump (~$ramGB GB on this system)." -ForegroundColor White
        Write-Host "  Runs FIRST to preserve pristine memory state." -ForegroundColor DarkGray
        Write-Host "  Requires ~$ramGB GB free disk space on the output drive." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  [1] Yes -- capture memory (recommended for incident response)" -ForegroundColor Green
        Write-Host "  [2] No  -- skip memory, collect artifacts only" -ForegroundColor White
        Write-Host ""

        do {
            $memChoice = Read-Host "Include memory capture? (1-2)"
        } while ($memChoice -notin @("1", "2"))

        if ($memChoice -eq "1") {
            $Categories = @("Memory") + $Categories
            Write-Host ""
            Write-Host "Memory capture enabled. Will run first." -ForegroundColor Cyan
            Write-Host ""
        } else {
            Write-Host ""
            Write-Host "Memory capture skipped." -ForegroundColor DarkGray
            Write-Host ""
        }
    }
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "reports\TriageCollection_$timestamp"
}
# Use an absolute path: .NET file APIs resolve relative paths against the
# process directory, not the PowerShell location
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

# Create output directory structure
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$logFile = Join-Path $OutputPath "collection_log.txt"
$manifestFile = Join-Path $OutputPath "collection_manifest.csv"

# Initialize manifest CSV (see Record-Manifest for the columns after CollectedAt).
# UTF-8 with BOM on both 5.1 and 7, so Import-Csv in 5.1 reads it as UTF-8.
[System.IO.File]::WriteAllText($manifestFile, "SHA256,SourcePath,DestPath,SizeBytes,CollectedAt,RelativePath,SourceCreatedUtc,SourceModifiedUtc,SourceAccessedUtc`r`n", (New-Object System.Text.UTF8Encoding($true)))

# ----------------------------------------------------------
# Defender Exclusion: add a temporary exclusion for the output
# path so collecting SAM/SECURITY hives doesn't trigger the
# Trojan:Win32/SAMDumpz detection. Added as the first step of
# the collection try block (below the helpers) and removed in
# its finally block, so it is also removed on errors/Ctrl+C.
# ----------------------------------------------------------
$script:defenderExclusionAdded = $false

function Remove-DefenderExclusion {
    # Returns $true if the exclusion was removed (or none was added)
    if ($script:defenderExclusionAdded) {
        try {
            Remove-MpPreference -ExclusionPath $OutputPath -ErrorAction Stop
        } catch {
            return $false
        }
        $script:defenderExclusionAdded = $false
    }
    return $true
}

# ----------------------------------------------------------
# Logging
# ----------------------------------------------------------
$script:logToFile = $true

function Log {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry
    if ($script:logToFile) { Add-Content -LiteralPath $logFile -Value $entry -ErrorAction SilentlyContinue }
}

function Log-Warning {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] WARNING: $Message"
    Write-Host $entry -ForegroundColor Yellow
    if ($script:logToFile) { Add-Content -LiteralPath $logFile -Value $entry -ErrorAction SilentlyContinue }
}

function Log-Error {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ERROR: $Message"
    Write-Host $entry -ForegroundColor Red
    if ($script:logToFile) { Add-Content -LiteralPath $logFile -Value $entry -ErrorAction SilentlyContinue }
}

function Log-Success {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] OK: $Message"
    Write-Host $entry -ForegroundColor Green
    if ($script:logToFile) { Add-Content -LiteralPath $logFile -Value $entry -ErrorAction SilentlyContinue }
}

# ----------------------------------------------------------
# Helper: Ensure directory exists
# ----------------------------------------------------------
function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

# ----------------------------------------------------------
# Helpers: file size, original file times, manifest fields
# ----------------------------------------------------------
# Size of a file in bytes, or -1 if it does not exist. Uses FileInfo, which
# sees hidden/system files (Get-Item without -Force does not) and does not
# treat [ ] in the path as wildcards.
function Get-FileLength {
    param([string]$Path)
    try {
        $fi = New-Object System.IO.FileInfo($Path)
        if ($fi.Exists) { return $fi.Length }
    } catch { Write-Verbose "Reading file size of ${Path}: $($_.Exception.Message)" }
    return -1
}

# Original Created/Modified/Accessed times (UTC) of a file, or $null if the
# path is not an existing file (command output, registry paths, ...).
# Read these BEFORE copying so the copy cannot change the access time.
function Get-SourceFileTimesUtc {
    param([string]$Path)
    try {
        if (-not $Path -or -not [System.IO.Path]::IsPathRooted($Path)) { return $null }
        if (-not [System.IO.File]::Exists($Path)) { return $null }
        return [PSCustomObject]@{
            Created  = [System.IO.File]::GetCreationTimeUtc($Path)
            Modified = [System.IO.File]::GetLastWriteTimeUtc($Path)
            Accessed = [System.IO.File]::GetLastAccessTimeUtc($Path)
        }
    } catch {
        return $null
    }
}

# UTC time as ISO 8601 round-trip text; blank when unknown/unset
function Format-UtcTime {
    param($Value)
    if ($null -eq $Value -or $Value -isnot [datetime]) { return "" }
    if ($Value.Year -le 1601) { return "" }
    return $Value.ToUniversalTime().ToString("o")
}

# Path relative to the collection root (no leading '\'), or "" if outside it
function Get-CollectionRelativePath {
    param([string]$Path)
    try {
        $root = [System.IO.Path]::GetFullPath($OutputPath).TrimEnd('\')
        $full = [System.IO.Path]::GetFullPath($Path)
        if ($full.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $full.Substring($root.Length + 1)
        }
    } catch { Write-Verbose "Computing collection-relative path of ${Path}: $($_.Exception.Message)" }
    return ""
}

# One CSV field, always quoted, embedded quotes doubled (same as Export-Csv)
function ConvertTo-CsvField {
    param($Value)
    if ($null -eq $Value) { $Value = "" }
    return '"' + ([string]$Value).Replace('"', '""') + '"'
}

# Relative path of a file under TargetRoot (for shadow copy access), or ""
function Get-TargetRelativePath {
    param([string]$Path)
    if ($Path -and $script:TargetRoot -and $Path.StartsWith($script:TargetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Path.Substring($script:TargetRoot.Length).TrimStart('\')
    }
    return ""
}

# ----------------------------------------------------------
# Helper: Copy file and record in manifest
# ----------------------------------------------------------
$script:fileCount = 0
$script:errorCount = 0
$script:totalBytes = 0

function Copy-ForensicFile {
    [OutputType([void])]
    param(
        [string]$SourcePath,
        [string]$DestDir,
        [string]$DestName = ""
    )

    # -LiteralPath: paths can contain [ ], which -Path treats as wildcards
    if (-not $SourcePath -or -not (Test-Path -LiteralPath $SourcePath)) {
        return
    }

    try {
        Ensure-Directory $DestDir

        if (-not $DestName) {
            $DestName = [System.IO.Path]::GetFileName($SourcePath)
        }
        $destPath = Join-Path $DestDir $DestName

        # Keep destination paths under MAX_PATH: Windows PowerShell 5.1 cannot
        # create longer ones. Long names (e.g. Recent .lnk files named after web
        # searches) are shortened with a hash suffix; the full original path is
        # kept in the manifest's SourcePath column. Names are also capped at
        # 100 characters so the zip still extracts under a deeper folder
        # (the timeline builder extracts into %TEMP%).
        if ($DestName.Length -gt 100 -or $destPath.Length -gt 250) {
            $ext = [System.IO.Path]::GetExtension($DestName)
            $sha1 = New-Object System.Security.Cryptography.SHA1Managed
            $nameHash = [System.BitConverter]::ToString($sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($DestName))).Replace("-", "").Substring(0, 8)
            $keep = [Math]::Min(100 - $ext.Length - 9, 250 - $DestDir.TrimEnd('\').Length - 1 - $ext.Length - 9)
            if ($keep -lt 8) { $keep = 8 }
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($DestName)
            if ($baseName.Length -gt $keep) { $baseName = $baseName.Substring(0, $keep) }
            $DestName = "$baseName~$nameHash$ext"
            $destPath = Join-Path $DestDir $DestName
        }

        # Original file times, read before the copy can update the access time
        $srcTimes = Get-SourceFileTimesUtc $SourcePath
    } catch {
        Log-Warning "Could not copy: $SourcePath -- $($_.Exception.Message)"
        $script:errorCount++
        return
    }

    $copyError = $null
    try {
        # Try direct copy first (also reads hidden/system files)
        [System.IO.File]::Copy($SourcePath, $destPath, $true)
        Record-Manifest -SourcePath $SourcePath -DestPath $destPath -SourceTimes $srcTimes
        return
    } catch {
        $copyError = $_.Exception
        while ($copyError.InnerException -and $copyError -is [System.Management.Automation.MethodInvocationException]) {
            $copyError = $copyError.InnerException
        }
    }

    # Try standard Copy-Item as fallback
    try {
        Copy-Item -LiteralPath $SourcePath -Destination $destPath -Force -ErrorAction Stop
        Record-Manifest -SourcePath $SourcePath -DestPath $destPath -SourceTimes $srcTimes
        return
    } catch { Write-Verbose "Copy-Item fallback for ${SourcePath}: $($_.Exception.Message)" }

    # File is in use (sharing/lock violation) on a live system, e.g. a browser
    # database: read it from the Volume Shadow Copy instead
    $inUse = $copyError -and (($copyError.HResult -eq -2147024864) -or ($copyError.HResult -eq -2147024863))
    if ($script:IsLive -and $inUse) {
        $relPath = Get-TargetRelativePath $SourcePath
        if ($relPath) {
            if (Copy-FromShadow -RelativePath $relPath -DestDir $DestDir -DestName $DestName -Quiet) {
                Log "Collected from shadow copy (file in use): $SourcePath"
                return
            }
            Log-Warning "Could not copy (locked, shadow copy also failed): $SourcePath"
            $script:errorCount++
            return
        }
    }

    $reason = "unknown error"
    if ($copyError) { $reason = $copyError.Message }
    if ($inUse) {
        Log-Warning "Could not copy (locked): $SourcePath"
    } else {
        Log-Warning "Could not copy: $SourcePath -- $reason"
    }
    $script:errorCount++
}

# Manifest columns:
#   SHA256, SourcePath, DestPath, SizeBytes, CollectedAt (collector local time),
#   RelativePath (DestPath relative to the collection root),
#   SourceCreatedUtc, SourceModifiedUtc, SourceAccessedUtc (ISO 8601 UTC times
#   of the ORIGINAL file; blank for command output, reg save and unknown).
# -SourceTimes: times captured before the copy (object with Created/Modified/
# Accessed); when not passed they are read from SourcePath if it is a file.
function Record-Manifest {
    param(
        [string]$SourcePath,
        [string]$DestPath,
        [object]$SourceTimes = $null
    )
    try {
        # FileInfo sees hidden/system files; Get-Item without -Force returned
        # nothing for them and the copy was deleted as "empty"
        $fileSize = Get-FileLength $DestPath
        if ($fileSize -lt 0) { return }
        if ($fileSize -eq 0) {
            # Remove empty files (failed copies that produced 0-byte output)
            Remove-Item -LiteralPath $DestPath -Force -ErrorAction SilentlyContinue
            return
        }

        if (-not $PSBoundParameters.ContainsKey('SourceTimes')) {
            $SourceTimes = Get-SourceFileTimesUtc $SourcePath
        }
        $created = ""; $modified = ""; $accessed = ""
        if ($SourceTimes) {
            $created  = Format-UtcTime $SourceTimes.Created
            $modified = Format-UtcTime $SourceTimes.Modified
            $accessed = Format-UtcTime $SourceTimes.Accessed
        }

        $hash = (Get-FileHash -LiteralPath $DestPath -Algorithm SHA256 -ErrorAction Stop).Hash
        $fields = @(
            $hash,
            $SourcePath,
            $DestPath,
            $fileSize,
            (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
            (Get-CollectionRelativePath $DestPath),
            $created,
            $modified,
            $accessed
        )
        $line = ($fields | ForEach-Object { ConvertTo-CsvField $_ }) -join ','
        # Explicit UTF-8 (the header is UTF-8); Add-Content in 5.1 writes ANSI
        [System.IO.File]::AppendAllText($manifestFile, $line + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
        $script:fileCount++
        $script:totalBytes += $fileSize
    } catch {
        Log-Warning "Could not hash/record: $DestPath -- $($_.Exception.Message)"
    }
}

# ----------------------------------------------------------
# Helper: Save command output to file and record in manifest
# ----------------------------------------------------------
function Save-CommandOutput {
    [OutputType([void])]
    param(
        [string]$Description,
        [string]$DestPath,
        [scriptblock]$Command
    )
    try {
        $output = & $Command 2>&1
        Ensure-Directory (Split-Path $DestPath -Parent)
        $output | Out-File -LiteralPath $DestPath -Encoding utf8 -Force
        Record-Manifest -SourcePath "(command: $Description)" -DestPath $DestPath
    } catch {
        Log-Error "Failed to collect $Description -- $($_.Exception.Message)"
        $script:errorCount++
    }
}

# ----------------------------------------------------------
# Helper: Volume Shadow Copy for locked files
# ----------------------------------------------------------
$script:shadowId = $null
$script:shadowPath = $null
$script:shadowUnavailable = $false

function Initialize-ShadowCopy {
    if ($script:shadowPath) { return $true }
    # Do not retry (and re-log) on every call after a failure / in image mode
    if ($script:shadowUnavailable) { return $false }
    if (-not $script:IsLive) {
        Log "Skipping shadow copy (mounted image mode -- files are not locked)"
        $script:shadowUnavailable = $true
        return $false
    }

    Log "Creating Volume Shadow Copy for locked file access..."
    try {
        $shadow = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{ Volume = $script:TargetRoot; Context = "ClientAccessible" } -ErrorAction Stop
        if ($shadow.ReturnValue -eq 0) {
            # Remember the ID first so cleanup can delete it even if the lookup below fails
            $script:shadowId = $shadow.ShadowID
            $shadowObj = Get-CimInstance -ClassName Win32_ShadowCopy -Filter "ID='$($script:shadowId)'"
            $script:shadowPath = $shadowObj.DeviceObject
            if (-not $script:shadowPath) {
                Log-Warning "Shadow copy created but its device path could not be read."
                $script:shadowUnavailable = $true
                return $false
            }
            Log-Success "Shadow copy created: $($script:shadowPath)"
            return $true
        } else {
            Log-Warning "Shadow copy creation returned code: $($shadow.ReturnValue)"
            $script:shadowUnavailable = $true
            return $false
        }
    } catch {
        Log-Warning "Could not create shadow copy: $($_.Exception.Message)"
        Log-Warning "Locked files (registry hives, browser databases) may be incomplete."
        $script:shadowUnavailable = $true
        return $false
    }
}

# Copy a file (path relative to TargetRoot) out of the shadow copy.
# -Quiet: the caller reports failures (no warning / error count here).
function Copy-FromShadow {
    param(
        [string]$RelativePath,
        [string]$DestDir,
        [string]$DestName = "",
        [switch]$Quiet
    )

    if (-not $script:shadowPath) {
        if (-not (Initialize-ShadowCopy)) {
            return $false
        }
    }

    $shadowFile = "$($script:shadowPath)\$RelativePath"
    if (-not $DestName) {
        $DestName = [System.IO.Path]::GetFileName($RelativePath)
    }
    $destPath = Join-Path $DestDir $DestName

    try {
        Ensure-Directory $DestDir

        # Original file times: from the snapshot itself, else from the live file
        $srcTimes = Get-SourceFileTimesUtc $shadowFile
        if (-not $srcTimes) {
            $srcTimes = Get-SourceFileTimesUtc ($script:TargetRoot.TrimEnd('\') + '\' + $RelativePath)
        }

        # .NET copy accepts the \\?\GLOBALROOT\Device\... shadow path and reads
        # hidden/system files (NTUSER.DAT, UsrClass.dat, hive .LOG1/.LOG2),
        # which "cmd /c copy" reports as not found. cmd copy stays as fallback.
        $notFound = $false
        try {
            [System.IO.File]::Copy($shadowFile, $destPath, $true)
        } catch {
            $copyError = $_.Exception
            if ($copyError.InnerException) { $copyError = $copyError.InnerException }
            if ($copyError -is [System.IO.FileNotFoundException] -or $copyError -is [System.IO.DirectoryNotFoundException]) {
                $notFound = $true
            } else {
                $null = cmd /c "copy /Y `"$shadowFile`" `"$destPath`"" 2>&1
            }
        }

        if ((Get-FileLength $destPath) -gt 0) {
            Record-Manifest -SourcePath "(shadow)$RelativePath" -DestPath $destPath -SourceTimes $srcTimes
            return $true
        }

        # Remove empty/corrupt shadow copy output
        if ((Get-FileLength $destPath) -ge 0) {
            Remove-Item -LiteralPath $destPath -Force -ErrorAction SilentlyContinue
        }
        if (-not $Quiet) {
            if ($notFound) {
                Log "Not present in shadow copy: $RelativePath"
            } else {
                Log-Warning "Shadow copy of $RelativePath did not produce output file"
                $script:errorCount++
            }
        }
        return $false
    } catch {
        if (-not $Quiet) {
            Log-Warning "Could not copy from shadow: $RelativePath -- $($_.Exception.Message)"
            $script:errorCount++
        }
        return $false
    }
}

function Remove-ShadowCopy {
    if ($script:shadowId) {
        Log "Removing shadow copy..."
        try {
            $shadowObj = Get-CimInstance -ClassName Win32_ShadowCopy -Filter "ID='$($script:shadowId)'" -ErrorAction Stop
            if ($shadowObj) {
                Remove-CimInstance -InputObject $shadowObj -ErrorAction Stop
                Log-Success "Shadow copy removed."
            }
        } catch {
            Log-Warning "Could not remove shadow copy: $($_.Exception.Message)"
            Log-Warning "Remove it manually: vssadmin delete shadows /shadow=$($script:shadowId)"
        }
        $script:shadowId = $null
        $script:shadowPath = $null
    }
}

# ----------------------------------------------------------
# Cleanup on every exit path (called from the finally block at
# the "Cleanup" banner): shadow copy and Defender exclusion
# ----------------------------------------------------------
$script:cleanupDone = $false
$script:collectionCompleted = $false

function Invoke-CollectionCleanup {
    if ($script:cleanupDone) { return }
    $script:cleanupDone = $true
    if (-not $script:collectionCompleted) {
        Log-Warning "Collection did not finish (interrupted or stopped by an error). Partial output: $OutputPath"
    }
    try {
        Remove-ShadowCopy
    } catch {
        Log-Warning "Could not remove shadow copy: $($_.Exception.Message)"
    }
    if ($script:defenderExclusionAdded) {
        Log "Removing temporary Defender exclusion..."
        if (Remove-DefenderExclusion) {
            Log-Success "Defender exclusion removed."
        } else {
            Log-Warning "Could not remove the temporary Defender exclusion. Remove it manually:"
            Log-Warning "  Remove-MpPreference -ExclusionPath `"$OutputPath`""
        }
    }
}

# ----------------------------------------------------------
# Helper: collection_info.json (metadata for the timeline
# builder: mode, start time, time zones, culture)
# ----------------------------------------------------------
# TimeZoneKeyName from the mounted image's SYSTEM hive, or $null.
# A temporary COPY of the hive (and its .LOG1/.LOG2) is loaded under
# HKLM: loading a hive can write to it, so the evidence file itself is
# never loaded (and read-only mounts could not be loaded at all).
function Get-ImageTimeZoneId {
    $configDir = "${script:TargetRoot}Windows\System32\config"
    $hiveSrc = Join-Path $configDir "SYSTEM"
    if (-not [System.IO.File]::Exists($hiveSrc)) { return $null }

    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("TriageTZ_" + [guid]::NewGuid().ToString("N"))
    $mountName = "TriageTZ_" + [guid]::NewGuid().ToString("N").Substring(0, 8)
    $loaded = $false
    $tzId = $null
    $current = $null
    $tzName = $null
    try {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        $hiveCopy = Join-Path $tempDir "SYSTEM"
        [System.IO.File]::Copy($hiveSrc, $hiveCopy, $true)
        foreach ($logExt in @(".LOG1", ".LOG2")) {
            if ([System.IO.File]::Exists($hiveSrc + $logExt)) {
                try { [System.IO.File]::Copy($hiveSrc + $logExt, $hiveCopy + $logExt, $true) } catch { Write-Verbose "Copying SYSTEM$logExt for the time zone lookup: $($_.Exception.Message)" }
            }
        }

        $null = reg load "HKLM\$mountName" "$hiveCopy" 2>&1
        if ($LASTEXITCODE -ne 0) { return $null }
        $loaded = $true

        # Select\Current = number of the active ControlSet00N
        $selectKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$mountName\Select")
        if ($selectKey) {
            try { $current = $selectKey.GetValue("Current") } finally { $selectKey.Close() }
        }
        if ($null -eq $current) { return $null }

        $tzPath = "{0}\ControlSet{1:D3}\Control\TimeZoneInformation" -f $mountName, [int]$current
        $tzKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($tzPath)
        if ($tzKey) {
            try { $tzName = $tzKey.GetValue("TimeZoneKeyName") } finally { $tzKey.Close() }
        }
        if ($tzName) {
            # The stored string can carry leftover characters after its NUL
            $tzName = ([string]$tzName).Split([char]0)[0].Trim()
            if ($tzName) { $tzId = $tzName }
        }
    } catch {
        $tzId = $null
    } finally {
        if ($loaded) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            $null = reg unload "HKLM\$mountName" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Start-Sleep -Seconds 1
                $null = reg unload "HKLM\$mountName" 2>&1
                if ($LASTEXITCODE -ne 0) {
                    Log-Warning "Could not unload temporary hive HKLM\$mountName -- run: reg unload HKLM\$mountName"
                }
            }
        }
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $tzId
}

# Write collection_info.json at the collection root and record it in the manifest
function Write-CollectionInfo {
    $infoPath = Join-Path $OutputPath "collection_info.json"
    try {
        $collectorTz = [System.TimeZoneInfo]::Local.Id
        if ($script:IsLive) {
            $mode = "Live"
            $targetTz = $collectorTz
        } else {
            $mode = "MountedImage"
            $targetTz = Get-ImageTimeZoneId
        }
        $info = [PSCustomObject][ordered]@{
            SchemaVersion       = 1
            ComputerName        = $env:COMPUTERNAME
            CollectorUser       = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            Mode                = $mode
            TargetDrive         = $TargetDrive
            TargetRoot          = $script:TargetRoot
            CollectionStartUtc  = $script:startTime.ToUniversalTime().ToString("o")
            CollectorTimeZoneId = $collectorTz
            CollectorCulture    = (Get-Culture).Name
            TargetTimeZoneId    = $targetTz
        }
        $json = $info | ConvertTo-Json
        # UTF-8 with BOM so Get-Content in Windows PowerShell 5.1 reads it as UTF-8
        [System.IO.File]::WriteAllText($infoPath, $json, (New-Object System.Text.UTF8Encoding($true)))
        Record-Manifest -SourcePath "(collection metadata)" -DestPath $infoPath
        if ($targetTz) {
            Log "Collection info written (target time zone: $targetTz)"
        } else {
            Log-Warning "Collection info written, but the target time zone could not be read from the image."
        }
    } catch {
        Log-Warning "Could not write collection_info.json -- $($_.Exception.Message)"
    }
}

# =============================================================
# Collection body. Everything from here down to the "Cleanup"
# banner runs inside this try block. Its finally block (at the
# Cleanup banner) removes the shadow copy and the Defender
# exclusion on every exit path: normal end, Ctrl+C, exit and
# terminating errors. The body is intentionally NOT re-indented
# so the diff stays small. (Closing the console window kills the
# process outright; that cannot be caught.)
# =============================================================
try {

# Inside a try block, a statement-terminating error (a .NET exception
# or a method call on $null outside an inner try/catch) would skip the
# whole rest of the collection. Log it and go on with the next step
# instead. Ctrl+C (PipelineStoppedException) is passed on, so the run
# stops and the finally block cleans up.
trap {
    if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { break }
    Log-Error "Unexpected error at line $($_.InvocationInfo.ScriptLineNumber) (rest of this step skipped): $($_.Exception.Message)"
    $script:errorCount++
    continue
}

# Defender exclusion (see Remove-DefenderExclusion). The flag is set
# before the call so that an interrupt while Add-MpPreference is still
# running also leads to its removal.
if ($script:IsLive) {
    $script:defenderExclusionAdded = $true
    try {
        Add-MpPreference -ExclusionPath $OutputPath -ErrorAction Stop
    } catch {
        # Warned below, with the start-of-run logging
        $script:defenderExclusionAdded = $false
    }
}

Log "=== Windows Forensic Triage Collection Started ==="
Log "Output directory: $OutputPath"
Log "Target drive: ${TargetDrive}:"
Log "Target root: $($script:TargetRoot)"
if ($script:IsLive) {
    Log "Mode: LIVE SYSTEM (full collection with live commands)"
} else {
    Log "Mode: MOUNTED IMAGE (file-copy only, live commands skipped)"
}
Log "Categories: $($Categories -join ', ')"
Log "SkipLargeFiles: $SkipLargeFiles"
if ($script:IsLive) {
    if ($script:defenderExclusionAdded) {
        Log-Success "Temporary Defender exclusion added for output path (will be removed at end)."
    } else {
        Log-Warning "Could not add Defender exclusion. SAM/SECURITY collection may be blocked."
        Log-Warning "If Defender blocks hive collection, manually add an exclusion in Windows Security"
        Log-Warning "for: $OutputPath"
    }
}
Log "Computer: $env:COMPUTERNAME (collector host)"
Log "User: $env:USERNAME"
if ($script:IsLive) {
    Log "OS: $((Get-CimInstance Win32_OperatingSystem).Caption) Build $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"
} else {
    Log "OS: (mounted image -- OS info reflects collector host, not target)"
}
Log "Time zone: $((Get-TimeZone).DisplayName)"
Write-CollectionInfo
Log ""

# =============================================================
# Collect system info snapshot
# =============================================================
if ($script:IsLive) {
    Log "--- Collecting system info snapshot ---"
    Save-CommandOutput -Description "systeminfo" `
        -DestPath (Join-Path $OutputPath "systeminfo.txt") `
        -Command { systeminfo }
} else {
    Log "--- Skipping systeminfo (mounted image -- would report collector host) ---"
}
Log ""

# =============================================================
# 0. Memory Capture (opt-in, runs first to preserve RAM state)
# =============================================================
if ($Categories -contains "Memory") {
    Log "============================================================="
    Log "  COLLECTING: Memory Dump"
    Log "============================================================="

    if (-not $script:IsLive) {
        Log "Skipping Memory capture (mounted image -- not applicable)"
    } else {
        # Detect available memory capture tool in tools\ directory
        $memCaptureTool = Find-MemoryCaptureTool
        foreach ($skipped in $script:skippedMemTools) {
            Log "Memory capture: $skipped -- skipped (this is an ARM64 machine)."
        }

        if ($memCaptureTool) {
            $memTool = $memCaptureTool.Path
            $memToolName = $memCaptureTool.Name
            $memDir = Join-Path $OutputPath "Memory"
            Ensure-Directory $memDir
            # DumpIt writes a Microsoft crash dump (.dmp: WinDbg, Volatility);
            # WinPmem and Magnet RAM Capture write a raw image
            if ($memToolName -eq "DumpIt") {
                $dumpFile = Join-Path $memDir "memory_dump.dmp"
            } else {
                $dumpFile = Join-Path $memDir "memory_dump.raw"
            }
            $memLogFile = Join-Path $memDir "memory_acquisition_log.txt"

            $ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 0)
            Log "Memory capture tool: $memToolName ($memTool)"
            Log "Expected dump size: ~$ramGB GB"
            Log "Capturing memory -- this may take several minutes..."

            try {
                switch ($memToolName) {
                    "WinPmem" {
                        $result = & $memTool acquire $dumpFile 2>&1
                    }
                    "DumpIt" {
                        # Uncompressed crash dump, no prompts (DumpIt may
                        # otherwise compress automatically)
                        $result = & $memTool /TYPE DMP /NOCOMPRESS /QUIET /OUTPUT $dumpFile 2>&1
                    }
                    "MagnetRAM" {
                        $result = & $memTool /accepteula /go /output $dumpFile 2>&1
                    }
                }

                # Save tool output as acquisition log
                $result | Out-File $memLogFile -Encoding utf8

                if ((Get-FileLength $dumpFile) -gt 0) {
                    $dumpSizeGB = [math]::Round((Get-FileLength $dumpFile) / 1GB, 2)
                    Record-Manifest -SourcePath "(memory dump via $memToolName)" -DestPath $dumpFile
                    Log-Success "Memory dump captured: $dumpFile ($dumpSizeGB GB)"
                } else {
                    Log-Warning "Memory dump failed or produced empty file."
                    Log-Warning "Check acquisition log: $memLogFile"
                }
            }
            catch {
                Log-Error "Memory capture failed: $($_.Exception.Message)"
                $script:errorCount++
            }
        } else {
            Log-Warning "Memory capture: no tool found in tools\ directory. Skipping."
            Log ""
            Log "  To enable memory capture (see tools\dumpit\README.txt):"
            Log ""
            Log "       DumpIt (Magnet Forensics, free; recommended -- x86, x64 and ARM64):"
            Log "         https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/"
            Log "         Extract the download into tools\dumpit\ as-is"
            Log "         (tools\dumpit\x64\DumpIt.exe, tools\dumpit\ARM64\DumpIt.exe, ...)"
            Log ""
            Log "       WinPmem (open-source; x64 only):"
            Log "         https://github.com/Velocidex/WinPmem/releases"
            Log "         Download winpmem_mini_x64.exe, rename to winpmem.exe"
            Log "         Place in: tools\winpmem\winpmem.exe"
            Log ""
            Log "       Magnet RAM Capture (Magnet Forensics, free):"
            Log "         https://www.magnetforensics.com/resources/magnet-ram-capture/"
            Log "         Place in: tools\magnetram\MagnetRAMCapture.exe"
            Log ""
        }
    }

    Log ""
}

# ----------------------------------------------------------
# Helpers for the FileSystem section: built-in raw NTFS reader
# for $MFT, $LogFile and $UsnJrnl:$J
# ----------------------------------------------------------

# NTFS metafiles cannot be opened through the file API (not even inside a
# shadow copy), so they are read from the volume device itself: boot sector
# -> $MFT runlist -> file record of the metafile -> runs of its $DATA stream
# (following $ATTRIBUTE_LIST when the attribute is split across extension
# records). Device reads are sector-aligned; data is copied in 4 MB chunks.
# The NTFS logic works on any Stream, so it can be tested on an image file.
# C# 5 only: Windows PowerShell 5.1 compiles Add-Type code with the old
# compiler (no string interpolation, expression-bodied members, out var,
# tuples or nameof). Compiled on first use only.
$script:triageNtfsSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace TriageNtfs
{
    // One run of a non-resident attribute: Length clusters from virtual
    // cluster Vcn on, stored from logical cluster Lcn on. Lcn -1 = sparse
    // run (reads as zeros, nothing stored on disk).
    public class DataRun
    {
        public long Vcn;
        public long Lcn;
        public long Length;
    }

    // One attribute record inside an MFT record
    public class NtfsAttribute
    {
        public uint Type;
        public string Name = "";
        public ushort Id;
        public ushort Flags;
        public bool NonResident;
        public long StartVcn;
        public long LastVcn;
        public long DataSize;
        public long InitializedSize;
        public byte[] ResidentData;
        public List<DataRun> Runs = new List<DataRun>();
    }

    // An MFT (FILE) record after the update sequence fixups
    public class MftRecord
    {
        public long Number;
        public ushort Flags;
        public long BaseRecord;
        public List<NtfsAttribute> Attributes = new List<NtfsAttribute>();
    }

    // A whole stream: the runs of all its extents in VCN order, sizes from
    // the first extent (later extents of a split attribute carry no sizes)
    public class NtfsStream
    {
        public string Name = "";
        public ushort Flags;
        public bool NonResident;
        public byte[] ResidentData;
        public long DataSize;
        public long InitializedSize;
        public List<DataRun> Runs = new List<DataRun>();
    }

    internal static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(string fileName, uint desiredAccess, uint shareMode,
            IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
    }

    // Reads NTFS metadata from a seekable Stream holding a whole volume
    public sealed class NtfsReader : IDisposable
    {
        public const uint AttributeListType = 0x20;
        public const uint FileNameType = 0x30;
        public const uint DataType = 0x80;
        private const uint EndMarker = 0xFFFFFFFF;
        private const long RecordMask = 0x0000FFFFFFFFFFFFL;   // file reference -> record number
        private const ushort FlagCompressed = 0x0001;
        private const ushort FlagEncrypted = 0x4000;

        private Stream volume;
        private readonly bool ownsVolume;
        private int bytesPerSector;
        private int bytesPerCluster;
        private int recordSize;
        private long mftStartLcn;
        private NtfsStream mft;
        private int chunkSize = 4 * 1024 * 1024;

        public NtfsReader(Stream volume) : this(volume, false)
        {
        }

        public NtfsReader(Stream volume, bool ownsVolume)
        {
            if (volume == null) throw new ArgumentNullException("volume");
            this.volume = volume;
            this.ownsVolume = ownsVolume;
            ReadBootSector();
            LoadMft();
        }

        public int BytesPerSector { get { return bytesPerSector; } }
        public int BytesPerCluster { get { return bytesPerCluster; } }
        public int RecordSize { get { return recordSize; } }
        public long MftStartLcn { get { return mftStartLcn; } }
        public long MftSize { get { return mft.DataSize; } }
        public long RecordCount { get { return mft.DataSize / recordSize; } }

        // Bytes per read when copying or scanning (rounded down to whole
        // clusters / records, at least one)
        public int ChunkSize
        {
            get { return chunkSize; }
            set
            {
                if (value < 1) throw new ArgumentOutOfRangeException("value");
                chunkSize = value;
            }
        }

        // Opens a volume device such as \\.\C: read-only. Read/write/delete
        // sharing keeps the mounted file system usable meanwhile.
        public static NtfsReader OpenVolume(string devicePath)
        {
            // GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING
            SafeFileHandle handle = NativeMethods.CreateFile(devicePath, 0x80000000, 0x7, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new IOException("cannot open " + devicePath + " (" + new Win32Exception(error).Message.TrimEnd('.') + ", Win32 error " + error + ")");
            }
            FileStream stream = null;
            try
            {
                // Buffer size 1 = unbuffered: each read goes to the device with
                // the (sector-aligned) offset and length it was given
                stream = new FileStream(handle, FileAccess.Read, 1);
                return new NtfsReader(stream, true);
            }
            catch
            {
                if (stream != null) stream.Dispose(); else handle.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            if (volume != null && ownsVolume) volume.Dispose();
            volume = null;
        }

        private static bool IsPowerOfTwo(long value)
        {
            return value > 0 && (value & (value - 1)) == 0;
        }

        private void ReadBootSector()
        {
            // 4096 bytes = whole sectors on 512-byte and 4K-sector volumes
            byte[] boot = new byte[4096];
            ReadExact(0, boot, 0, boot.Length);
            if (Encoding.ASCII.GetString(boot, 3, 8) != "NTFS    ")
                throw new InvalidDataException("not an NTFS volume (no NTFS signature in the boot sector)");
            bytesPerSector = BitConverter.ToUInt16(boot, 0x0B);
            if (bytesPerSector < 256 || bytesPerSector > 4096 || !IsPowerOfTwo(bytesPerSector))
                throw new InvalidDataException("invalid bytes per sector in the boot sector: " + bytesPerSector);
            // Sectors per cluster: above 0x80 the value means 2^(256 - value)
            int spc = boot[0x0D];
            long sectorsPerCluster = spc;
            if (spc > 0x80)
            {
                if (256 - spc > 20) throw new InvalidDataException("invalid sectors per cluster in the boot sector: 0x" + spc.ToString("X2"));
                sectorsPerCluster = 1L << (256 - spc);
            }
            long clusterSize = sectorsPerCluster * bytesPerSector;
            if (!IsPowerOfTwo(clusterSize) || clusterSize > 2 * 1024 * 1024)
                throw new InvalidDataException("invalid cluster size in the boot sector: " + clusterSize);
            bytesPerCluster = (int)clusterSize;
            mftStartLcn = BitConverter.ToInt64(boot, 0x30);
            // Clusters per MFT record: a negative value n means 2^-n bytes
            int clustersPerRecord = unchecked((sbyte)boot[0x40]);
            long size = 0;
            if (clustersPerRecord > 0) size = (long)clustersPerRecord * bytesPerCluster;
            else if (clustersPerRecord > -32) size = 1L << (-clustersPerRecord);
            if (size < 256 || size > 65536 || !IsPowerOfTwo(size))
                throw new InvalidDataException("invalid MFT record size in the boot sector: " + size);
            recordSize = (int)size;
            if (mftStartLcn <= 0)
                throw new InvalidDataException("invalid $MFT cluster in the boot sector: " + mftStartLcn);
        }

        // Record 0 ($MFT itself) sits at the cluster named in the boot sector.
        // Its own $DATA extent (VCN 0) maps the start of $MFT; extension
        // records holding further extents are read through what is mapped so far.
        private void LoadMft()
        {
            byte[] buffer = new byte[recordSize];
            ReadVolume(mftStartLcn * bytesPerCluster, buffer, 0, recordSize);
            if (!ApplyFixups(buffer, 0, recordSize))
                throw new InvalidDataException("MFT record 0 (cluster " + mftStartLcn + ") has no valid FILE header or update sequence");
            MftRecord record0 = ParseRecord(buffer, 0, 0);
            NtfsAttribute first = null;
            foreach (NtfsAttribute a in record0.Attributes)
            {
                if (a.Type == DataType && a.Name.Length == 0 && a.NonResident && a.StartVcn == 0) { first = a; break; }
            }
            if (first == null) throw new InvalidDataException("MFT record 0 has no non-resident $DATA attribute");
            List<NtfsAttribute> extents = new List<NtfsAttribute>();
            extents.Add(first);
            mft = BuildStream(extents, "");
            mft = GetStream(record0, DataType, "", true);
        }

        // The whole $DATA stream (unnamed: "") of an MFT record, or null if
        // the record has no such stream
        public NtfsStream GetDataStream(long recordNumber, string streamName)
        {
            if (streamName == null) streamName = "";
            return GetStream(ReadRecord(recordNumber), DataType, streamName, false);
        }

        // Fixed-up and parsed MFT record (must be in use)
        public MftRecord ReadRecord(long number)
        {
            if (number < 0 || number >= RecordCount)
                throw new InvalidDataException("MFT record " + number + " is outside $MFT (" + RecordCount + " records)");
            byte[] buffer = new byte[recordSize];
            ReadStreamBytes(mft, number * recordSize, buffer, 0, recordSize);
            if (!ApplyFixups(buffer, 0, recordSize))
                throw new InvalidDataException("MFT record " + number + " has no valid FILE header or update sequence");
            MftRecord record = ParseRecord(buffer, 0, number);
            if ((record.Flags & 1) == 0) throw new InvalidDataException("MFT record " + number + " is not in use");
            return record;
        }

        // Number of the first in-use base record that has a $FILE_NAME called
        // name (case-insensitive) in directory parentRecord, or -1. Scans
        // $MFT from the start in chunks; unused or damaged records are skipped.
        public long FindRecordByName(long parentRecord, string name)
        {
            long total = RecordCount;
            int perChunk = Math.Max(1, chunkSize / recordSize);
            byte[] chunk = new byte[perChunk * recordSize];
            for (long first = 0; first < total; first += perChunk)
            {
                int count = (int)Math.Min(perChunk, total - first);
                ReadStreamBytes(mft, first * recordSize, chunk, 0, count * recordSize);
                for (int i = 0; i < count; i++)
                {
                    int off = i * recordSize;
                    // In use (flag 1) and a base record (base reference 0; an
                    // extension record of $MFT refers to record 0 with a
                    // sequence number, so the whole reference is checked)
                    if ((BitConverter.ToUInt16(chunk, off + 0x16) & 1) == 0) continue;
                    if (BitConverter.ToInt64(chunk, off + 0x20) != 0) continue;
                    if (!ApplyFixups(chunk, off, recordSize)) continue;
                    MftRecord record;
                    try
                    {
                        record = ParseRecord(chunk, off, first + i);
                    }
                    catch (InvalidDataException)
                    {
                        continue;
                    }
                    foreach (NtfsAttribute a in record.Attributes)
                    {
                        // $FILE_NAME: parent reference at 0, name length at 0x40, name at 0x42
                        if (a.Type != FileNameType || a.NonResident || a.ResidentData.Length < 0x42) continue;
                        byte[] value = a.ResidentData;
                        int nameLength = value[0x40];
                        if (0x42 + nameLength * 2 > value.Length) continue;
                        if ((BitConverter.ToInt64(value, 0) & RecordMask) != parentRecord) continue;
                        if (string.Equals(Encoding.Unicode.GetString(value, 0x42, nameLength * 2), name, StringComparison.OrdinalIgnoreCase))
                            return first + i;
                    }
                }
            }
            return -1;
        }

        public long CopyStreamToFile(NtfsStream stream, string path, bool allocatedOnly)
        {
            using (FileStream output = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read))
            {
                return CopyStream(stream, output, allocatedOnly);
            }
        }

        // Writes a stream to output in chunks of whole clusters. allocatedOnly:
        // only the runs stored on disk, in VCN order (sparse runs left out);
        // otherwise sparse runs are written as zeros. Output ends at the real
        // size (DataSize); bytes past the initialized size are written as
        // zeros. Returns the number of bytes written.
        public long CopyStream(NtfsStream stream, Stream output, bool allocatedOnly)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            if (!stream.NonResident)
            {
                output.Write(stream.ResidentData, 0, stream.ResidentData.Length);
                return stream.ResidentData.Length;
            }
            if ((stream.Flags & FlagCompressed) != 0) throw new NotSupportedException("stream '" + stream.Name + "' is compressed");
            if ((stream.Flags & FlagEncrypted) != 0) throw new NotSupportedException("stream '" + stream.Name + "' is encrypted");
            int chunkClusters = Math.Max(1, chunkSize / bytesPerCluster);
            byte[] buffer = new byte[chunkClusters * bytesPerCluster];
            long written = 0;
            long mapped = 0;
            foreach (DataRun run in stream.Runs)
            {
                long runStart = run.Vcn * bytesPerCluster;
                if (runStart >= stream.DataSize) break;
                long runEnd = Math.Min((run.Vcn + run.Length) * bytesPerCluster, stream.DataSize);
                mapped = runEnd;
                if (run.Lcn < 0 && allocatedOnly) continue;
                for (long position = runStart; position < runEnd; )
                {
                    int length = (int)Math.Min(buffer.Length, runEnd - position);
                    if (run.Lcn < 0)
                    {
                        Array.Clear(buffer, 0, length);
                    }
                    else
                    {
                        // Whole clusters, so the device read stays aligned
                        int readLength = (length + bytesPerCluster - 1) / bytesPerCluster * bytesPerCluster;
                        long lcn = run.Lcn + (position - runStart) / bytesPerCluster;
                        ReadVolume(lcn * bytesPerCluster, buffer, 0, readLength);
                    }
                    if (position + length > stream.InitializedSize)
                    {
                        int keep = (int)Math.Max(0, stream.InitializedSize - position);
                        Array.Clear(buffer, keep, length - keep);
                    }
                    output.Write(buffer, 0, length);
                    written += length;
                    position += length;
                }
            }
            if (mapped < stream.DataSize)
                throw new InvalidDataException("the runlist of stream '" + stream.Name + "' maps only " + mapped + " of " + stream.DataSize + " bytes");
            return written;
        }

        // All extents of the attribute (type, name) of a file. Without an
        // $ATTRIBUTE_LIST they are all in the base record; with one, each
        // entry names the record (base or extension) holding an extent.
        // updateMft: the stream is $MFT itself; re-map $MFT after each extent
        // so that later extension records can be read.
        private NtfsStream GetStream(MftRecord baseRecord, uint type, string name, bool updateMft)
        {
            List<NtfsAttribute> extents = new List<NtfsAttribute>();
            NtfsAttribute list = null;
            foreach (NtfsAttribute a in baseRecord.Attributes)
            {
                if (a.Type == AttributeListType) { list = a; break; }
            }
            if (list == null)
            {
                foreach (NtfsAttribute a in baseRecord.Attributes)
                {
                    if (a.Type == type && a.Name == name) extents.Add(a);
                }
                if (extents.Count == 0) return null;
                return BuildStream(extents, name);
            }

            // Entry: type (0), length (4), name length (6), name offset (7),
            // starting VCN (8), file reference of the holding record (0x10),
            // attribute id (0x18). Entries are sorted by type, name and VCN.
            byte[] entries = ReadAttributeValue(list);
            Dictionary<long, MftRecord> records = new Dictionary<long, MftRecord>();
            records[baseRecord.Number] = baseRecord;
            int pos = 0;
            while (pos + 0x1A <= entries.Length)
            {
                uint entryType = BitConverter.ToUInt32(entries, pos);
                int entryLength = BitConverter.ToUInt16(entries, pos + 4);
                if (entryType == EndMarker || entryLength == 0) break;
                int nameLength = entries[pos + 6];
                int nameOffset = entries[pos + 7];
                if (entryLength < 0x1A || pos + entryLength > entries.Length || nameOffset + nameLength * 2 > entryLength)
                    throw new InvalidDataException("damaged $ATTRIBUTE_LIST in MFT record " + baseRecord.Number);
                string entryName = Encoding.Unicode.GetString(entries, pos + nameOffset, nameLength * 2);
                if (entryType == type && entryName == name)
                {
                    long recordNumber = BitConverter.ToInt64(entries, pos + 0x10) & RecordMask;
                    ushort id = BitConverter.ToUInt16(entries, pos + 0x18);
                    MftRecord holder;
                    if (!records.TryGetValue(recordNumber, out holder))
                    {
                        holder = ReadRecord(recordNumber);
                        if (holder.BaseRecord != baseRecord.Number)
                            throw new InvalidDataException("MFT record " + recordNumber + " is not an extension record of record " + baseRecord.Number);
                        records[recordNumber] = holder;
                    }
                    NtfsAttribute found = null;
                    foreach (NtfsAttribute a in holder.Attributes)
                    {
                        if (a.Type == type && a.Id == id && a.Name == name) { found = a; break; }
                    }
                    if (found == null)
                        throw new InvalidDataException("attribute " + id + " listed in the $ATTRIBUTE_LIST of record " + baseRecord.Number + " is missing from record " + recordNumber);
                    extents.Add(found);
                    if (updateMft) mft = BuildStream(extents, name);
                }
                pos += entryLength;
            }
            if (extents.Count == 0) return null;
            return BuildStream(extents, name);
        }

        // Joins the extents of one attribute (in VCN order, no gaps)
        private static NtfsStream BuildStream(List<NtfsAttribute> extents, string name)
        {
            extents.Sort(CompareStartVcn);
            NtfsAttribute first = extents[0];
            NtfsStream stream = new NtfsStream();
            stream.Name = name;
            stream.Flags = first.Flags;
            stream.NonResident = first.NonResident;
            stream.DataSize = first.DataSize;
            stream.InitializedSize = first.InitializedSize;
            if (!first.NonResident)
            {
                if (extents.Count > 1) throw new InvalidDataException("stream '" + name + "' is resident but has more than one extent");
                stream.ResidentData = first.ResidentData;
                return stream;
            }
            long nextVcn = 0;
            foreach (NtfsAttribute extent in extents)
            {
                if (!extent.NonResident || extent.StartVcn != nextVcn)
                    throw new InvalidDataException("the extents of stream '" + name + "' are not contiguous at VCN " + nextVcn);
                stream.Runs.AddRange(extent.Runs);
                nextVcn = extent.LastVcn + 1;
            }
            return stream;
        }

        private static int CompareStartVcn(NtfsAttribute x, NtfsAttribute y)
        {
            return x.StartVcn.CompareTo(y.StartVcn);
        }

        // Value of an attribute: resident data, or read through its runs
        private byte[] ReadAttributeValue(NtfsAttribute attribute)
        {
            if (!attribute.NonResident) return attribute.ResidentData;
            if (attribute.StartVcn != 0 || attribute.DataSize < 0 || attribute.DataSize > 64 * 1024 * 1024)
                throw new InvalidDataException("unexpected non-resident attribute 0x" + attribute.Type.ToString("X") + " of " + attribute.DataSize + " bytes");
            List<NtfsAttribute> extents = new List<NtfsAttribute>();
            extents.Add(attribute);
            byte[] value = new byte[attribute.DataSize];
            ReadStreamBytes(BuildStream(extents, attribute.Name), 0, value, 0, value.Length);
            return value;
        }

        // Checks the "FILE" signature and undoes the update sequence: on disk
        // the last two bytes of every stride (512 bytes) hold the update
        // sequence number; the original bytes are kept in the update sequence
        // array. False = not a valid record (unused, torn write or damaged).
        private static bool ApplyFixups(byte[] b, int off, int length)
        {
            if (b[off] != 0x46 || b[off + 1] != 0x49 || b[off + 2] != 0x4C || b[off + 3] != 0x45) return false;
            int usaOffset = BitConverter.ToUInt16(b, off + 4);
            int usaCount = BitConverter.ToUInt16(b, off + 6);
            if (usaCount < 2 || usaOffset < 0x28 || usaOffset + usaCount * 2 > length) return false;
            int stride = length / (usaCount - 1);
            if (stride * (usaCount - 1) != length || stride < 256) return false;
            for (int i = 1; i < usaCount; i++)
            {
                int p = off + i * stride - 2;
                if (b[p] != b[off + usaOffset] || b[p + 1] != b[off + usaOffset + 1]) return false;
            }
            for (int i = 1; i < usaCount; i++)
            {
                int p = off + i * stride - 2;
                b[p] = b[off + usaOffset + 2 * i];
                b[p + 1] = b[off + usaOffset + 2 * i + 1];
            }
            return true;
        }

        // Header: first attribute offset (0x14), flags (0x16, 1 = in use),
        // bytes in use (0x18), base record reference (0x20)
        private MftRecord ParseRecord(byte[] b, int off, long number)
        {
            MftRecord record = new MftRecord();
            record.Number = number;
            record.Flags = BitConverter.ToUInt16(b, off + 0x16);
            record.BaseRecord = BitConverter.ToInt64(b, off + 0x20) & RecordMask;
            int used = (int)Math.Min(BitConverter.ToUInt32(b, off + 0x18), (uint)recordSize);
            int pos = BitConverter.ToUInt16(b, off + 0x14);
            while (pos + 4 <= used)
            {
                uint type = BitConverter.ToUInt32(b, off + pos);
                if (type == EndMarker) break;
                int length = pos + 0x10 <= used ? (int)BitConverter.ToUInt32(b, off + pos + 4) : 0;
                if (length < 0x10 || length > used - pos)
                    throw new InvalidDataException("MFT record " + number + ": damaged attribute at offset " + pos);
                record.Attributes.Add(ParseAttribute(b, off + pos, length, number));
                pos += length;
            }
            return record;
        }

        // Attribute header: type (0), length (4), non-resident (8), name
        // length (9), name offset (0x0A), flags (0x0C), id (0x0E). Resident:
        // value length (0x10), value offset (0x14). Non-resident: first and
        // last VCN (0x10, 0x18), runlist offset (0x20), allocated, real and
        // initialized size (0x28, 0x30, 0x38).
        private static NtfsAttribute ParseAttribute(byte[] b, int p, int length, long number)
        {
            NtfsAttribute a = new NtfsAttribute();
            a.Type = BitConverter.ToUInt32(b, p);
            a.NonResident = b[p + 8] != 0;
            int nameLength = b[p + 9];
            int nameOffset = BitConverter.ToUInt16(b, p + 0x0A);
            a.Flags = BitConverter.ToUInt16(b, p + 0x0C);
            a.Id = BitConverter.ToUInt16(b, p + 0x0E);
            if (nameLength > 0)
            {
                if (nameOffset + nameLength * 2 > length)
                    throw new InvalidDataException("MFT record " + number + ": damaged attribute name");
                a.Name = Encoding.Unicode.GetString(b, p + nameOffset, nameLength * 2);
            }
            if (!a.NonResident)
            {
                if (length < 0x18) throw new InvalidDataException("MFT record " + number + ": damaged resident attribute");
                long valueLength = BitConverter.ToUInt32(b, p + 0x10);
                int valueOffset = BitConverter.ToUInt16(b, p + 0x14);
                if (valueOffset + valueLength > length)
                    throw new InvalidDataException("MFT record " + number + ": damaged resident attribute");
                a.ResidentData = new byte[valueLength];
                Buffer.BlockCopy(b, p + valueOffset, a.ResidentData, 0, (int)valueLength);
                a.DataSize = valueLength;
                a.InitializedSize = valueLength;
            }
            else
            {
                if (length < 0x40) throw new InvalidDataException("MFT record " + number + ": damaged non-resident attribute");
                a.StartVcn = BitConverter.ToInt64(b, p + 0x10);
                a.LastVcn = BitConverter.ToInt64(b, p + 0x18);
                int runsOffset = BitConverter.ToUInt16(b, p + 0x20);
                a.DataSize = BitConverter.ToInt64(b, p + 0x30);
                a.InitializedSize = BitConverter.ToInt64(b, p + 0x38);
                if (runsOffset < 0x40 || runsOffset > length)
                    throw new InvalidDataException("MFT record " + number + ": damaged runlist offset");
                a.Runs = DecodeRuns(b, p + runsOffset, p + length, a.StartVcn, number);
                long nextVcn = a.StartVcn;
                foreach (DataRun run in a.Runs) nextVcn += run.Length;
                if (nextVcn != a.LastVcn + 1)
                    throw new InvalidDataException("MFT record " + number + ": runlist ends at VCN " + nextVcn + ", attribute at " + (a.LastVcn + 1));
            }
            return a;
        }

        // Runlist (mapping pairs): a header byte (low nibble = size of the
        // length field, high nibble = size of the offset field), the run
        // length, then the run's LCN as a signed offset from the previous
        // run's LCN. No offset field = sparse run. A 0 header ends the list.
        private static List<DataRun> DecodeRuns(byte[] b, int pos, int end, long startVcn, long number)
        {
            List<DataRun> runs = new List<DataRun>();
            long vcn = startVcn;
            long lcn = 0;
            while (pos < end && b[pos] != 0)
            {
                int lengthSize = b[pos] & 0x0F;
                int offsetSize = (b[pos] >> 4) & 0x0F;
                if (lengthSize == 0 || lengthSize > 8 || offsetSize > 8 || pos + 1 + lengthSize + offsetSize > end)
                    throw new InvalidDataException("MFT record " + number + ": damaged runlist");
                DataRun run = new DataRun();
                run.Vcn = vcn;
                run.Length = ReadLittleEndian(b, pos + 1, lengthSize, false);
                if (run.Length <= 0) throw new InvalidDataException("MFT record " + number + ": damaged runlist (run length)");
                if (offsetSize == 0)
                {
                    run.Lcn = -1;
                }
                else
                {
                    lcn += ReadLittleEndian(b, pos + 1 + lengthSize, offsetSize, true);
                    if (lcn < 0) throw new InvalidDataException("MFT record " + number + ": damaged runlist (negative LCN)");
                    run.Lcn = lcn;
                }
                runs.Add(run);
                vcn += run.Length;
                pos += 1 + lengthSize + offsetSize;
            }
            return runs;
        }

        private static long ReadLittleEndian(byte[] b, int pos, int size, bool signed)
        {
            long value = 0;
            for (int i = size - 1; i >= 0; i--) value = (value << 8) | b[pos + i];
            if (signed && size < 8 && (b[pos + size - 1] & 0x80) != 0) value |= -1L << (size * 8);
            return value;
        }

        // Reads bytes of a stream by virtual offset (sparse parts read as zeros)
        private void ReadStreamBytes(NtfsStream stream, long offset, byte[] buffer, int index, int count)
        {
            if (!stream.NonResident)
            {
                if (offset < 0 || offset + count > stream.ResidentData.Length)
                    throw new EndOfStreamException("read past the end of resident stream '" + stream.Name + "'");
                Buffer.BlockCopy(stream.ResidentData, (int)offset, buffer, index, count);
                return;
            }
            while (count > 0)
            {
                long vcn = offset / bytesPerCluster;
                DataRun run = FindRun(stream.Runs, vcn);
                if (run == null)
                    throw new InvalidDataException("offset " + offset + " of stream '" + stream.Name + "' is not mapped by its runlist");
                int length = (int)Math.Min(count, (run.Vcn + run.Length) * bytesPerCluster - offset);
                if (run.Lcn < 0)
                    Array.Clear(buffer, index, length);
                else
                    ReadVolume((run.Lcn + vcn - run.Vcn) * bytesPerCluster + offset % bytesPerCluster, buffer, index, length);
                offset += length;
                index += length;
                count -= length;
            }
        }

        private static DataRun FindRun(List<DataRun> runs, long vcn)
        {
            int low = 0;
            int high = runs.Count - 1;
            while (low <= high)
            {
                int middle = low + (high - low) / 2;
                DataRun run = runs[middle];
                if (vcn < run.Vcn) high = middle - 1;
                else if (vcn >= run.Vcn + run.Length) low = middle + 1;
                else return run;
            }
            return null;
        }

        // Volume reads: offset and length are widened to whole sectors (a
        // volume device rejects anything else)
        private void ReadVolume(long offset, byte[] buffer, int index, int count)
        {
            long start = offset - offset % bytesPerSector;
            long end = offset + count;
            long alignedEnd = (end + bytesPerSector - 1) / bytesPerSector * bytesPerSector;
            if (start == offset && alignedEnd == end)
            {
                ReadExact(offset, buffer, index, count);
                return;
            }
            byte[] aligned = new byte[alignedEnd - start];
            ReadExact(start, aligned, 0, aligned.Length);
            Buffer.BlockCopy(aligned, (int)(offset - start), buffer, index, count);
        }

        private void ReadExact(long offset, byte[] buffer, int index, int count)
        {
            volume.Position = offset;
            int done = 0;
            while (done < count)
            {
                int read = volume.Read(buffer, index + done, count - done);
                if (read <= 0) throw new EndOfStreamException("read past the end of the volume at offset " + (offset + done));
                done += read;
            }
        }
    }
}
'@

$script:ntfsReaderReady = $null
function Initialize-TriageNtfsReader {
    if ($null -ne $script:ntfsReaderReady) { return $script:ntfsReaderReady }
    if ('TriageNtfs.NtfsReader' -as [type]) {
        $script:ntfsReaderReady = $true
        return $true
    }
    try {
        Add-Type -TypeDefinition $script:triageNtfsSource -ErrorAction Stop
        $script:ntfsReaderReady = $true
    } catch {
        Log-Warning "Raw NTFS reader could not be compiled (raw `$MFT, `$LogFile and `$UsnJrnl:`$J not collected): $($_.Exception.Message)"
        $script:errorCount++
        $script:ntfsReaderReady = $false
    }
    return $script:ntfsReaderReady
}

# Message of the exception behind an error record (.NET method calls wrap
# it in a MethodInvocationException)
function Get-TriageErrorMessage {
    param($ErrorRecord)
    $innerError = $ErrorRecord.Exception
    while ($innerError.InnerException -and $innerError -is [System.Management.Automation.MethodInvocationException]) {
        $innerError = $innerError.InnerException
    }
    return $innerError.Message
}

# Copy one $DATA stream of an MFT record to DestPath and record it in the
# manifest. -AllocatedOnly leaves out sparse runs ($UsnJrnl:$J).
# -Signature: expected first bytes of the copy (discarded if different).
function Copy-TriageRawNtfsStream {
    [OutputType([void])]
    param(
        [object]$Reader,
        [long]$RecordNumber,
        [string]$StreamName,
        [string]$Label,
        [string]$DestPath,
        [string]$SourcePath,
        [string]$Signature = "",
        [switch]$AllocatedOnly
    )
    $stream = $null
    $written = 0
    try {
        $stream = $Reader.GetDataStream($RecordNumber, $StreamName)
        if ($null -eq $stream) {
            Log-Warning "Could not collect $Label (raw NTFS): MFT record $RecordNumber has no such data stream"
            $script:errorCount++
            return
        }
        $written = $Reader.CopyStreamToFile($stream, $DestPath, $AllocatedOnly.IsPresent)
    } catch {
        Log-Warning "Could not collect $Label (raw NTFS): $(Get-TriageErrorMessage $_)"
        $script:errorCount++
        Remove-Item -LiteralPath $DestPath -Force -ErrorAction SilentlyContinue
        return
    }

    if ($written -le 0) {
        Log "$Label (raw NTFS): no allocated data -- nothing to copy"
        Remove-Item -LiteralPath $DestPath -Force -ErrorAction SilentlyContinue
        return
    }

    if ($Signature) {
        $head = ""
        try {
            $headStream = [System.IO.File]::OpenRead($DestPath)
            try {
                $headBytes = New-Object byte[] $Signature.Length
                $headRead = $headStream.Read($headBytes, 0, $headBytes.Length)
                $head = [System.Text.Encoding]::ASCII.GetString($headBytes, 0, $headRead)
            } finally {
                $headStream.Dispose()
            }
        } catch { Write-Verbose "Reading the start of ${DestPath}: $($_.Exception.Message)" }
        if ($head -cne $Signature) {
            Log-Warning "Raw NTFS copy of $Label does not start with '$Signature' -- discarded"
            Remove-Item -LiteralPath $DestPath -Force -ErrorAction SilentlyContinue
            $script:errorCount++
            return
        }
    }

    Record-Manifest -SourcePath $SourcePath -DestPath $DestPath
    $sizeText = "$([math]::Round($written / 1MB, 2)) MB ($written bytes)"
    if ($AllocatedOnly) {
        Log-Success "Collected $Label (raw NTFS, allocated part only): $sizeText; stream size $([math]::Round($stream.DataSize / 1MB, 2)) MB"
    } else {
        Log-Success "Collected $Label (raw NTFS): $sizeText"
    }
}

# Raw $MFT, $LogFile and $UsnJrnl:$J (allocated part) of the target volume
# into DestDir. Live system: the system volume. Mounted image: its drive,
# but only when the Windows root is the root of that drive and the volume
# is NTFS (a nested layout such as G:\C\ is a folder, not a volume).
# Never throws: failures are logged as warnings and the collection goes on.
function Save-TriageRawNtfsFiles {
    [OutputType([void])]
    param([string]$DestDir)

    if (-not $script:IsLive) {
        if ($script:TargetRoot.TrimEnd('\') -ne "${TargetDrive}:") {
            Log "Raw `$MFT, `$LogFile, `$UsnJrnl:`$J skipped: the Windows root $($script:TargetRoot) is a folder on ${TargetDrive}:, not the root of a volume"
            return
        }
        $fileSystem = ""
        try {
            $fileSystem = (New-Object System.IO.DriveInfo($TargetDrive)).DriveFormat
        } catch { Write-Verbose "Reading the file system of ${TargetDrive}: $($_.Exception.Message)" }
        if ($fileSystem -ne "NTFS") {
            if (-not $fileSystem) { $fileSystem = "unknown" }
            Log "Raw `$MFT, `$LogFile, `$UsnJrnl:`$J skipped: ${TargetDrive}: is not an NTFS volume (file system: $fileSystem)"
            return
        }
    }
    if (-not (Initialize-TriageNtfsReader)) { return }

    $volumePath = "\\.\${TargetDrive}:"
    Log "Reading NTFS metafiles from $volumePath (built-in raw NTFS reader)..."
    $reader = $null
    try {
        $reader = [TriageNtfs.NtfsReader]::OpenVolume($volumePath)
    } catch {
        Log-Warning "Raw `$MFT, `$LogFile and `$UsnJrnl:`$J not collected: $(Get-TriageErrorMessage $_)"
        $script:errorCount++
        return
    }
    try {
        Log "  $($reader.BytesPerCluster)-byte clusters, $($reader.RecordSize)-byte MFT records, `$MFT $([math]::Round($reader.MftSize / 1MB, 2)) MB"

        # $MFT = unnamed $DATA of record 0, $LogFile = unnamed $DATA of record 2
        Copy-TriageRawNtfsStream -Reader $reader -RecordNumber 0 -StreamName "" -Label '$MFT' `
            -DestPath (Join-Path $DestDir '$MFT') -SourcePath "(raw NTFS $volumePath `$MFT)" -Signature "FILE"
        Copy-TriageRawNtfsStream -Reader $reader -RecordNumber 2 -StreamName "" -Label '$LogFile' `
            -DestPath (Join-Path $DestDir '$LogFile') -SourcePath "(raw NTFS $volumePath `$LogFile)"

        # $UsnJrnl:$J = the $J stream of the entry named $UsnJrnl in $Extend
        # (record 11). $J is sparse: the journal's old, freed part reads as
        # zeros, so only the allocated runs are copied.
        $usnRecord = -1
        $searchFailed = $false
        try {
            $usnRecord = $reader.FindRecordByName(11, '$UsnJrnl')
        } catch {
            Log-Warning "Could not collect `$UsnJrnl:`$J (raw NTFS): searching the MFT failed -- $(Get-TriageErrorMessage $_)"
            $script:errorCount++
            $searchFailed = $true
        }
        if ($usnRecord -ge 0) {
            Copy-TriageRawNtfsStream -Reader $reader -RecordNumber $usnRecord -StreamName '$J' -Label '$UsnJrnl:$J' `
                -DestPath (Join-Path $DestDir '$UsnJrnl_$J') -SourcePath "(raw NTFS $volumePath `$UsnJrnl:`$J)" -AllocatedOnly
        } elseif (-not $searchFailed) {
            Log-Warning "No `$UsnJrnl in `$Extend on ${TargetDrive}: (USN journal not active?) -- raw `$UsnJrnl:`$J not collected"
        }
    } finally {
        $reader.Dispose()
    }
}

# =============================================================
# 1. FileSystem Artifacts
# =============================================================
if ($Categories -contains "FileSystem") {
    Log "============================================================="
    Log "  COLLECTING: FileSystem Artifacts"
    Log "============================================================="
    $fsDir = Join-Path $OutputPath "FileSystem"
    Ensure-Directory $fsDir

    if ($SkipLargeFiles) {
        Log "SkipLargeFiles is set -- skipping the raw NTFS copies (`$MFT, `$LogFile, `$UsnJrnl:`$J) and the USN journal export"
    } else {
        # Raw $MFT, $LogFile and $UsnJrnl:$J (allocated part) with the built-in
        # NTFS reader. Failures are logged; the fsutil export below runs anyway.
        try {
            Save-TriageRawNtfsFiles -DestDir $fsDir
        } catch {
            Log-Warning "Raw NTFS copies failed: $(Get-TriageErrorMessage $_)"
            $script:errorCount++
        }

        # $UsnJrnl:$J as text (the timeline builder parses this export)
        Log "Collecting `$UsnJrnl:`$J via fsutil usn readjournal..."
        try {
            $ujDest = Join-Path $fsDir '$UsnJrnl_$J.txt'
            fsutil usn readjournal ${TargetDrive}: csv 2>&1 | Out-File -LiteralPath $ujDest -Encoding utf8
            # fsutil writes its error message (e.g. "Error:  Access is denied.")
            # instead of a journal when it fails: a real export has a "Usn," header
            $ujHead = @(Get-Content -LiteralPath $ujDest -TotalCount 20 -ErrorAction SilentlyContinue)
            if ((Get-FileLength $ujDest) -gt 0 -and -not ($ujHead -match '^Usn,')) {
                Log-Warning "fsutil could not export the USN journal: $((($ujHead | Where-Object { $_ }) -join ' ').Trim())"
                Remove-Item -LiteralPath $ujDest -Force -ErrorAction SilentlyContinue
                $script:errorCount++
            }
            elseif ((Get-FileLength $ujDest) -gt 0) {
                Record-Manifest -SourcePath "(fsutil usn readjournal)" -DestPath $ujDest
                Log-Success "Collected USN Journal via fsutil (CSV format)"
            } else {
                Remove-Item -LiteralPath $ujDest -Force -ErrorAction SilentlyContinue
                Log-Warning "Could not collect `$UsnJrnl"
            }
        } catch {
            Log-Warning "Could not collect `$UsnJrnl: $($_.Exception.Message)"
        }
    }

    Log-Success "FileSystem collection complete."
    Log ""
}

# =============================================================
# 2. Registry Hives
# =============================================================
if ($Categories -contains "Registry") {
    Log "============================================================="
    Log "  COLLECTING: Registry Hives"
    Log "============================================================="
    $regDir = Join-Path $OutputPath "Registry"
    Ensure-Directory $regDir

    # System hives
    $systemHives = @("SYSTEM", "SOFTWARE", "SAM", "SECURITY")

    if ($script:IsLive) {
        # Live system: use reg save (cleaner than VSS shadow copy)
        # A temporary Defender exclusion was added at script start so that
        # collecting SAM/SECURITY doesn't trigger Trojan:Win32/SAMDumpz.
        foreach ($hiveName in $systemHives) {
            Log "Collecting $hiveName hive via reg save..."
            try {
                $destFile = Join-Path $regDir $hiveName
                reg save "HKLM\$hiveName" $destFile /y 2>&1 | Out-Null
                if ((Get-FileLength $destFile) -gt 0) {
                    Record-Manifest -SourcePath "HKLM\$hiveName" -DestPath $destFile
                    Log-Success "Collected $hiveName via reg save"
                } else {
                    Log-Warning "Could not collect $hiveName via reg save"
                }
            } catch {
                Log-Warning "Could not collect ${hiveName}: $($_.Exception.Message)"
            }
        }
    } else {
        # Mounted image: copy hive files directly from config directory
        $hiveSourceDir = "${script:TargetRoot}Windows\System32\config"
        foreach ($hiveName in $systemHives) {
            Log "Collecting $hiveName hive (file copy from mounted image)..."
            $hiveSrc = Join-Path $hiveSourceDir $hiveName
            if (Test-Path -LiteralPath $hiveSrc) {
                Copy-ForensicFile -SourcePath $hiveSrc -DestDir $regDir -DestName $hiveName
                if ((Get-FileLength (Join-Path $regDir $hiveName)) -gt 0) {
                    Log-Success "Collected $hiveName (file copy)"
                } else {
                    Log-Warning "Could not collect $hiveName"
                }
            } else {
                Log-Warning "$hiveName not found at $hiveSrc"
            }
        }
    }

    # Amcache (hive + transaction logs so dirty hives can be recovered)
    Log "Collecting Amcache.hve..."
    $amcacheSrc = "${script:TargetRoot}Windows\AppCompat\Programs\Amcache.hve"
    $amcachePath = "Windows\AppCompat\Programs\Amcache.hve"
    $result = Copy-FromShadow -RelativePath $amcachePath -DestDir $regDir -DestName "Amcache.hve"
    if (-not $result) {
        Copy-ForensicFile -SourcePath $amcacheSrc -DestDir $regDir
    }
    if ((Get-FileLength (Join-Path $regDir "Amcache.hve")) -gt 0) {
        Log-Success "Collected Amcache.hve"
    } else {
        Log-Warning "Could not collect Amcache.hve"
    }
    # Collect transaction logs for dirty hive recovery (locked + hidden, need shadow copy)
    foreach ($logExt in @(".LOG1", ".LOG2")) {
        $logRelPath = "Windows\AppCompat\Programs\Amcache.hve${logExt}"
        $logResult = Copy-FromShadow -RelativePath $logRelPath -DestDir $regDir -DestName "Amcache.hve${logExt}"
        if (-not $logResult) {
            # Fallback to direct copy
            $logSrc = "${amcacheSrc}${logExt}"
            if (Test-Path -LiteralPath $logSrc) {
                Copy-ForensicFile -SourcePath $logSrc -DestDir $regDir
            }
        }
        if ((Get-FileLength (Join-Path $regDir "Amcache.hve${logExt}")) -gt 0) {
            Log-Success "Collected Amcache.hve${logExt}"
        }
    }

    # Per-user hives: NTUSER.DAT and UsrClass.dat
    Log "Collecting per-user registry hives..."
    $userProfiles = Get-ChildItem "${script:TargetRoot}Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }

    # Build a map of loaded HKU SIDs to profile folder names for reg save (live
    # system only). Local/domain accounts are S-1-5-21-..., Entra ID (Azure AD)
    # accounts S-1-12-1-...; *_Classes keys do not match (anchored at the end).
    $sidToUser = @{}
    if ($script:IsLive) {
        try {
            $hkuKeys = reg query HKU 2>&1
            foreach ($line in $hkuKeys) {
                if ("$line" -match '(S-1-5-21-[\d-]+|S-1-12-1-[\d-]+)$') {
                    $sid = $Matches[1]
                    $profileName = $null
                    # Profile folder from ProfileList (Entra ID folder names often
                    # differ from the account name)
                    try {
                        $profileKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
                        $profileImage = (Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
                        if ($profileImage) { $profileName = [System.IO.Path]::GetFileName($profileImage.TrimEnd('\')) }
                    } catch { Write-Verbose "Reading ProfileList entry for ${sid}: $($_.Exception.Message)" }
                    # Fallback: account name
                    if (-not $profileName) {
                        try {
                            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
                            $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
                            $profileName = $objUser.Value -replace '^.*\\', ''
                        } catch { Write-Verbose "Translating SID $sid to an account name: $($_.Exception.Message)" }
                    }
                    if ($profileName) { $sidToUser[$profileName] = $sid }
                }
            }
        } catch { Write-Verbose "Mapping loaded HKU hives to profile folders: $($_.Exception.Message)" }
    }

    foreach ($userDir in $userProfiles) {
        $userName = $userDir.Name
        $userRegDir = Join-Path $regDir $userName
        Ensure-Directory $userRegDir

        # Check if this user has a loaded HKU hive (active/logged-in user)
        $userSid = $sidToUser[$userName]

        # NTUSER.DAT
        $ntuser = Join-Path $userDir.FullName "NTUSER.DAT"
        if (Test-Path -LiteralPath $ntuser) {
            Log "Collecting NTUSER.DAT for $userName..."
            $collected = $false

            # Method 1: reg save via HKU\SID (live system only, works for active user)
            if ($script:IsLive -and $userSid -and -not $collected) {
                $destFile = Join-Path $userRegDir "NTUSER.DAT"
                try {
                    reg save "HKU\$userSid" $destFile /y 2>&1 | Out-Null
                    if ((Get-FileLength $destFile) -gt 0) {
                        Record-Manifest -SourcePath "HKU\$userSid" -DestPath $destFile
                        Log-Success "Collected NTUSER.DAT for $userName via reg save"
                        $collected = $true
                    }
                } catch { Write-Verbose "reg save of HKU\$userSid for ${userName}: $($_.Exception.Message)" }
            }

            # Method 2: Shadow copy
            if (-not $collected) {
                $relPath = "Users\$userName\NTUSER.DAT"
                $result = Copy-FromShadow -RelativePath $relPath -DestDir $userRegDir -DestName "NTUSER.DAT"
                if ($result) { $collected = $true }
            }

            # Method 3: Direct copy (works for non-active users)
            if (-not $collected) {
                Copy-ForensicFile -SourcePath $ntuser -DestDir $userRegDir -DestName "NTUSER.DAT"
            }
        }

        # UsrClass.dat
        $usrclass = Join-Path $userDir.FullName "AppData\Local\Microsoft\Windows\UsrClass.dat"
        if (Test-Path -LiteralPath $usrclass) {
            Log "Collecting UsrClass.dat for $userName..."
            $collected = $false

            # Method 1: reg save via HKU\SID_Classes (live system only, works for active user)
            if ($script:IsLive -and $userSid -and -not $collected) {
                $destFile = Join-Path $userRegDir "UsrClass.dat"
                try {
                    reg save "HKU\${userSid}_Classes" $destFile /y 2>&1 | Out-Null
                    if ((Get-FileLength $destFile) -gt 0) {
                        Record-Manifest -SourcePath "HKU\${userSid}_Classes" -DestPath $destFile
                        Log-Success "Collected UsrClass.dat for $userName via reg save"
                        $collected = $true
                    }
                } catch { Write-Verbose "reg save of HKU\${userSid}_Classes for ${userName}: $($_.Exception.Message)" }
            }

            # Method 2: Shadow copy
            if (-not $collected) {
                $relPath = "Users\$userName\AppData\Local\Microsoft\Windows\UsrClass.dat"
                $result = Copy-FromShadow -RelativePath $relPath -DestDir $userRegDir -DestName "UsrClass.dat"
                if ($result) { $collected = $true }
            }

            # Method 3: Direct copy (works for non-active users)
            if (-not $collected) {
                Copy-ForensicFile -SourcePath $usrclass -DestDir $userRegDir -DestName "UsrClass.dat"
            }
        }
    }

    Log-Success "Registry collection complete."
    Log ""
}

# =============================================================
# 3. Event Logs
# =============================================================
if ($Categories -contains "EventLogs") {
    Log "============================================================="
    Log "  COLLECTING: Event Logs"
    Log "============================================================="
    $evtDir = Join-Path $OutputPath "EventLogs"
    Ensure-Directory $evtDir

    $eventLogs = @(
        "System",
        "Security",
        "Application",
        "Microsoft-Windows-Sysmon%4Operational",
        "Microsoft-Windows-PowerShell%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational",
        "Microsoft-Windows-Windows Defender%4Operational",
        "Microsoft-Windows-Bits-Client%4Operational"
    )

    $evtxRoot = "${script:TargetRoot}Windows\System32\winevt\Logs"

    foreach ($logName in $eventLogs) {
        $fileName = "$logName.evtx"
        $sourcePath = Join-Path $evtxRoot $fileName
        if (Test-Path $sourcePath) {
            Log "Collecting $fileName..."
            $destFile = Join-Path $evtDir $fileName
            if ($script:IsLive) {
                # Live system: use wevtutil to export (handles locked logs properly)
                try {
                    $wevtName = $logName -replace '%4', '/'
                    wevtutil epl $wevtName $destFile 2>&1 | Out-Null
                    if (Test-Path $destFile) {
                        Record-Manifest -SourcePath $sourcePath -DestPath $destFile
                        Log-Success "Collected $fileName"
                    } else {
                        # Fallback to file copy via shadow
                        $result = Copy-FromShadow -RelativePath "Windows\System32\winevt\Logs\$fileName" -DestDir $evtDir
                        if ($result) { Log-Success "Collected $fileName (shadow)" }
                        else { Log-Warning "Could not collect $fileName" }
                    }
                } catch {
                    Log-Warning "Could not collect $fileName -- $($_.Exception.Message)"
                }
            } else {
                # Mounted image: direct file copy (not locked)
                Copy-ForensicFile -SourcePath $sourcePath -DestDir $evtDir -DestName $fileName
                if (Test-Path $destFile) {
                    Log-Success "Collected $fileName (file copy)"
                } else {
                    Log-Warning "Could not collect $fileName"
                }
            }
        } else {
            Log "Skipping $fileName (not present on target)"
        }
    }

    Log-Success "Event Logs collection complete."
    Log ""
}

# ----------------------------------------------------------
# Helpers for the Execution, USB and Persistence sections:
# registry key times, loaded user hives, SID names, CSV output
# ----------------------------------------------------------

# RegQueryInfoKey P/Invoke (key last-write time is not exposed by
# Microsoft.Win32.RegistryKey). Compiled on first use only.
$script:regLastWriteReady = $null
function Initialize-TriageRegLastWrite {
    if ($null -ne $script:regLastWriteReady) { return $script:regLastWriteReady }
    if ('TriageNative.RegKeyInfo' -as [type]) {
        $script:regLastWriteReady = $true
        return $true
    }
    try {
        Add-Type -Namespace TriageNative -Name RegKeyInfo -ErrorAction Stop -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
public static extern int RegQueryInfoKey(
    Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
    IntPtr lpClass, IntPtr lpcchClass, IntPtr lpReserved,
    IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen,
    IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen,
    IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
'@
        $script:regLastWriteReady = $true
    } catch {
        Log-Warning "Registry key last-write times unavailable: $($_.Exception.Message)"
        $script:regLastWriteReady = $false
    }
    return $script:regLastWriteReady
}

# Open a registry key read-only in the 64-bit view. Hive is "HKLM" or "HKU".
# Returns $null if the key is missing or access is denied.
function Open-TriageRegKey {
    param(
        [string]$Hive,
        [string]$SubKey
    )
    try {
        $hiveId = [Microsoft.Win32.RegistryHive]::LocalMachine
        if ($Hive -eq "HKU") { $hiveId = [Microsoft.Win32.RegistryHive]::Users }
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hiveId, [Microsoft.Win32.RegistryView]::Registry64)
        return $baseKey.OpenSubKey($SubKey, $false)
    } catch {
        return $null
    }
}

# Last-write time of an open registry key as UTC ISO 8601 ("o"); "" if unknown
function Get-TriageRegLastWriteUtc {
    param([Microsoft.Win32.RegistryKey]$Key)
    if ($null -eq $Key) { return "" }
    if (-not (Initialize-TriageRegLastWrite)) { return "" }
    try {
        $fileTime = [long]0
        $z = [IntPtr]::Zero
        $rc = [TriageNative.RegKeyInfo]::RegQueryInfoKey($Key.Handle, $z, $z, $z, $z, $z, $z, $z, $z, $z, $z, [ref]$fileTime)
        if ($rc -eq 0 -and $fileTime -gt 0) {
            return [DateTime]::FromFileTimeUtc($fileTime).ToString("o")
        }
    } catch { Write-Verbose "Reading last-write time of $($Key.Name): $($_.Exception.Message)" }
    return ""
}

# Last-write time of HKLM\SYSTEM\CurrentControlSet\Services\<Name>
function Get-TriageServiceKeyLastWriteUtc {
    param([string]$Name)
    if (-not $Name) { return "" }
    $key = Open-TriageRegKey -Hive "HKLM" -SubKey "SYSTEM\CurrentControlSet\Services\$Name"
    if ($null -eq $key) { return "" }
    try {
        return (Get-TriageRegLastWriteUtc -Key $key)
    } finally {
        $key.Close()
    }
}

# Registry value data as text (multi-string joined, binary as hex)
function Format-TriageRegValue {
    param($Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [byte[]]) { return [BitConverter]::ToString($Value) }
    if ($Value -is [array]) { return (@($Value | ForEach-Object { [string]$_ }) -join "; ") }
    return [string]$Value
}

# SIDs of the user hives loaded under HKU: local (S-1-5-21-*) and
# Entra ID (S-1-12-1-*) accounts, not the *_Classes hives
function Get-TriageLoadedUserSids {
    $sids = @()
    try {
        $hku = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
        foreach ($name in $hku.GetSubKeyNames()) {
            if ($name -match '^S-1-(5-21|12-1)-[\d-]+$') { $sids += $name }
        }
    } catch {
        Log-Warning "Could not enumerate loaded user hives under HKU (per-user registry data skipped): $($_.Exception.Message)"
    }
    return $sids
}

# SID -> account name (best effort, cached). Uses the profile folder name
# first so it matches the per-user folder names in the collection.
$script:sidUserCache = @{}
function Resolve-TriageSidUser {
    param([string]$Sid)
    if (-not $Sid) { return "" }
    if ($script:sidUserCache.ContainsKey($Sid)) { return $script:sidUserCache[$Sid] }
    $name = ""
    if ($Sid -match '^S-1-(5-21|12-1)-') {
        $profileKey = Open-TriageRegKey -Hive "HKLM" -SubKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
        if ($null -ne $profileKey) {
            try {
                $profilePath = [string]$profileKey.GetValue("ProfileImagePath")
                if ($profilePath) { $name = [IO.Path]::GetFileName($profilePath.TrimEnd('\')) }
            } catch {
                Write-Verbose "Reading ProfileImagePath for ${Sid}: $($_.Exception.Message)"
            } finally {
                $profileKey.Close()
            }
        }
    }
    if (-not $name) {
        try {
            $account = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
            $name = $account -replace '^.*\\', ''
        } catch { Write-Verbose "Translating SID $Sid to an account name: $($_.Exception.Message)" }
    }
    $script:sidUserCache[$Sid] = $name
    return $name
}

# Write rows to a CSV (header only when there are no rows) and record it in the manifest
function Export-TriageCsv {
    [OutputType([void])]
    param(
        [string]$Description,
        [string]$DestPath,
        [string[]]$Columns,
        [object[]]$Rows
    )
    try {
        Ensure-Directory (Split-Path $DestPath -Parent)
        if ($Rows -and $Rows.Count -gt 0) {
            $Rows | Select-Object -Property $Columns |
                Export-Csv -LiteralPath $DestPath -NoTypeInformation -Encoding UTF8 -Force
        } else {
            ('"' + ($Columns -join '","') + '"') | Out-File -LiteralPath $DestPath -Encoding utf8 -Force
        }
        Record-Manifest -SourcePath "(command: $Description)" -DestPath $DestPath
    } catch {
        Log-Error "Failed to collect $Description -- $($_.Exception.Message)"
        $script:errorCount++
    }
}

# BAM (Background Activity Moderator): one row per value whose data starts
# with an 8-byte FILETIME (last execution, UTC)
function Get-TriageBamRows {
    param(
        [string]$Hive = "HKLM",
        [string[]]$KeyPaths = @(
            "SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
            "SYSTEM\CurrentControlSet\Services\bam\UserSettings"
        )
    )
    $rows = @()
    $failedSidKeys = 0
    $lastError = ""
    foreach ($keyPath in $KeyPaths) {
        $rootKey = Open-TriageRegKey -Hive $Hive -SubKey $keyPath
        if ($null -eq $rootKey) { continue }
        try {
            foreach ($sid in $rootKey.GetSubKeyNames()) {
                $sidKey = $null
                try {
                    $sidKey = $rootKey.OpenSubKey($sid, $false)
                    if ($null -eq $sidKey) { continue }
                    $user = Resolve-TriageSidUser $sid
                    foreach ($valueName in $sidKey.GetValueNames()) {
                        if ($valueName -eq "Version" -or $valueName -eq "SequenceNumber") { continue }
                        $data = $sidKey.GetValue($valueName)
                        if ($data -isnot [byte[]] -or $data.Length -lt 8) { continue }
                        $fileTime = [BitConverter]::ToInt64($data, 0)
                        $lastExec = ""
                        if ($fileTime -gt 0) {
                            try { $lastExec = [DateTime]::FromFileTimeUtc($fileTime).ToString("o") } catch { Write-Verbose "Converting BAM FILETIME of ${valueName}: $($_.Exception.Message)" }
                        }
                        $rows += [PSCustomObject]@{
                            Sid              = $sid
                            User             = $user
                            Path             = $valueName
                            LastExecutionUtc = $lastExec
                        }
                    }
                } catch {
                    $failedSidKeys++
                    $lastError = $_.Exception.Message
                } finally {
                    if ($null -ne $sidKey) { $sidKey.Close() }
                }
            }
        } finally {
            $rootKey.Close()
        }
    }
    if ($failedSidKeys -gt 0) {
        Log-Warning "Could not read BAM entries of $failedSidKeys user key(s) -- last error: $lastError"
    }
    return $rows
}

# USB storage disks known to PnP (including devices not currently connected)
# with install / arrival / removal times from the device properties
function Get-TriageUsbStorageRows {
    $rows = @()
    $keyNames = @("DEVPKEY_Device_FirstInstallDate", "DEVPKEY_Device_InstallDate",
        "DEVPKEY_Device_LastArrivalDate", "DEVPKEY_Device_LastRemovalDate")
    $devices = @(Get-PnpDevice -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -like 'USBSTOR\DISK*' } | Sort-Object InstanceId)
    $failedDevices = 0
    $lastError = ""
    foreach ($device in $devices) {
        $times = @{}
        try {
            $props = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName $keyNames -ErrorAction Stop
            foreach ($prop in $props) {
                if ($prop.Data -is [datetime]) {
                    $times[$prop.KeyName] = $prop.Data.ToUniversalTime().ToString("o")
                }
            }
        } catch {
            $failedDevices++
            $lastError = $_.Exception.Message
        }
        # Serial = last instance id segment without the "&<n>" LUN suffix
        $serial = (($device.InstanceId -split '\\')[-1]) -replace '&\d+$', ''
        $rows += [PSCustomObject]@{
            FriendlyName    = [string]$device.FriendlyName
            InstanceId      = [string]$device.InstanceId
            Serial          = $serial
            FirstInstallUtc = [string]$times["DEVPKEY_Device_FirstInstallDate"]
            InstallUtc      = [string]$times["DEVPKEY_Device_InstallDate"]
            LastArrivalUtc  = [string]$times["DEVPKEY_Device_LastArrivalDate"]
            LastRemovalUtc  = [string]$times["DEVPKEY_Device_LastRemovalDate"]
        }
    }
    if ($failedDevices -gt 0) {
        Log-Warning "Could not read PnP install/arrival/removal times of $failedDevices USB storage device(s) -- last error: $lastError"
    }
    return $rows
}

# Task Scheduler time -> UTC "o"; "never" (1999-11-30 or MinValue) or missing -> ""
function Format-TriageTaskTime {
    param($Value)
    if ($null -eq $Value) { return "" }
    try {
        $time = [datetime]$Value
        if ($time.Year -lt 2000) { return "" }
        return $time.ToUniversalTime().ToString("o")
    } catch {
        return ""
    }
}

# Local-time text of the live system (no offset = local) -> UTC "o"; "" if unparseable
function ConvertFrom-TriageLocalTimeText {
    param([string]$Text)
    if (-not $Text) { return "" }
    $parsed = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]"AssumeLocal, AdjustToUniversal"
    if ([datetime]::TryParse($Text.Trim(), [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.ToString("o")
    }
    return ""
}

# All scheduled tasks (including disabled) with run times from Get-ScheduledTaskInfo
function Get-TriageScheduledTaskRows {
    $rows = @()
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
    $failedInfo = 0
    $lastError = ""
    foreach ($task in $tasks) {
        $info = $null
        try {
            $info = Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop
        } catch {
            $failedInfo++
            $lastError = $_.Exception.Message
        }

        # Account the task runs as (group name for group principals)
        $runAs = ""
        if ($task.Principal) {
            if ($task.Principal.UserId) { $runAs = [string]$task.Principal.UserId }
            elseif ($task.Principal.GroupId) { $runAs = [string]$task.Principal.GroupId }
        }

        $actionList = @()
        foreach ($action in $task.Actions) {
            if ($action.Execute) {
                $actionList += ("$($action.Execute) $($action.Arguments)").Trim()
            } elseif ($action.ClassId) {
                $actionList += ("ComHandler $($action.ClassId) $($action.Data)" -replace '\s+', ' ').Trim()
            }
        }
        $triggerList = @()
        foreach ($trigger in $task.Triggers) {
            if ($trigger) { $triggerList += $trigger.ToString() }
        }

        $lastRun = ""
        $nextRun = ""
        $lastResult = ""
        if ($info) {
            $lastRun = Format-TriageTaskTime $info.LastRunTime
            $nextRun = Format-TriageTaskTime $info.NextRunTime
            if ($null -ne $info.LastTaskResult) { $lastResult = [string]$info.LastTaskResult }
        }

        $rows += [PSCustomObject]@{
            TaskName            = [string]$task.TaskName
            TaskPath            = [string]$task.TaskPath
            State               = [string]$task.State
            Author              = [string]$task.Author
            UserId              = $runAs
            Actions             = $actionList -join "; "
            Triggers            = $triggerList -join "; "
            RegistrationDateUtc = ConvertFrom-TriageLocalTimeText ([string]$task.Date)
            LastRunTimeUtc      = $lastRun
            NextRunTimeUtc      = $nextRun
            LastTaskResult      = $lastResult
        }
    }
    if ($failedInfo -gt 0) {
        Log-Warning "Could not read run times (Get-ScheduledTaskInfo) of $failedInfo scheduled task(s) -- last error: $lastError"
    }
    return $rows
}

# Run-key locations, relative to HKLM and to each loaded user hive
$script:triageRunKeyPaths = @(
    "SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)
# Listed in run_keys.txt only (not autostart entries themselves)
$script:triageShellFolderPaths = @(
    "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
)

# HKLM plus every loaded user hive, with display name and user
function Get-TriageRunKeyHives {
    $hives = @([PSCustomObject]@{ Hive = "HKLM"; Base = "HKLM"; Prefix = ""; User = "" })
    foreach ($sid in (Get-TriageLoadedUserSids)) {
        $hives += [PSCustomObject]@{ Hive = "HKU\$sid"; Base = "HKU"; Prefix = "$sid\"; User = (Resolve-TriageSidUser $sid) }
    }
    return $hives
}

# One row per Run-key value (data not environment-expanded)
function Get-TriageRunKeyRows {
    $rows = @()
    foreach ($hive in (Get-TriageRunKeyHives)) {
        foreach ($keyPath in $script:triageRunKeyPaths) {
            $key = Open-TriageRegKey -Hive $hive.Base -SubKey ($hive.Prefix + $keyPath)
            if ($null -eq $key) { continue }
            try {
                $lastWrite = Get-TriageRegLastWriteUtc -Key $key
                foreach ($valueName in $key.GetValueNames()) {
                    $label = $valueName
                    if (-not $label) { $label = "(Default)" }
                    $data = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $rows += [PSCustomObject]@{
                        Hive            = $hive.Hive
                        User            = $hive.User
                        KeyPath         = $keyPath
                        ValueName       = $label
                        Command         = (Format-TriageRegValue $data)
                        KeyLastWriteUtc = $lastWrite
                    }
                }
            } catch {
                # Few iterations (Run-key paths x loaded hives): one warning per key
                Log-Warning "Could not read Run key $($hive.Hive)\$keyPath for run_keys.csv -- $($_.Exception.Message)"
            } finally {
                $key.Close()
            }
        }
    }
    return $rows
}

# Human-readable listing of the Run keys (and Shell Folders) for run_keys.txt
function Get-TriageRunKeyText {
    $keyPaths = $script:triageRunKeyPaths + $script:triageShellFolderPaths
    foreach ($hive in (Get-TriageRunKeyHives)) {
        foreach ($keyPath in $keyPaths) {
            if ($hive.User) {
                Write-Output "=== $($hive.Hive)\$keyPath ($($hive.User)) ==="
            } else {
                Write-Output "=== $($hive.Hive)\$keyPath ==="
            }
            $key = Open-TriageRegKey -Hive $hive.Base -SubKey ($hive.Prefix + $keyPath)
            if ($null -eq $key) {
                Write-Output "(key does not exist)"
            } else {
                try {
                    Write-Output "KeyLastWriteUtc : $(Get-TriageRegLastWriteUtc -Key $key)"
                    $valueNames = @($key.GetValueNames())
                    if ($valueNames.Count -eq 0) { Write-Output "(no values)" }
                    foreach ($valueName in $valueNames) {
                        $label = $valueName
                        if (-not $label) { $label = "(Default)" }
                        $data = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        Write-Output "$label : $(Format-TriageRegValue $data)"
                    }
                } catch {
                    Write-Output "(could not read key: $($_.Exception.Message))"
                } finally {
                    $key.Close()
                }
            }
            Write-Output ""
        }
    }
}

# Startup folders: the all-users folder plus every profile's folder
# (works for the live system and for mounted images)
function Get-TriageStartupFolders {
    $folders = @()
    $folders += [PSCustomObject]@{
        Scope  = "AllUsers"
        User   = ""
        Folder = "${script:TargetRoot}ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    }
    $startupProfiles = Get-ChildItem "${script:TargetRoot}Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }
    foreach ($profileDir in $startupProfiles) {
        $folders += [PSCustomObject]@{
            Scope  = "User"
            User   = $profileDir.Name
            Folder = (Join-Path $profileDir.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
        }
    }
    return $folders
}

# Write startup_folders.txt (for humans) and startup_folders.csv
function Save-TriageStartupFolders {
    [OutputType([void])]
    param([string]$PersistenceDir)

    # List each folder once (hidden items included, desktop.ini skipped)
    $startupListing = @()
    foreach ($startupFolder in (Get-TriageStartupFolders)) {
        $folderExists = Test-Path -LiteralPath $startupFolder.Folder
        $folderItems = @()
        $listError = ""
        if ($folderExists) {
            $listErrors = $null
            $folderItems = @(Get-ChildItem -LiteralPath $startupFolder.Folder -Force -ErrorAction SilentlyContinue -ErrorVariable listErrors |
                Where-Object { $_.Name -ne "desktop.ini" })
            if ($listErrors) {
                $listError = $listErrors[0].Exception.Message
                Log-Warning "Could not list startup folder $($startupFolder.Folder): $listError"
            }
        }
        $startupListing += [PSCustomObject]@{
            Info   = $startupFolder
            Exists = $folderExists
            Items  = $folderItems
            Error  = $listError
        }
    }

    Save-CommandOutput -Description "startup_folders" `
        -DestPath (Join-Path $PersistenceDir "startup_folders.txt") `
        -Command {
            foreach ($listing in $startupListing) {
                Write-Output "=== $($listing.Info.Folder) ==="
                if (-not $listing.Exists) {
                    Write-Output "(path does not exist)"
                } elseif ($listing.Items.Count -gt 0) {
                    $listing.Items | Format-Table Name, CreationTime, LastWriteTime, Length -AutoSize
                } elseif ($listing.Error) {
                    Write-Output "(could not list folder: $($listing.Error))"
                } else {
                    Write-Output "(empty)"
                }
                Write-Output ""
            }
        }

    $startupRows = @()
    foreach ($listing in $startupListing) {
        foreach ($item in $listing.Items) {
            $startupRows += [PSCustomObject]@{
                Scope       = $listing.Info.Scope
                User        = $listing.Info.User
                Folder      = $listing.Info.Folder
                Name        = $item.Name
                CreatedUtc  = $item.CreationTimeUtc.ToString("o")
                ModifiedUtc = $item.LastWriteTimeUtc.ToString("o")
            }
        }
    }
    Export-TriageCsv -Description "startup_folders csv" `
        -DestPath (Join-Path $PersistenceDir "startup_folders.csv") `
        -Columns @("Scope", "User", "Folder", "Name", "CreatedUtc", "ModifiedUtc") `
        -Rows $startupRows
    Log "Startup folders: $($startupRows.Count) item(s) found."
}

# =============================================================
# 4. Execution Artifacts
# =============================================================
if ($Categories -contains "Execution") {
    Log "============================================================="
    Log "  COLLECTING: Execution Artifacts"
    Log "============================================================="
    $execDir = Join-Path $OutputPath "Execution"

    # Prefetch files
    $prefetchDir = Join-Path $execDir "Prefetch"
    Ensure-Directory $prefetchDir
    $prefetchSource = "${script:TargetRoot}Windows\Prefetch"
    if (Test-Path $prefetchSource) {
        Log "Collecting Prefetch files..."
        # -Force here and at the other artifact listings: without it
        # Get-ChildItem silently skips hidden/system files
        $pfFiles = Get-ChildItem -Path $prefetchSource -Filter "*.pf" -Force -ErrorAction SilentlyContinue
        $pfCount = 0
        foreach ($pf in $pfFiles) {
            Copy-ForensicFile -SourcePath $pf.FullName -DestDir $prefetchDir
            $destFile = Join-Path $prefetchDir $pf.Name
            if (Test-Path $destFile) { $pfCount++ }
        }
        Log-Success "Collected $pfCount Prefetch files."
    } else {
        Log-Warning "Prefetch directory not found (may be disabled)."
    }

    if ($script:IsLive) {
        # Recent Apps (per loaded user hive -- export the key where it exists)
        Log "Collecting RecentApps registry data..."
        $recentAppsSubKey = "Software\Microsoft\Windows\CurrentVersion\Search\RecentApps"
        $recentAppsCount = 0
        foreach ($userSid in (Get-TriageLoadedUserSids)) {
            $recentAppsKey = Open-TriageRegKey -Hive "HKU" -SubKey "$userSid\$recentAppsSubKey"
            if ($null -eq $recentAppsKey) { continue }
            $recentAppsKey.Close()
            $recentAppsUser = Resolve-TriageSidUser $userSid
            if (-not $recentAppsUser) { $recentAppsUser = $userSid }
            $recentAppsDir = Join-Path $execDir "RecentApps\$recentAppsUser"
            Ensure-Directory $recentAppsDir
            $regPath = "HKU\$userSid\$recentAppsSubKey"
            $destFile = Join-Path $recentAppsDir "RecentApps.reg"
            reg export $regPath $destFile /y 2>&1 | Out-Null
            if (Test-Path -LiteralPath $destFile) {
                Record-Manifest -SourcePath $regPath -DestPath $destFile
                $recentAppsCount++
            } else {
                # Do not leave an empty folder behind
                try { [IO.Directory]::Delete($recentAppsDir) } catch { Write-Verbose "Removing empty folder ${recentAppsDir}: $($_.Exception.Message)" }
            }
        }
        if ($recentAppsCount -gt 0) {
            Log-Success "Collected RecentApps registry export for $recentAppsCount user(s)."
        } else {
            try { [IO.Directory]::Delete((Join-Path $execDir "RecentApps")) } catch { Write-Verbose "Removing empty RecentApps folder: $($_.Exception.Message)" }
            Log "RecentApps key not found for any loaded user (normal on Windows 11 and recent Windows 10 builds)."
        }

        # BAM (Background Activity Moderator): decode each value's FILETIME into a CSV
        Log "Collecting BAM data..."
        $bamRows = @(Get-TriageBamRows)
        Export-TriageCsv -Description "BAM entries" `
            -DestPath (Join-Path $execDir "bam_entries.csv") `
            -Columns @("Sid", "User", "Path", "LastExecutionUtc") `
            -Rows $bamRows
        if ($bamRows.Count -gt 0) {
            Log-Success "Collected $($bamRows.Count) BAM entries."
        } else {
            Log-Warning "No BAM entries found (bam key missing or not readable)."
        }

        # ShimCache / AppCompatCache
        Log "Collecting AppCompatCache..."
        Save-CommandOutput -Description "AppCompatCache" `
            -DestPath (Join-Path $execDir "appcompat_cache.reg") `
            -Command {
                reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v AppCompatCache 2>&1
            }
    } else {
        Log "Skipping RecentApps, BAM, AppCompatCache (mounted image -- live registry not available)"
    }

    Log-Success "Execution artifacts collection complete."
    Log ""
}

# =============================================================
# 5. Network Artifacts
# =============================================================
if ($Categories -contains "Network") {
    Log "============================================================="
    Log "  COLLECTING: Network Artifacts"
    Log "============================================================="

    if (-not $script:IsLive) {
        Log "Skipping Network artifacts (mounted image -- live network state not applicable)"
        Log ""
    } else {
    $netDir = Join-Path $OutputPath "Network"
    Ensure-Directory $netDir

    Log "Collecting DNS cache..."
    Save-CommandOutput -Description "dns_cache" `
        -DestPath (Join-Path $netDir "dns_cache.txt") `
        -Command { Get-DnsClientCache | Format-Table -AutoSize -Wrap }

    Log "Collecting ARP cache..."
    Save-CommandOutput -Description "arp_cache" `
        -DestPath (Join-Path $netDir "arp_cache.txt") `
        -Command { Get-NetNeighbor | Format-Table -AutoSize -Wrap }

    Log "Collecting netstat..."
    Save-CommandOutput -Description "netstat" `
        -DestPath (Join-Path $netDir "netstat.txt") `
        -Command { netstat -anob 2>&1 }

    Log "Collecting network connections with process info..."
    Save-CommandOutput -Description "tcp_connections" `
        -DestPath (Join-Path $netDir "tcp_connections.csv") `
        -Command {
            Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
                @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
                ConvertTo-Csv -NoTypeInformation
        }

    Log "Collecting network profiles..."
    Save-CommandOutput -Description "network_profiles" `
        -DestPath (Join-Path $netDir "network_profiles.txt") `
        -Command {
            Get-NetConnectionProfile | Format-List
            Write-Output "`n--- Network Adapters ---"
            Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, MacAddress, LinkSpeed -AutoSize
            Write-Output "`n--- IP Configuration ---"
            Get-NetIPConfiguration | Format-List
        }

    Log "Collecting firewall rules..."
    Save-CommandOutput -Description "firewall_rules" `
        -DestPath (Join-Path $netDir "firewall_rules.txt") `
        -Command {
            # Out-String with a wide width: Out-File cuts a table to the
            # console width, which dropped the Direction/Action/Profile columns
            Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue |
                Select-Object DisplayName, Direction, Action, Profile |
                Sort-Object Direction, DisplayName |
                Format-Table -AutoSize |
                Out-String -Width 4096
        }

    Log "Collecting Wi-Fi profiles..."
    Save-CommandOutput -Description "wifi_profiles" `
        -DestPath (Join-Path $netDir "wifi_profiles.txt") `
        -Command { netsh wlan show profiles 2>&1 }

    Log "Collecting network shares..."
    Save-CommandOutput -Description "network_shares" `
        -DestPath (Join-Path $netDir "network_shares.txt") `
        -Command {
            Get-SmbShare -ErrorAction SilentlyContinue | Format-Table -AutoSize
            Write-Output "`n--- Mapped Drives ---"
            Get-SmbMapping -ErrorAction SilentlyContinue | Format-Table -AutoSize
        }

    Log-Success "Network artifacts collection complete."
    Log ""
    } # end if IsLive
}

# =============================================================
# 6. User Activity Artifacts
# =============================================================
if ($Categories -contains "UserActivity") {
    Log "============================================================="
    Log "  COLLECTING: User Activity Artifacts"
    Log "============================================================="
    $uaDir = Join-Path $OutputPath "UserActivity"

    $userProfiles = Get-ChildItem "${script:TargetRoot}Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }

    foreach ($userDir in $userProfiles) {
        $userName = $userDir.Name
        Log "Collecting user activity for: $userName"

        # Recent LNK files
        $recentSource = Join-Path $userDir.FullName "AppData\Roaming\Microsoft\Windows\Recent"
        if (Test-Path $recentSource) {
            $recentDest = Join-Path $uaDir "$userName\RecentFiles"
            Ensure-Directory $recentDest
            $lnkFiles = Get-ChildItem -Path $recentSource -Filter "*.lnk" -Force -ErrorAction SilentlyContinue
            $lnkCount = 0
            foreach ($lnk in $lnkFiles) {
                Copy-ForensicFile -SourcePath $lnk.FullName -DestDir $recentDest
                $destFile = Join-Path $recentDest $lnk.Name
                if (Test-Path $destFile) { $lnkCount++ }
            }
            Log-Success "Collected $lnkCount recent LNK files for $userName"
        }

        # Jump Lists - AutomaticDestinations
        $autoJumpSource = Join-Path $userDir.FullName "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
        if (Test-Path $autoJumpSource) {
            $autoJumpDest = Join-Path $uaDir "$userName\JumpLists\AutomaticDestinations"
            Ensure-Directory $autoJumpDest
            $jlFiles = Get-ChildItem -Path $autoJumpSource -File -Force -ErrorAction SilentlyContinue
            $jlCount = 0
            foreach ($jl in $jlFiles) {
                Copy-ForensicFile -SourcePath $jl.FullName -DestDir $autoJumpDest
                $destFile = Join-Path $autoJumpDest $jl.Name
                if (Test-Path $destFile) { $jlCount++ }
            }
            Log-Success "Collected $jlCount AutomaticDestinations for $userName"
        }

        # Jump Lists - CustomDestinations
        $customJumpSource = Join-Path $userDir.FullName "AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"
        if (Test-Path $customJumpSource) {
            $customJumpDest = Join-Path $uaDir "$userName\JumpLists\CustomDestinations"
            Ensure-Directory $customJumpDest
            $jlFiles = Get-ChildItem -Path $customJumpSource -File -Force -ErrorAction SilentlyContinue
            $jlCount = 0
            foreach ($jl in $jlFiles) {
                Copy-ForensicFile -SourcePath $jl.FullName -DestDir $customJumpDest
                $destFile = Join-Path $customJumpDest $jl.Name
                if (Test-Path $destFile) { $jlCount++ }
            }
            Log-Success "Collected $jlCount CustomDestinations for $userName"
        }

        # ShellBags note
        $shellBagDir = Join-Path $uaDir "$userName\ShellBags"
        Ensure-Directory $shellBagDir
        "ShellBag data is stored in UsrClass.dat, collected in the Registry/ directory." |
            Out-File -FilePath (Join-Path $shellBagDir "_see_registry_usrclass.dat.txt") -Encoding utf8

        # PowerShell console history
        $psHistoryPath = Join-Path $userDir.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $psHistoryPath) {
            $psHistDest = Join-Path $uaDir "$userName"
            Copy-ForensicFile -SourcePath $psHistoryPath -DestDir $psHistDest -DestName "ConsoleHost_history.txt"
            Log-Success "Collected PowerShell history for $userName"
        }
    }

    Log-Success "User Activity collection complete."
    Log ""
}

# ----------------------------------------------------------
# Helper for the Browser section: current Chromium-based browsers
# (Chrome 96+, Edge, Brave, Vivaldi, Opera) keep cookies in
# <profile>\Network\Cookies; the profile-root "Cookies" is the legacy
# location. Copied (with its journal, if present) to <dest>\Network\.
# ----------------------------------------------------------
function Copy-TriageChromiumNetworkCookies {
    [OutputType([void])]
    param(
        [string]$ProfileDir,
        [string]$DestDir
    )
    foreach ($cookieFile in @("Cookies", "Cookies-journal")) {
        $sourcePath = Join-Path $ProfileDir "Network\$cookieFile"
        if (Test-Path -LiteralPath $sourcePath) {
            Copy-ForensicFile -SourcePath $sourcePath -DestDir (Join-Path $DestDir "Network") -DestName $cookieFile
        }
    }
}

# =============================================================
# 7. Browser Artifacts
# =============================================================
if ($Categories -contains "Browser") {
    Log "============================================================="
    Log "  COLLECTING: Browser Artifacts"
    Log "============================================================="
    $browserDir = Join-Path $OutputPath "Browser"

    $userProfiles = Get-ChildItem "${script:TargetRoot}Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }

    foreach ($userDir in $userProfiles) {
        $userName = $userDir.Name

        # Chrome
        $chromeBase = Join-Path $userDir.FullName "AppData\Local\Google\Chrome\User Data"
        if (Test-Path -LiteralPath $chromeBase) {
            Log "Collecting Chrome data for $userName..."
            # Collect from Default and any numbered profiles
            $chromeProfiles = Get-ChildItem -Path $chromeBase -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" }

            foreach ($browserProfile in $chromeProfiles) {
                $destDir = Join-Path $browserDir "$userName\Chrome\$($browserProfile.Name)"
                # History-journal: SQLite rollback journal (collected when present).
                # Files locked by a running browser are read from the shadow copy
                # (see Copy-ForensicFile).
                $chromeFiles = @("History", "History-journal", "Bookmarks", "Login Data", "Cookies", "Web Data", "Top Sites", "Shortcuts")
                foreach ($cf in $chromeFiles) {
                    $sourcePath = Join-Path $browserProfile.FullName $cf
                    if (Test-Path -LiteralPath $sourcePath) {
                        Copy-ForensicFile -SourcePath $sourcePath -DestDir $destDir -DestName $cf
                    }
                }
                Copy-TriageChromiumNetworkCookies -ProfileDir $browserProfile.FullName -DestDir $destDir
            }
            Log-Success "Collected Chrome artifacts for $userName"
        }

        # Edge (Chromium-based, same structure as Chrome)
        $edgeBase = Join-Path $userDir.FullName "AppData\Local\Microsoft\Edge\User Data"
        if (Test-Path -LiteralPath $edgeBase) {
            Log "Collecting Edge data for $userName..."
            $edgeProfiles = Get-ChildItem -Path $edgeBase -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" }

            foreach ($browserProfile in $edgeProfiles) {
                $destDir = Join-Path $browserDir "$userName\Edge\$($browserProfile.Name)"
                $edgeFiles = @("History", "History-journal", "Bookmarks", "Login Data", "Cookies", "Web Data", "Top Sites", "Shortcuts")
                foreach ($ef in $edgeFiles) {
                    $sourcePath = Join-Path $browserProfile.FullName $ef
                    if (Test-Path -LiteralPath $sourcePath) {
                        Copy-ForensicFile -SourcePath $sourcePath -DestDir $destDir -DestName $ef
                    }
                }
                Copy-TriageChromiumNetworkCookies -ProfileDir $browserProfile.FullName -DestDir $destDir
            }
            Log-Success "Collected Edge artifacts for $userName"
        }

        # Brave (Chromium-based)
        $braveBase = Join-Path $userDir.FullName "AppData\Local\BraveSoftware\Brave-Browser\User Data"
        if (Test-Path -LiteralPath $braveBase) {
            Log "Collecting Brave data for $userName..."
            $braveProfiles = Get-ChildItem -Path $braveBase -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" }

            foreach ($browserProfile in $braveProfiles) {
                $destDir = Join-Path $browserDir "$userName\Brave\$($browserProfile.Name)"
                $braveFiles = @("History", "History-journal", "Bookmarks", "Login Data", "Cookies", "Web Data", "Top Sites", "Shortcuts")
                foreach ($bf in $braveFiles) {
                    $sourcePath = Join-Path $browserProfile.FullName $bf
                    if (Test-Path -LiteralPath $sourcePath) {
                        Copy-ForensicFile -SourcePath $sourcePath -DestDir $destDir -DestName $bf
                    }
                }
                Copy-TriageChromiumNetworkCookies -ProfileDir $browserProfile.FullName -DestDir $destDir
            }
            Log-Success "Collected Brave artifacts for $userName"
        }

        # Opera (Chromium-based, slightly different path)
        $operaPaths = @(
            (Join-Path $userDir.FullName "AppData\Roaming\Opera Software\Opera Stable"),
            (Join-Path $userDir.FullName "AppData\Roaming\Opera Software\Opera GX Stable")
        )
        foreach ($operaBase in $operaPaths) {
            if (Test-Path -LiteralPath $operaBase) {
                $operaName = if ($operaBase -match "GX") { "OperaGX" } else { "Opera" }
                Log "Collecting $operaName data for $userName..."
                $destDir = Join-Path $browserDir "$userName\$operaName"
                $operaFiles = @("History", "History-journal", "Bookmarks", "Login Data", "Cookies", "Web Data", "Top Sites", "Shortcuts")
                foreach ($of in $operaFiles) {
                    $sourcePath = Join-Path $operaBase $of
                    if (Test-Path -LiteralPath $sourcePath) {
                        Copy-ForensicFile -SourcePath $sourcePath -DestDir $destDir -DestName $of
                    }
                }
                Copy-TriageChromiumNetworkCookies -ProfileDir $operaBase -DestDir $destDir
                Log-Success "Collected $operaName artifacts for $userName"
            }
        }

        # Vivaldi (Chromium-based)
        $vivaldiBase = Join-Path $userDir.FullName "AppData\Local\Vivaldi\User Data"
        if (Test-Path -LiteralPath $vivaldiBase) {
            Log "Collecting Vivaldi data for $userName..."
            $vivaldiProfiles = Get-ChildItem -Path $vivaldiBase -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" }

            foreach ($browserProfile in $vivaldiProfiles) {
                $destDir = Join-Path $browserDir "$userName\Vivaldi\$($browserProfile.Name)"
                $vivaldiFiles = @("History", "History-journal", "Bookmarks", "Login Data", "Cookies", "Web Data", "Top Sites", "Shortcuts")
                foreach ($vf in $vivaldiFiles) {
                    $sourcePath = Join-Path $browserProfile.FullName $vf
                    if (Test-Path -LiteralPath $sourcePath) {
                        Copy-ForensicFile -SourcePath $sourcePath -DestDir $destDir -DestName $vf
                    }
                }
                Copy-TriageChromiumNetworkCookies -ProfileDir $browserProfile.FullName -DestDir $destDir
            }
            Log-Success "Collected Vivaldi artifacts for $userName"
        }

        # Firefox
        $firefoxBase = Join-Path $userDir.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"
        if (Test-Path -LiteralPath $firefoxBase) {
            Log "Collecting Firefox data for $userName..."
            $ffProfiles = Get-ChildItem -Path $firefoxBase -Directory -Force -ErrorAction SilentlyContinue

            foreach ($browserProfile in $ffProfiles) {
                $destDir = Join-Path $browserDir "$userName\Firefox\$($browserProfile.Name)"
                # *-wal: SQLite write-ahead logs with the most recent rows (not
                # yet merged into the database); collected when present
                $ffFiles = @("places.sqlite", "places.sqlite-wal", "logins.json", "cookies.sqlite", "cookies.sqlite-wal", "formhistory.sqlite", "formhistory.sqlite-wal", "permissions.sqlite", "key4.db")
                foreach ($ff in $ffFiles) {
                    $sourcePath = Join-Path $browserProfile.FullName $ff
                    if (Test-Path -LiteralPath $sourcePath) {
                        Copy-ForensicFile -SourcePath $sourcePath -DestDir $destDir -DestName $ff
                    }
                }
            }
            Log-Success "Collected Firefox artifacts for $userName"
        }
    }

    Log-Success "Browser artifacts collection complete."
    Log ""
}

# =============================================================
# 8. USB Artifacts
# =============================================================
if ($Categories -contains "USB") {
    Log "============================================================="
    Log "  COLLECTING: USB Artifacts"
    Log "============================================================="
    $usbDir = Join-Path $OutputPath "USB"
    Ensure-Directory $usbDir

    # setupapi device logs: setupapi.dev.log plus the rotated
    # setupapi.dev.<yyyymmdd_hhmmss>.log files (original names kept)
    $infDir = "${script:TargetRoot}Windows\INF"
    $setupapiLogs = @(Get-ChildItem -LiteralPath $infDir -Filter "setupapi.dev*.log" -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "setupapi.dev*.log" } | Sort-Object Name)
    if ($setupapiLogs.Count -gt 0) {
        Log "Collecting $($setupapiLogs.Count) setupapi device log(s)..."
        $setupapiCount = 0
        foreach ($setupapiLog in $setupapiLogs) {
            Copy-ForensicFile -SourcePath $setupapiLog.FullName -DestDir $usbDir
            if (Test-Path -LiteralPath (Join-Path $usbDir $setupapiLog.Name)) { $setupapiCount++ }
        }
        Log-Success "Collected $setupapiCount setupapi device log(s): $(($setupapiLogs | ForEach-Object { $_.Name }) -join ', ')"
    } else {
        Log-Warning "No setupapi.dev*.log found in $infDir"
    }

    # USB device registry entries (live system only -- queries live HKLM registry)
    if ($script:IsLive) {
        Log "Collecting USB device registry info..."
        Save-CommandOutput -Description "USB storage devices" `
            -DestPath (Join-Path $usbDir "usb_storage_devices.txt") `
            -Command {
                Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue |
                    Select-Object FriendlyName, HardwareID, Mfg, Service, ContainerID, PSChildName |
                    Format-List
            }

        # USB storage disks with PnP first-install / arrival / removal times
        # (includes devices that are not currently connected)
        Log "Collecting USB storage device PnP timestamps..."
        if (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) {
            $usbStorageRows = @(Get-TriageUsbStorageRows)
            Export-TriageCsv -Description "USB storage devices (PnP properties)" `
                -DestPath (Join-Path $usbDir "usb_storage_devices.csv") `
                -Columns @("FriendlyName", "InstanceId", "Serial", "FirstInstallUtc", "InstallUtc", "LastArrivalUtc", "LastRemovalUtc") `
                -Rows $usbStorageRows
            Log-Success "Collected PnP timestamps for $($usbStorageRows.Count) USB storage device(s)."
        } else {
            Log-Warning "Get-PnpDevice not available -- usb_storage_devices.csv not collected."
        }

        Save-CommandOutput -Description "USB devices" `
            -DestPath (Join-Path $usbDir "usb_devices.txt") `
            -Command {
                Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\*" -ErrorAction SilentlyContinue |
                    Select-Object DeviceDesc, HardwareID, Mfg, Service, PSChildName |
                    Format-List
            }

        # MountedDevices
        Save-CommandOutput -Description "Mounted devices" `
            -DestPath (Join-Path $usbDir "mounted_devices.txt") `
            -Command {
                Get-ItemProperty "HKLM:\SYSTEM\MountedDevices" -ErrorAction SilentlyContinue | Format-List
            }
    } else {
        Log "Skipping USB registry queries (mounted image -- use collected SYSTEM hive for USB analysis)"
    }

    Log-Success "USB artifacts collection complete."
    Log ""
}

# =============================================================
# 9. Persistence Artifacts
# =============================================================
if ($Categories -contains "Persistence") {
    Log "============================================================="
    Log "  COLLECTING: Persistence Artifacts"
    Log "============================================================="
    $persDir = Join-Path $OutputPath "Persistence"
    Ensure-Directory $persDir

    if ($script:IsLive) {
        # Scheduled Tasks (live system only) -- all tasks, including disabled ones
        Log "Collecting scheduled tasks..."
        $taskRows = @(Get-TriageScheduledTaskRows)
        Export-TriageCsv -Description "scheduled_tasks" `
            -DestPath (Join-Path $persDir "scheduled_tasks.csv") `
            -Columns @("TaskName", "TaskPath", "State", "Author", "UserId", "Actions", "Triggers",
                "RegistrationDateUtc", "LastRunTimeUtc", "NextRunTimeUtc", "LastTaskResult") `
            -Rows $taskRows
        Log "Scheduled tasks: $($taskRows.Count) task(s) found."

        # Services (KeyLastWriteUtc = last-write time of the service's registry key)
        Log "Collecting services..."
        Save-CommandOutput -Description "services" `
            -DestPath (Join-Path $persDir "services.csv") `
            -Command {
                Get-CimInstance Win32_Service |
                    Select-Object Name, DisplayName, State, StartMode, PathName, StartName, Description,
                        @{Name='KeyLastWriteUtc';Expression={ Get-TriageServiceKeyLastWriteUtc $_.Name }} |
                    ConvertTo-Csv -NoTypeInformation
            }

        # Startup entries
        Log "Collecting startup entries..."
        Save-CommandOutput -Description "startup_entries" `
            -DestPath (Join-Path $persDir "startup_entries.csv") `
            -Command {
                Get-CimInstance Win32_StartupCommand |
                    Select-Object Name, Command, Location, User |
                    ConvertTo-Csv -NoTypeInformation
            }

        # Run / RunOnce keys: HKLM plus every loaded user hive (not only the
        # account running the collector)
        Log "Collecting Run/RunOnce registry keys..."
        Save-CommandOutput -Description "run_keys" `
            -DestPath (Join-Path $persDir "run_keys.txt") `
            -Command { Get-TriageRunKeyText }
        $runKeyRows = @(Get-TriageRunKeyRows)
        Export-TriageCsv -Description "run_keys csv" `
            -DestPath (Join-Path $persDir "run_keys.csv") `
            -Columns @("Hive", "User", "KeyPath", "ValueName", "Command", "KeyLastWriteUtc") `
            -Rows $runKeyRows
        Log "Run keys: $($runKeyRows.Count) value(s) in HKLM and $(@(Get-TriageLoadedUserSids).Count) loaded user hive(s)."

        # Startup folder contents (all-users folder + every user profile)
        Log "Collecting startup folders..."
        Save-TriageStartupFolders -PersistenceDir $persDir

        # WMI Event Subscriptions (persistence mechanism)
        Log "Collecting WMI event subscriptions..."
        Save-CommandOutput -Description "wmi_subscriptions" `
            -DestPath (Join-Path $persDir "wmi_subscriptions.csv") `
            -Command {
                $filters = Get-CimInstance -Namespace "root\subscription" -ClassName __EventFilter -ErrorAction SilentlyContinue
                $consumers = Get-CimInstance -Namespace "root\subscription" -ClassName __EventConsumer -ErrorAction SilentlyContinue
                $bindings = Get-CimInstance -Namespace "root\subscription" -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue

                $results = @()
                foreach ($binding in $bindings) {
                    # CIM returns Filter/Consumer as instance references: write them
                    # as WMI paths, e.g. __EventFilter.Name="SCM Event Log Filter"
                    $filterRef = ""
                    $consumerRef = ""
                    if ($binding.Filter) { $filterRef = '{0}.Name="{1}"' -f $binding.Filter.CimClass.CimClassName, $binding.Filter.Name }
                    if ($binding.Consumer) { $consumerRef = '{0}.Name="{1}"' -f $binding.Consumer.CimClass.CimClassName, $binding.Consumer.Name }
                    $results += [PSCustomObject]@{
                        Type     = "Binding"
                        Filter   = $filterRef
                        Consumer = $consumerRef
                        Details  = ""
                    }
                }
                foreach ($filter in $filters) {
                    $results += [PSCustomObject]@{
                        Type     = "Filter"
                        Filter   = $filter.Name
                        Consumer = ""
                        Details  = $filter.Query
                    }
                }
                foreach ($consumer in $consumers) {
                    $results += [PSCustomObject]@{
                        Type     = "Consumer"
                        Filter   = ""
                        Consumer = $consumer.Name
                        Details  = ($consumer | Select-Object * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties | Out-String).Trim()
                    }
                }
                if ($results.Count -eq 0) {
                    Write-Output "No WMI event subscriptions found."
                } else {
                    $results | ConvertTo-Csv -NoTypeInformation
                }
            }

        # Drivers (unsigned or suspicious)
        Log "Collecting driver info..."
        Save-CommandOutput -Description "drivers" `
            -DestPath (Join-Path $persDir "drivers.csv") `
            -Command {
                Get-CimInstance -ClassName Win32_SystemDriver |
                    Select-Object Name, DisplayName, PathName, State, StartMode, ServiceType,
                        @{Name='KeyLastWriteUtc';Expression={ Get-TriageServiceKeyLastWriteUtc $_.Name }} |
                    ConvertTo-Csv -NoTypeInformation
            }

        # DLL search order hijack check - common directories
        Log "Collecting loaded DLLs info..."
        Save-CommandOutput -Description "loaded_dlls" `
            -DestPath (Join-Path $persDir "loaded_dlls_suspicious.txt") `
            -Command {
                Get-Process -ErrorAction SilentlyContinue |
                    Where-Object { $_.Modules } |
                    ForEach-Object {
                        $proc = $_
                        $_.Modules | Where-Object { $_.FileName -and $_.FileName -notlike "${script:TargetRoot}Windows\*" -and $_.FileName -notlike "${script:TargetRoot}Program Files*" } |
                            Select-Object @{Name='ProcessName';Expression={$proc.ProcessName}},
                                @{Name='PID';Expression={$proc.Id}},
                                FileName
                    } | Format-Table -AutoSize -Wrap
            }
    } else {
        # Mounted image: collect file-based persistence artifacts
        Log "Collecting persistence artifacts from mounted image (file-based only)..."

        # Scheduled task XML definitions
        $taskSourceDir = "${script:TargetRoot}Windows\System32\Tasks"
        if (Test-Path $taskSourceDir) {
            Log "Collecting scheduled task XML files..."
            $taskDestDir = Join-Path $persDir "ScheduledTasks_XML"
            Ensure-Directory $taskDestDir
            # -Recurse -Force is safe here: the Tasks folder has no junctions
            $taskFiles = Get-ChildItem -Path $taskSourceDir -File -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 0 } | Select-Object -First 200
            $taskCount = 0
            foreach ($tf in $taskFiles) {
                Copy-ForensicFile -SourcePath $tf.FullName -DestDir $taskDestDir -DestName $tf.Name
                if (Test-Path (Join-Path $taskDestDir $tf.Name)) { $taskCount++ }
            }
            Log-Success "Collected $taskCount scheduled task XML file(s)."
        }

        # Startup folders from mounted image (all-users folder + every user profile)
        Log "Collecting startup folders..."
        Save-TriageStartupFolders -PersistenceDir $persDir

        Log "Skipping live-only persistence checks (services, WMI, drivers, DLLs, Run keys)"
    }

    Log-Success "Persistence artifacts collection complete."
    Log ""
}

# =============================================================
# 10. AntiVirus / Endpoint Security Logs
# =============================================================
if ($Categories -contains "AntiVirus") {
    Log "============================================================="
    Log "  COLLECTING: AntiVirus / Endpoint Security Logs"
    Log "============================================================="
    $avDir = Join-Path $OutputPath "AntiVirus"
    Ensure-Directory $avDir

    # --- Detect installed AV products via WMI (live only) ---
    if ($script:IsLive) {
        Log "Detecting installed antivirus products..."
        Save-CommandOutput -Description "installed_av_products" `
            -DestPath (Join-Path $avDir "installed_av_products.txt") `
            -Command {
                try {
                    $avProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
                    foreach ($av in $avProducts) {
                        Write-Output "=== $($av.displayName) ==="
                        Write-Output "  Instance GUID : $($av.instanceGuid)"
                        Write-Output "  Product State  : $($av.productState)"
                        Write-Output "  Path           : $($av.pathToSignedProductExe)"
                        Write-Output "  Reporting Path : $($av.pathToSignedReportingExe)"
                        Write-Output ""
                    }
                }
                catch {
                    Write-Output "Could not query SecurityCenter2 (may not be available on server OS)."
                }
            }

        # --- Windows Defender live queries ---
        Log "Collecting Windows Defender logs and status..."

        Save-CommandOutput -Description "defender_detection_history" `
            -DestPath (Join-Path $avDir "defender_detections.csv") `
            -Command {
                try {
                    Get-MpThreatDetection -ErrorAction Stop |
                        Select-Object DetectionID, ThreatID, ThreatName,
                            @{Name='DomainUser';Expression={$_.DomainUser -join '; '}},
                            @{Name='ProcessName';Expression={$_.ProcessName -join '; '}},
                            @{Name='Resources';Expression={($_.Resources | Select-Object -First 5) -join '; '}},
                            InitialDetectionTime, LastThreatStatusChangeTime, RemediationTime,
                            ThreatStatusID, AdditionalActionsBitMask |
                        ConvertTo-Csv -NoTypeInformation
                }
                catch {
                    Write-Output "No Defender threat detections found or Defender not available."
                }
            }

        Save-CommandOutput -Description "defender_threat_catalog" `
            -DestPath (Join-Path $avDir "defender_threats.csv") `
            -Command {
                try {
                    Get-MpThreat -ErrorAction Stop |
                        Select-Object ThreatID, ThreatName, SeverityID, CategoryID, IsActive,
                            @{Name='Resources';Expression={($_.Resources | Select-Object -First 5) -join '; '}} |
                        ConvertTo-Csv -NoTypeInformation
                }
                catch {
                    Write-Output "No Defender threat history found or Defender not available."
                }
            }

        Save-CommandOutput -Description "defender_status" `
            -DestPath (Join-Path $avDir "defender_status.txt") `
            -Command {
                try {
                    Get-MpComputerStatus -ErrorAction Stop | Format-List
                }
                catch {
                    Write-Output "Could not query Defender status."
                }
            }

        Save-CommandOutput -Description "defender_preferences" `
            -DestPath (Join-Path $avDir "defender_preferences.txt") `
            -Command {
                try {
                    Get-MpPreference -ErrorAction Stop | Format-List
                }
                catch {
                    Write-Output "Could not query Defender preferences."
                }
            }
    } else {
        Log "Skipping AV live queries (mounted image -- WMI/Defender cmdlets not applicable)"
    }

    # Defender support logs and the third-party AV logs below are listed with
    # -Force (hidden/system log files too). The -Recurse walks start inside the
    # vendor's own folder, so they never reach the "Application Data"-style
    # junctions of ProgramData or user profiles (which Windows PowerShell 5.1
    # would follow with -Force, looping)
    $defenderSupportDir = "${script:TargetRoot}ProgramData\Microsoft\Windows Defender\Support"
    if (Test-Path $defenderSupportDir) {
        Log "Collecting Defender support logs..."
        $defenderDestDir = Join-Path $avDir "Defender"
        Ensure-Directory $defenderDestDir
        $defenderLogs = Get-ChildItem -Path $defenderSupportDir -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".log", ".txt", ".etl" -and $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 10
        foreach ($dl in $defenderLogs) {
            Copy-ForensicFile -SourcePath $dl.FullName -DestDir $defenderDestDir
        }
        Log-Success "Collected $($defenderLogs.Count) Defender support log(s)."
    }

    # --- Symantec Endpoint Protection ---
    # SEP 12+ (CurrentVersion\Data\Logs) and SEP 11 (Logs). The daily AV scan
    # logs (AV\*.Log, parsed by the timeline builder) are always collected;
    # the other logs: newest 20.
    $sepLogDirs = @(
        "${script:TargetRoot}ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs",
        "${script:TargetRoot}ProgramData\Symantec\Symantec Endpoint Protection\Logs"
    ) | Where-Object { Test-Path -LiteralPath $_ }
    if ($sepLogDirs) {
        Log "Detected Symantec Endpoint Protection -- collecting logs..."
        $sepDestDir = Join-Path $avDir "Symantec_SEP"
        Ensure-Directory $sepDestDir
        $sepAll = @(Get-ChildItem -LiteralPath $sepLogDirs -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 })
        $sepAvLogs = @($sepAll | Where-Object { $_.Directory.Name -eq "AV" -and $_.Extension -eq ".log" })
        $sepOther = @($sepAll | Where-Object { -not ($_.Directory.Name -eq "AV" -and $_.Extension -eq ".log") } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20)
        $sepLogs = @($sepAvLogs) + @($sepOther)
        foreach ($sl in $sepLogs) {
            Copy-ForensicFile -SourcePath $sl.FullName -DestDir $sepDestDir
        }
        Log-Success "Collected $($sepLogs.Count) Symantec SEP log(s) ($($sepAvLogs.Count) daily AV log(s))."
    }

    # Symantec event logs
    $sepEvtLog = "Symantec Endpoint Protection Client"
    $sepEvtPath = Join-Path "${script:TargetRoot}Windows\System32\winevt\Logs" "$sepEvtLog.evtx"
    if (Test-Path $sepEvtPath) {
        Log "Collecting Symantec event log..."
        $destFile = Join-Path $avDir "Symantec_SEP_EventLog.evtx"
        if ($script:IsLive) {
            try {
                wevtutil epl $sepEvtLog $destFile 2>&1 | Out-Null
                if (Test-Path $destFile) {
                    Record-Manifest -SourcePath $sepEvtPath -DestPath $destFile
                    Log-Success "Collected Symantec event log."
                }
            }
            catch { Log-Warning "Could not collect Symantec event log." }
        } else {
            Copy-ForensicFile -SourcePath $sepEvtPath -DestDir $avDir -DestName "Symantec_SEP_EventLog.evtx"
            if (Test-Path $destFile) { Log-Success "Collected Symantec event log (file copy)." }
        }
    }

    # --- CrowdStrike Falcon ---
    $csLogDir = "${script:TargetRoot}Windows\System32\drivers\CrowdStrike"
    $csDataDir = "${script:TargetRoot}ProgramData\CrowdStrike"
    if ((Test-Path $csLogDir) -or (Test-Path $csDataDir)) {
        Log "Detected CrowdStrike Falcon -- collecting logs..."
        $csDestDir = Join-Path $avDir "CrowdStrike"
        Ensure-Directory $csDestDir
        foreach ($csDir in @($csLogDir, $csDataDir)) {
            if (Test-Path $csDir) {
                $csLogs = Get-ChildItem -Path $csDir -File -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in ".log", ".txt", ".etl", ".csv" -and $_.Length -gt 0 } |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 20
                foreach ($cl in $csLogs) {
                    Copy-ForensicFile -SourcePath $cl.FullName -DestDir $csDestDir
                }
            }
        }
        Log-Success "Collected CrowdStrike log(s)."
    }

    # CrowdStrike event log
    $csEvtLog = "CrowdStrike-Falcon/Operational"
    $csEvtPath = Join-Path "${script:TargetRoot}Windows\System32\winevt\Logs" "CrowdStrike-Falcon%4Operational.evtx"
    if (Test-Path $csEvtPath) {
        Log "Collecting CrowdStrike event log..."
        $destFile = Join-Path $avDir "CrowdStrike_EventLog.evtx"
        if ($script:IsLive) {
            try {
                wevtutil epl $csEvtLog $destFile 2>&1 | Out-Null
                if (Test-Path $destFile) {
                    Record-Manifest -SourcePath $csEvtPath -DestPath $destFile
                    Log-Success "Collected CrowdStrike event log."
                }
            }
            catch { Log-Warning "Could not collect CrowdStrike event log." }
        } else {
            Copy-ForensicFile -SourcePath $csEvtPath -DestDir $avDir -DestName "CrowdStrike_EventLog.evtx"
            if (Test-Path $destFile) { Log-Success "Collected CrowdStrike event log (file copy)." }
        }
    }

    # --- SentinelOne ---
    $s1LogDir = "${script:TargetRoot}ProgramData\Sentinel\SentinelAgent\Logs"
    if (Test-Path $s1LogDir) {
        Log "Detected SentinelOne -- collecting logs..."
        $s1DestDir = Join-Path $avDir "SentinelOne"
        Ensure-Directory $s1DestDir
        $s1Logs = Get-ChildItem -Path $s1LogDir -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($sl in $s1Logs) {
            Copy-ForensicFile -SourcePath $sl.FullName -DestDir $s1DestDir
        }
        Log-Success "Collected $($s1Logs.Count) SentinelOne log(s)."
    }

    # --- Carbon Black ---
    $cbLogDir = "${script:TargetRoot}ProgramData\CarbonBlack\Logs"
    if (Test-Path $cbLogDir) {
        Log "Detected Carbon Black -- collecting logs..."
        $cbDestDir = Join-Path $avDir "CarbonBlack"
        Ensure-Directory $cbDestDir
        $cbLogs = Get-ChildItem -Path $cbLogDir -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($cl in $cbLogs) {
            Copy-ForensicFile -SourcePath $cl.FullName -DestDir $cbDestDir
        }
        Log-Success "Collected $($cbLogs.Count) Carbon Black log(s)."
    }

    # --- Malwarebytes ---
    $mbLogDir = "${script:TargetRoot}ProgramData\Malwarebytes\MBAMService\Logs"
    if (Test-Path $mbLogDir) {
        Log "Detected Malwarebytes -- collecting logs..."
        $mbDestDir = Join-Path $avDir "Malwarebytes"
        Ensure-Directory $mbDestDir
        $mbLogs = Get-ChildItem -Path $mbLogDir -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($ml in $mbLogs) {
            Copy-ForensicFile -SourcePath $ml.FullName -DestDir $mbDestDir
        }
        Log-Success "Collected $($mbLogs.Count) Malwarebytes log(s)."
    }

    # --- Sophos ---
    $sophosLogDir = "${script:TargetRoot}ProgramData\Sophos"
    if (Test-Path $sophosLogDir) {
        Log "Detected Sophos -- collecting logs..."
        $sophosDestDir = Join-Path $avDir "Sophos"
        Ensure-Directory $sophosDestDir
        $sophosAll = @(Get-ChildItem -Path $sophosLogDir -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".log", ".txt", ".xml", ".csv" -and $_.Length -gt 0 })
        # Sophos Anti-Virus detection log (SAV.txt, parsed by the timeline
        # builder) always; everything else: newest 20
        $sophosKey = @($sophosAll | Where-Object { $_.Name -like "SAV*.txt" })
        $sophosOther = @($sophosAll | Where-Object { $_.Name -notlike "SAV*.txt" } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20)
        $sophosLogs = @($sophosKey) + @($sophosOther)
        foreach ($sl in $sophosLogs) {
            Copy-ForensicFile -SourcePath $sl.FullName -DestDir $sophosDestDir
        }
        Log-Success "Collected $($sophosLogs.Count) Sophos log(s)."
    }

    # --- ESET ---
    # Every ESET product keeps its logs in ProgramData\ESET\<product>\Logs
    # (ESET Security, NOD32 Antivirus, Smart/Internet Security, Endpoint
    # Antivirus/Security, File/Server Security, ...). Each product goes to its
    # own subfolder; virlog.dat (detections) is always collected.
    $esetProductDirs = @(Get-ChildItem -LiteralPath "${script:TargetRoot}ProgramData\ESET" -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "Logs") })
    if ($esetProductDirs.Count -gt 0) {
        Log "Detected ESET ($(($esetProductDirs | ForEach-Object { $_.Name }) -join ', ')) -- collecting logs..."
        $esetCount = 0
        foreach ($esetProduct in $esetProductDirs) {
            $esetDestDir = Join-Path $avDir "ESET\$($esetProduct.Name)"
            Ensure-Directory $esetDestDir
            $esetAll = @(Get-ChildItem -LiteralPath (Join-Path $esetProduct.FullName "Logs") -File -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 0 })
            $esetKey = @($esetAll | Where-Object { $_.Name -like "virlog*.dat" })
            $esetOther = @($esetAll | Where-Object { $_.Name -notlike "virlog*.dat" } |
                Sort-Object LastWriteTime -Descending | Select-Object -First 20)
            foreach ($el in (@($esetKey) + @($esetOther))) {
                Copy-ForensicFile -SourcePath $el.FullName -DestDir $esetDestDir
                $esetCount++
            }
        }
        Log-Success "Collected $esetCount ESET log(s)."
    }

    # --- Kaspersky ---
    $kaspLogDir = "${script:TargetRoot}ProgramData\Kaspersky Lab"
    if (Test-Path $kaspLogDir) {
        Log "Detected Kaspersky -- collecting logs..."
        $kaspDestDir = Join-Path $avDir "Kaspersky"
        Ensure-Directory $kaspDestDir
        $kaspLogs = Get-ChildItem -Path $kaspLogDir -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".log", ".txt", ".rpt", ".csv" -and $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($kl in $kaspLogs) {
            Copy-ForensicFile -SourcePath $kl.FullName -DestDir $kaspDestDir
        }
        Log-Success "Collected $($kaspLogs.Count) Kaspersky log(s)."
    }

    # --- McAfee / Trellix ---
    # Both folders are checked (Trellix-branded products can sit next to
    # older McAfee ones). VirusScan logs in DesktopProtection\ (incl.
    # AccessProtectionLog.txt, parsed by the timeline builder) always;
    # everything else: newest 20.
    $mcafeeLogDirs = @(
        "${script:TargetRoot}ProgramData\McAfee",
        "${script:TargetRoot}ProgramData\Trellix"
    ) | Where-Object { Test-Path -LiteralPath $_ }
    if ($mcafeeLogDirs) {
        Log "Detected McAfee/Trellix -- collecting logs..."
        $mcafeeDestDir = Join-Path $avDir "McAfee_Trellix"
        Ensure-Directory $mcafeeDestDir
        $mcafeeAll = @(Get-ChildItem -LiteralPath $mcafeeLogDirs -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".log", ".txt", ".csv" -and $_.Length -gt 0 })
        $mcafeeKey = @($mcafeeAll | Where-Object { $_.Directory.Name -eq "DesktopProtection" })
        $mcafeeOther = @($mcafeeAll | Where-Object { $_.Directory.Name -ne "DesktopProtection" } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20)
        $mcafeeLogs = @($mcafeeKey) + @($mcafeeOther)
        foreach ($ml in $mcafeeLogs) {
            Copy-ForensicFile -SourcePath $ml.FullName -DestDir $mcafeeDestDir
        }
        Log-Success "Collected $($mcafeeLogs.Count) McAfee/Trellix log(s)."
    }

    # --- Bitdefender ---
    $bdLogDir = "${script:TargetRoot}ProgramData\Bitdefender"
    if (Test-Path $bdLogDir) {
        Log "Detected Bitdefender -- collecting logs..."
        $bdDestDir = Join-Path $avDir "Bitdefender"
        Ensure-Directory $bdDestDir
        $bdLogs = Get-ChildItem -Path $bdLogDir -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".log", ".txt", ".xml", ".csv" -and $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($bl in $bdLogs) {
            Copy-ForensicFile -SourcePath $bl.FullName -DestDir $bdDestDir
        }
        Log-Success "Collected $($bdLogs.Count) Bitdefender log(s)."
    }

    # --- Trend Micro ---
    $tmLogDir = "${script:TargetRoot}ProgramData\Trend Micro"
    if (Test-Path $tmLogDir) {
        Log "Detected Trend Micro -- collecting logs..."
        $tmDestDir = Join-Path $avDir "TrendMicro"
        Ensure-Directory $tmDestDir
        $tmLogs = Get-ChildItem -Path $tmLogDir -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".log", ".txt", ".csv" -and $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($tl in $tmLogs) {
            Copy-ForensicFile -SourcePath $tl.FullName -DestDir $tmDestDir
        }
        Log-Success "Collected $($tmLogs.Count) Trend Micro log(s)."
    }

    # --- Webroot ---
    $wrLogDir = "${script:TargetRoot}ProgramData\WRData"
    if (Test-Path $wrLogDir) {
        Log "Detected Webroot -- collecting logs..."
        $wrDestDir = Join-Path $avDir "Webroot"
        Ensure-Directory $wrDestDir
        $wrLogs = Get-ChildItem -Path $wrLogDir -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".log", ".txt", ".csv" -and $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($wl in $wrLogs) {
            Copy-ForensicFile -SourcePath $wl.FullName -DestDir $wrDestDir
        }
        Log-Success "Collected $($wrLogs.Count) Webroot log(s)."
    }

    # --- Norton / NortonLifeLock ---
    $nortonLogDir = "${script:TargetRoot}ProgramData\Norton"
    if (-not (Test-Path $nortonLogDir)) {
        $nortonLogDir = "${script:TargetRoot}ProgramData\NortonLifeLock"
    }
    if (Test-Path $nortonLogDir) {
        Log "Detected Norton -- collecting logs..."
        $nortonDestDir = Join-Path $avDir "Norton"
        Ensure-Directory $nortonDestDir
        $nortonLogs = Get-ChildItem -Path $nortonLogDir -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".log", ".txt", ".csv" -and $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($nl in $nortonLogs) {
            Copy-ForensicFile -SourcePath $nl.FullName -DestDir $nortonDestDir
        }
        Log-Success "Collected $($nortonLogs.Count) Norton log(s)."
    }

    # --- Cylance ---
    $cylLogDir = "${script:TargetRoot}ProgramData\Cylance\Status"
    if (Test-Path $cylLogDir) {
        Log "Detected Cylance -- collecting logs..."
        $cylDestDir = Join-Path $avDir "Cylance"
        Ensure-Directory $cylDestDir
        $cylLogs = Get-ChildItem -Path $cylLogDir -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($cl in $cylLogs) {
            Copy-ForensicFile -SourcePath $cl.FullName -DestDir $cylDestDir
        }
        Log-Success "Collected $($cylLogs.Count) Cylance log(s)."
    }

    Log-Success "AntiVirus / Endpoint Security log collection complete."
    Log ""
}

# =============================================================
# Cleanup: Remove Shadow Copy and Defender Exclusion
# =============================================================
$script:collectionCompleted = $true

# End of the collection try block that starts above the "Collection
# Started" log line (the body in between is intentionally not
# re-indented). The finally block runs on normal completion, on
# terminating errors, on exit and on Ctrl+C, so the shadow copy and the
# Defender exclusion are never left behind. (Closing the console window
# kills the process outright; that cannot be caught.)
} finally {
    Invoke-CollectionCleanup
}

# =============================================================
# Collected copies keep the attributes of their source. Clear Hidden/System
# on everything in the collection folder so nothing in the zip (NTUSER.DAT,
# UsrClass.dat, hive .LOG1/.LOG2, ...) extracts as hidden, and older
# zip tools that skip hidden files still include them.
# =============================================================
try {
    $hiddenMask = [int][System.IO.FileAttributes]::Hidden -bor [int][System.IO.FileAttributes]::System
    Get-ChildItem -LiteralPath $OutputPath -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { ([int]$_.Attributes -band $hiddenMask) -ne 0 } |
        ForEach-Object {
            $item = $_
            try {
                $newAttributes = [int]$item.Attributes -band (-bnot $hiddenMask)
                if ($newAttributes -eq 0) { $newAttributes = [int][System.IO.FileAttributes]::Normal }
                $item.Attributes = [System.IO.FileAttributes]$newAttributes
            } catch {
                Log-Warning "Could not clear hidden/system attribute (may be missing from the zip): $($item.FullName)"
            }
        }
} catch {
    Log-Warning "Could not clear hidden/system attributes in the collection: $($_.Exception.Message)"
}

# =============================================================
# Summary: written to collection_log.txt BEFORE compression so the
# zip contains it; shown on screen again at the very end
# =============================================================
$endTime = Get-Date
$duration = $endTime - $script:startTime
$zipPath = "$OutputPath.zip"
# Memory dump, if captured: memory_dump.dmp (DumpIt) or memory_dump.raw
$memDumpFile = $null
foreach ($dumpExt in @("dmp", "raw")) {
    $dumpCandidate = Join-Path $OutputPath "Memory\memory_dump.$dumpExt"
    if ((Get-FileLength $dumpCandidate) -ge 0) { $memDumpFile = $dumpCandidate; break }
}
$memDumpMovedTo = $null

$summaryLines = @(
    "============================================================="
    "  COLLECTION SUMMARY"
    "============================================================="
    "  Target drive:   ${TargetDrive}: ($( if ($script:IsLive) { 'LIVE SYSTEM' } else { 'MOUNTED IMAGE' } ))"
    "  Computer:       $env:COMPUTERNAME"
    "  Start time:     $($script:startTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    "  End time:       $($endTime.ToString('yyyy-MM-dd HH:mm:ss')) (before compression)"
    "  Duration:       $($duration.ToString('hh\:mm\:ss'))"
    "  Files collected: $($script:fileCount)"
    "  Errors:         $($script:errorCount)"
    "  Total size:     $([math]::Round($script:totalBytes / 1MB, 2)) MB"
)
if ($NoCompress) {
    $summaryLines += "  Output:         $OutputPath"
} else {
    $summaryLines += "  Output:         $zipPath"
    if ($memDumpFile) {
        $summaryLines += "  Memory dump:    ${OutputPath}_$(Split-Path $memDumpFile -Leaf) (kept outside the zip)"
    }
}
$summaryLines += "  Manifest:       collection_manifest.csv (inside collection)"
$summaryLines += "============================================================="

Log ""
foreach ($summaryLine in $summaryLines) { Log $summaryLine }
Log ""
Log "=== Windows Forensic Triage Collection Complete ==="

# =============================================================
# Compression
# =============================================================
if (-not $NoCompress) {
    Log "============================================================="
    Log "  COMPRESSING OUTPUT"
    Log "============================================================="

    # Memory dump: kept next to the zip, not inside it (as large as RAM, slow
    # to compress, and analysis tools need the file itself)
    if ($memDumpFile) {
        $dumpSizeGB = [math]::Round((Get-FileLength $memDumpFile) / 1GB, 2)
        Log "Memory dump detected ($dumpSizeGB GB) -- keeping it next to the zip."
        # Move dump out of the collection folder temporarily
        $memDumpMovedTo = "${OutputPath}_$(Split-Path $memDumpFile -Leaf)"
        Move-Item -LiteralPath $memDumpFile -Destination $memDumpMovedTo -Force
        # Remove empty Memory folder if only the dump was in it
        $memDir = Join-Path $OutputPath "Memory"
        $memDirContents = Get-ChildItem -LiteralPath $memDir -File -Force -ErrorAction SilentlyContinue
        if ($memDirContents.Count -eq 0) {
            Remove-Item -LiteralPath $memDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Log "Compressing to: $zipPath"
    try {
        # ZipFile instead of Compress-Archive: Compress-Archive in Windows
        # PowerShell 5.1 fails on files over 2 GB (a large raw $MFT) and skips
        # hidden files; ZipFile writes Zip64 and includes everything
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        if ([System.IO.File]::Exists($zipPath)) { [System.IO.File]::Delete($zipPath) }
        [System.IO.Compression.ZipFile]::CreateFromDirectory($OutputPath, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $true)
        $zipSize = [math]::Round((Get-FileLength $zipPath) / 1MB, 2)
        Log-Success "Compressed to $zipPath ($zipSize MB)"

        # Stop logging to file before deleting the folder that contains it
        $script:logToFile = $false

        # Clean up uncompressed folder after successful zip
        Log "Removing uncompressed collection folder..."
        Remove-Item -LiteralPath $OutputPath -Recurse -Force -ErrorAction Stop
        Log-Success "Cleanup complete. Only the .zip remains."

        if ($memDumpMovedTo -and (Test-Path -LiteralPath $memDumpMovedTo)) {
            Log-Success "Memory dump saved separately: $memDumpMovedTo"
            Log "  (Not included in zip due to size. Transfer separately.)"
        }
    } catch {
        Log-Warning "Compression or cleanup issue: $($_.Exception.Message)"
        Log "Output may remain at: $OutputPath"
        # Move dump back if compression failed
        if ($memDumpMovedTo -and (Test-Path -LiteralPath $memDumpMovedTo)) {
            $memDir = Join-Path $OutputPath "Memory"
            Ensure-Directory $memDir
            Move-Item -LiteralPath $memDumpMovedTo -Destination $memDumpFile -Force
        }
    }
}

# =============================================================
# Summary on screen (the same text is in collection_log.txt)
# =============================================================
Write-Host ""
foreach ($summaryLine in $summaryLines) { Write-Host $summaryLine }
if (-not $NoCompress) {
    if ((Get-FileLength $zipPath) -gt 0) {
        Write-Host "  Zip created:    $zipPath ($([math]::Round((Get-FileLength $zipPath) / 1MB, 2)) MB)" -ForegroundColor Green
    } else {
        Write-Host "  Zip NOT created -- collection left at: $OutputPath" -ForegroundColor Yellow
    }
}
if ($memDumpMovedTo -and (Test-Path -LiteralPath $memDumpMovedTo)) {
    $dumpGB = [math]::Round((Get-FileLength $memDumpMovedTo) / 1GB, 2)
    Write-Host "  Memory dump:    $memDumpMovedTo ($dumpGB GB)"
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

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
            } catch {}
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

# --- Interactive memory capture prompt ---
# Only show if: live system, Memory not already in Categories, and a tool exists
if ($script:IsLive -and ($Categories -notcontains "Memory")) {
    $memToolFound = $false
    $memToolInfo = ""
    $supportedMemTools = @(
        @{ Name = "WinPmem";    Paths = @("winpmem\winpmem.exe", "winpmem.exe") },
        @{ Name = "DumpIt";     Paths = @("dumpit\dumpit.exe", "dumpit.exe") },
        @{ Name = "MagnetRAM";  Paths = @("magnetram\MagnetRAMCapture.exe", "MagnetRAMCapture.exe") }
    )
    foreach ($tool in $supportedMemTools) {
        foreach ($relPath in $tool.Paths) {
            $toolPath = Join-Path $script:ToolsDir $relPath
            if (Test-Path $toolPath) {
                $memToolFound = $true
                $memToolInfo = "$($tool.Name) (tools\$relPath)"
                break
            }
        }
        if ($memToolFound) { break }
    }

    if ($memToolFound) {
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

# Create output directory structure
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$logFile = Join-Path $OutputPath "collection_log.txt"
$manifestFile = Join-Path $OutputPath "collection_manifest.csv"

# Initialize manifest CSV
"SHA256,SourcePath,DestPath,SizeBytes,CollectedAt" | Out-File -FilePath $manifestFile -Encoding utf8

# ----------------------------------------------------------
# Defender Exclusion: add a temporary exclusion for the output
# path so collecting SAM/SECURITY hives doesn't trigger the
# Trojan:Win32/SAMDumpz detection. Removed at script end.
# ----------------------------------------------------------
$script:defenderExclusionAdded = $false
if ($script:IsLive) {
    try {
        Add-MpPreference -ExclusionPath $OutputPath -ErrorAction Stop
        $script:defenderExclusionAdded = $true
    } catch {
        # Will warn later when logging is available
    }
}

function Remove-DefenderExclusion {
    if ($script:defenderExclusionAdded) {
        try {
            Remove-MpPreference -ExclusionPath $OutputPath -ErrorAction Stop
        } catch {}
        $script:defenderExclusionAdded = $false
    }
}

# ----------------------------------------------------------
# Logging
# ----------------------------------------------------------
$script:logToFile = $true

function Log {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry
    if ($script:logToFile) { Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue }
}

function Log-Warning {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] WARNING: $Message"
    Write-Host $entry -ForegroundColor Yellow
    if ($script:logToFile) { Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue }
}

function Log-Error {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ERROR: $Message"
    Write-Host $entry -ForegroundColor Red
    if ($script:logToFile) { Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue }
}

function Log-Success {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] OK: $Message"
    Write-Host $entry -ForegroundColor Green
    if ($script:logToFile) { Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue }
}

# ----------------------------------------------------------
# Helper: Ensure directory exists
# ----------------------------------------------------------
function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
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

    if (-not (Test-Path $SourcePath)) {
        return
    }

    Ensure-Directory $DestDir

    if (-not $DestName) {
        $DestName = Split-Path $SourcePath -Leaf
    }
    $destPath = Join-Path $DestDir $DestName

    try {
        # Try direct copy first
        [System.IO.File]::Copy($SourcePath, $destPath, $true)
        Record-Manifest -SourcePath $SourcePath -DestPath $destPath
        return
    } catch {
        # File is locked, try standard Copy-Item as fallback
        try {
            Copy-Item -Path $SourcePath -Destination $destPath -Force -ErrorAction Stop
            Record-Manifest -SourcePath $SourcePath -DestPath $destPath
            return
        } catch {
            Log-Warning "Could not copy (locked): $SourcePath"
            $script:errorCount++
            return
        }
    }
}

function Record-Manifest {
    param(
        [string]$SourcePath,
        [string]$DestPath
    )
    if (-not (Test-Path $DestPath)) { return }
    $fileSize = (Get-Item $DestPath -ErrorAction SilentlyContinue).Length
    if ($fileSize -eq 0) {
        # Remove empty files (failed shadow copies that produced 0-byte output)
        Remove-Item $DestPath -Force -ErrorAction SilentlyContinue
        return
    }
    try {
        $hash = (Get-FileHash -Path $DestPath -Algorithm SHA256 -ErrorAction Stop).Hash
        $script:fileCount++
        $script:totalBytes += $fileSize
        $line = "$hash,`"$SourcePath`",`"$DestPath`",$fileSize,$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Add-Content -Path $manifestFile -Value $line
    } catch {
        Log-Warning "Could not hash/record: $DestPath"
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
        $output | Out-File -FilePath $DestPath -Encoding utf8 -Force
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

function Initialize-ShadowCopy {
    if ($script:shadowPath) { return $true }
    if (-not $script:IsLive) {
        Log "Skipping shadow copy (mounted image mode -- files are not locked)"
        return $false
    }

    Log "Creating Volume Shadow Copy for locked file access..."
    try {
        $shadow = (Get-WmiObject -List Win32_ShadowCopy).Create($script:TargetRoot, "ClientAccessible")
        if ($shadow.ReturnValue -eq 0) {
            $script:shadowId = $shadow.ShadowID
            $shadowObj = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $script:shadowId }
            $script:shadowPath = $shadowObj.DeviceObject
            Log-Success "Shadow copy created: $($script:shadowPath)"
            return $true
        } else {
            Log-Warning "Shadow copy creation returned code: $($shadow.ReturnValue)"
            return $false
        }
    } catch {
        Log-Warning "Could not create shadow copy: $($_.Exception.Message)"
        Log-Warning "Locked files ($('$')MFT, registry hives) may be incomplete."
        return $false
    }
}

function Copy-FromShadow {
    param(
        [string]$RelativePath,
        [string]$DestDir,
        [string]$DestName = ""
    )

    if (-not $script:shadowPath) {
        if (-not (Initialize-ShadowCopy)) {
            return $false
        }
    }

    $shadowFile = "$($script:shadowPath)\$RelativePath"
    if (-not $DestName) {
        $DestName = Split-Path $RelativePath -Leaf
    }
    $destPath = Join-Path $DestDir $DestName

    Ensure-Directory $DestDir

    try {
        # Use cmd /c copy to access the shadow device path
        $result = cmd /c "copy `"$shadowFile`" `"$destPath`"" 2>&1
        if ((Test-Path $destPath) -and (Get-Item $destPath).Length -gt 0) {
            Record-Manifest -SourcePath "(shadow)$RelativePath" -DestPath $destPath
            return $true
        } else {
            # Remove empty/corrupt shadow copy output
            Remove-Item $destPath -Force -ErrorAction SilentlyContinue
            Log-Warning "Shadow copy of $RelativePath did not produce output file"
            $script:errorCount++
            return $false
        }
    } catch {
        Log-Warning "Could not copy from shadow: $RelativePath -- $($_.Exception.Message)"
        $script:errorCount++
        return $false
    }
}

function Remove-ShadowCopy {
    if ($script:shadowId) {
        Log "Removing shadow copy..."
        try {
            $shadowObj = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $script:shadowId }
            if ($shadowObj) {
                $shadowObj.Delete()
                Log-Success "Shadow copy removed."
            }
        } catch {
            Log-Warning "Could not remove shadow copy: $($_.Exception.Message)"
        }
        $script:shadowId = $null
        $script:shadowPath = $null
    }
}

# =============================================================
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
        $memTool = $null
        $memToolName = ""
        $supportedMemTools = @(
            @{ Name = "WinPmem";    Paths = @("winpmem\winpmem.exe", "winpmem.exe") },
            @{ Name = "DumpIt";     Paths = @("dumpit\dumpit.exe", "dumpit.exe") },
            @{ Name = "MagnetRAM";  Paths = @("magnetram\MagnetRAMCapture.exe", "MagnetRAMCapture.exe") }
        )
        foreach ($tool in $supportedMemTools) {
            foreach ($relPath in $tool.Paths) {
                $toolPath = Join-Path $script:ToolsDir $relPath
                if (Test-Path $toolPath) {
                    $memTool = $toolPath
                    $memToolName = $tool.Name
                    break
                }
            }
            if ($memTool) { break }
        }

        if ($memTool) {
            $memDir = Join-Path $OutputPath "Memory"
            Ensure-Directory $memDir
            $dumpFile = Join-Path $memDir "memory_dump.raw"
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
                        $result = & $memTool /output $dumpFile /quiet 2>&1
                    }
                    "MagnetRAM" {
                        $result = & $memTool /accepteula /go /output $dumpFile 2>&1
                    }
                }

                # Save tool output as acquisition log
                $result | Out-File $memLogFile -Encoding utf8

                if ((Test-Path $dumpFile) -and (Get-Item $dumpFile).Length -gt 0) {
                    $dumpSizeMB = [math]::Round((Get-Item $dumpFile).Length / 1MB, 0)
                    $dumpSizeGB = [math]::Round((Get-Item $dumpFile).Length / 1GB, 2)
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
            Log "  To enable memory capture:"
            Log "    1. Create a subfolder in tools\ for your chosen tool"
            Log "    2. Download and place the .exe inside:"
            Log ""
            Log "       WinPmem (recommended, open-source):"
            Log "         https://github.com/Velocidex/WinPmem/releases"
            Log "         Download winpmem_mini_x64.exe, rename to winpmem.exe"
            Log "         Place in: tools\winpmem\winpmem.exe"
            Log ""
            Log "       DumpIt (Magnet Forensics, free):"
            Log "         https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/"
            Log "         Place in: tools\dumpit\dumpit.exe"
            Log ""
            Log "       Magnet RAM Capture (Magnet Forensics, free):"
            Log "         https://www.magnetforensics.com/resources/magnet-ram-capture/"
            Log "         Place in: tools\magnetram\MagnetRAMCapture.exe"
            Log ""
        }
    }

    Log ""
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
        Log "SkipLargeFiles is set -- skipping `$MFT, `$LogFile, `$UsnJrnl"
    } else {
        # $MFT - Master File Table
        Log "Collecting `$MFT (via shadow copy)..."
        $mftResult = Copy-FromShadow -RelativePath '$MFT' -DestDir $fsDir -DestName '$MFT'
        if (-not $mftResult) {
            # Try fsutil as alternative
            Log "Trying fsutil for `$MFT..."
            try {
                $mftDest = Join-Path $fsDir '$MFT'
                $fsutilOutput = fsutil file queryextents ${script:TargetRoot}`$MFT 2>&1
                Log "fsutil query: $fsutilOutput"
                # fsutil cannot directly extract $MFT, shadow copy is the primary method
                if (-not (Test-Path $mftDest)) {
                    Log-Warning "`$MFT collection requires Volume Shadow Copy or a raw disk reader."
                }
            } catch {
                Log-Warning "Could not collect `$MFT: $($_.Exception.Message)"
            }
        } else {
            Log-Success "Collected `$MFT"
        }

        # $LogFile
        Log "Collecting `$LogFile..."
        $logfileResult = Copy-FromShadow -RelativePath '$LogFile' -DestDir $fsDir -DestName '$LogFile'
        if ($logfileResult) { Log-Success "Collected `$LogFile" }
        else { Log-Warning "Could not collect `$LogFile" }

        # $UsnJrnl:$J
        Log "Collecting `$UsnJrnl:`$J..."
        $usnjrnlResult = Copy-FromShadow -RelativePath '$Extend\$UsnJrnl' -DestDir $fsDir -DestName '$UsnJrnl_$J'
        if (-not $usnjrnlResult) {
            # Try fsutil to read the USN journal
            Log "Trying fsutil usn readjournal..."
            try {
                $ujDest = Join-Path $fsDir '$UsnJrnl_$J.txt'
                fsutil usn readjournal ${TargetDrive}: csv 2>&1 | Out-File -FilePath $ujDest -Encoding utf8
                if ((Test-Path $ujDest) -and (Get-Item $ujDest).Length -gt 0) {
                    Record-Manifest -SourcePath "(fsutil usn readjournal)" -DestPath $ujDest
                    Log-Success "Collected USN Journal via fsutil (CSV format)"
                } else {
                    Remove-Item $ujDest -Force -ErrorAction SilentlyContinue
                    Log-Warning "Could not collect `$UsnJrnl"
                }
            } catch {
                Log-Warning "Could not collect `$UsnJrnl: $($_.Exception.Message)"
            }
        } else {
            Log-Success "Collected `$UsnJrnl"
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
                if (Test-Path $destFile) {
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
            if (Test-Path $hiveSrc) {
                Copy-ForensicFile -SourcePath $hiveSrc -DestDir $regDir -DestName $hiveName
                if (Test-Path (Join-Path $regDir $hiveName)) {
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
    if (Test-Path (Join-Path $regDir "Amcache.hve")) {
        Log-Success "Collected Amcache.hve"
    } else {
        Log-Warning "Could not collect Amcache.hve"
    }
    # Collect transaction logs for dirty hive recovery (locked, need shadow copy)
    foreach ($logExt in @(".LOG1", ".LOG2")) {
        $logRelPath = "Windows\AppCompat\Programs\Amcache.hve${logExt}"
        $logResult = Copy-FromShadow -RelativePath $logRelPath -DestDir $regDir -DestName "Amcache.hve${logExt}"
        if (-not $logResult) {
            # Fallback to direct copy
            $logSrc = "${amcacheSrc}${logExt}"
            if (Test-Path $logSrc) {
                Copy-ForensicFile -SourcePath $logSrc -DestDir $regDir
            }
        }
        if (Test-Path (Join-Path $regDir "Amcache.hve${logExt}")) {
            Log-Success "Collected Amcache.hve${logExt}"
        }
    }

    # Per-user hives: NTUSER.DAT and UsrClass.dat
    Log "Collecting per-user registry hives..."
    $userProfiles = Get-ChildItem "${script:TargetRoot}Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }

    # Build a map of loaded HKU SIDs to usernames for reg save (live system only)
    $sidToUser = @{}
    if ($script:IsLive) {
        try {
            $hkuKeys = reg query HKU 2>&1
            foreach ($line in $hkuKeys) {
                if ($line -match '(S-1-5-21-[\d-]+)$') {
                    $sid = $Matches[1]
                    try {
                        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
                        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
                        $resolvedName = $objUser.Value -replace '^.*\\', ''
                        $sidToUser[$resolvedName] = $sid
                    } catch {}
                }
            }
        } catch {}
    }

    foreach ($userDir in $userProfiles) {
        $userName = $userDir.Name
        $userRegDir = Join-Path $regDir $userName
        Ensure-Directory $userRegDir

        # Check if this user has a loaded HKU hive (active/logged-in user)
        $userSid = $sidToUser[$userName]

        # NTUSER.DAT
        $ntuser = Join-Path $userDir.FullName "NTUSER.DAT"
        if (Test-Path $ntuser) {
            Log "Collecting NTUSER.DAT for $userName..."
            $collected = $false

            # Method 1: reg save via HKU\SID (live system only, works for active user)
            if ($script:IsLive -and $userSid -and -not $collected) {
                $destFile = Join-Path $userRegDir "NTUSER.DAT"
                try {
                    reg save "HKU\$userSid" $destFile /y 2>&1 | Out-Null
                    if ((Test-Path $destFile) -and (Get-Item $destFile).Length -gt 0) {
                        Record-Manifest -SourcePath "HKU\$userSid" -DestPath $destFile
                        Log-Success "Collected NTUSER.DAT for $userName via reg save"
                        $collected = $true
                    }
                } catch {}
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
        if (Test-Path $usrclass) {
            Log "Collecting UsrClass.dat for $userName..."
            $collected = $false

            # Method 1: reg save via HKU\SID_Classes (live system only, works for active user)
            if ($script:IsLive -and $userSid -and -not $collected) {
                $destFile = Join-Path $userRegDir "UsrClass.dat"
                try {
                    reg save "HKU\${userSid}_Classes" $destFile /y 2>&1 | Out-Null
                    if ((Test-Path $destFile) -and (Get-Item $destFile).Length -gt 0) {
                        Record-Manifest -SourcePath "HKU\${userSid}_Classes" -DestPath $destFile
                        Log-Success "Collected UsrClass.dat for $userName via reg save"
                        $collected = $true
                    }
                } catch {}
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
        $pfFiles = Get-ChildItem -Path $prefetchSource -Filter "*.pf" -ErrorAction SilentlyContinue
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
        # Recent Apps (from NTUSER via registry -- export the key)
        $recentAppsDir = Join-Path $execDir "RecentApps"
        Ensure-Directory $recentAppsDir
        Log "Collecting RecentApps registry data..."
        try {
            $regPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps"
            $destFile = Join-Path $recentAppsDir "RecentApps.reg"
            reg export $regPath $destFile /y 2>&1 | Out-Null
            if (Test-Path $destFile) {
                Record-Manifest -SourcePath $regPath -DestPath $destFile
                Log-Success "Collected RecentApps registry export."
            }
        } catch {
            Log "RecentApps key not found (normal on some builds)."
        }

        # BAM (Background Activity Moderator)
        Log "Collecting BAM data..."
        Save-CommandOutput -Description "BAM entries" `
            -DestPath (Join-Path $execDir "bam_entries.txt") `
            -Command {
                Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*" -ErrorAction SilentlyContinue |
                    Format-List
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
            Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue |
                Select-Object DisplayName, Direction, Action, Profile |
                Sort-Object Direction, DisplayName |
                Format-Table -AutoSize -Wrap
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
            $lnkFiles = Get-ChildItem -Path $recentSource -Filter "*.lnk" -ErrorAction SilentlyContinue
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
            $jlFiles = Get-ChildItem -Path $autoJumpSource -ErrorAction SilentlyContinue
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
            $jlFiles = Get-ChildItem -Path $customJumpSource -ErrorAction SilentlyContinue
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
        if (Test-Path $chromeBase) {
            Log "Collecting Chrome data for $userName..."
            # Collect from Default and any numbered profiles
            $chromeProfiles = Get-ChildItem -Path $chromeBase -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" }

            foreach ($profile in $chromeProfiles) {
                $destDir = Join-Path $browserDir "$userName\Chrome\$($profile.Name)"
                $chromeFiles = @("History", "Bookmarks", "Login Data", "Cookies", "Web Data", "Top Sites", "Shortcuts")
                foreach ($cf in $chromeFiles) {
                    $sourcePath = Join-Path $profile.FullName $cf
                    if (Test-Path $sourcePath) {
                        Copy-ForensicFile -SourcePath $sourcePath -DestDir $destDir -DestName $cf
                    }
                }
            }
            Log-Success "Collected Chrome artifacts for $userName"
        }

        # Edge (Chromium-based, same structure as Chrome)
        $edgeBase = Join-Path $userDir.FullName "AppData\Local\Microsoft\Edge\User Data"
        if (Test-Path $edgeBase) {
            Log "Collecting Edge data for $userName..."
            $edgeProfiles = Get-ChildItem -Path $edgeBase -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" }

            foreach ($profile in $edgeProfiles) {
                $destDir = Join-Path $browserDir "$userName\Edge\$($profile.Name)"
                $edgeFiles = @("History", "Bookmarks", "Login Data", "Cookies", "Web Data", "Top Sites", "Shortcuts")
                foreach ($ef in $edgeFiles) {
                    $sourcePath = Join-Path $profile.FullName $ef
                    if (Test-Path $sourcePath) {
                        Copy-ForensicFile -SourcePath $sourcePath -DestDir $destDir -DestName $ef
                    }
                }
            }
            Log-Success "Collected Edge artifacts for $userName"
        }

        # Brave (Chromium-based)
        $braveBase = Join-Path $userDir.FullName "AppData\Local\BraveSoftware\Brave-Browser\User Data"
        if (Test-Path $braveBase) {
            Log "Collecting Brave data for $userName..."
            $braveProfiles = Get-ChildItem -Path $braveBase -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" }

            foreach ($profile in $braveProfiles) {
                $destDir = Join-Path $browserDir "$userName\Brave\$($profile.Name)"
                $braveFiles = @("History", "Bookmarks", "Login Data", "Cookies", "Web Data", "Top Sites", "Shortcuts")
                foreach ($bf in $braveFiles) {
                    $sourcePath = Join-Path $profile.FullName $bf
                    if (Test-Path $sourcePath) {
                        Copy-ForensicFile -SourcePath $sourcePath -DestDir $destDir -DestName $bf
                    }
                }
            }
            Log-Success "Collected Brave artifacts for $userName"
        }

        # Opera (Chromium-based, slightly different path)
        $operaPaths = @(
            (Join-Path $userDir.FullName "AppData\Roaming\Opera Software\Opera Stable"),
            (Join-Path $userDir.FullName "AppData\Roaming\Opera Software\Opera GX Stable")
        )
        foreach ($operaBase in $operaPaths) {
            if (Test-Path $operaBase) {
                $operaName = if ($operaBase -match "GX") { "OperaGX" } else { "Opera" }
                Log "Collecting $operaName data for $userName..."
                $destDir = Join-Path $browserDir "$userName\$operaName"
                $operaFiles = @("History", "Bookmarks", "Login Data", "Cookies", "Web Data", "Top Sites", "Shortcuts")
                foreach ($of in $operaFiles) {
                    $sourcePath = Join-Path $operaBase $of
                    if (Test-Path $sourcePath) {
                        Copy-ForensicFile -SourcePath $sourcePath -DestDir $destDir -DestName $of
                    }
                }
                Log-Success "Collected $operaName artifacts for $userName"
            }
        }

        # Vivaldi (Chromium-based)
        $vivaldiBase = Join-Path $userDir.FullName "AppData\Local\Vivaldi\User Data"
        if (Test-Path $vivaldiBase) {
            Log "Collecting Vivaldi data for $userName..."
            $vivaldiProfiles = Get-ChildItem -Path $vivaldiBase -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" }

            foreach ($profile in $vivaldiProfiles) {
                $destDir = Join-Path $browserDir "$userName\Vivaldi\$($profile.Name)"
                $vivaldiFiles = @("History", "Bookmarks", "Login Data", "Cookies", "Web Data", "Top Sites", "Shortcuts")
                foreach ($vf in $vivaldiFiles) {
                    $sourcePath = Join-Path $profile.FullName $vf
                    if (Test-Path $sourcePath) {
                        Copy-ForensicFile -SourcePath $sourcePath -DestDir $destDir -DestName $vf
                    }
                }
            }
            Log-Success "Collected Vivaldi artifacts for $userName"
        }

        # Firefox
        $firefoxBase = Join-Path $userDir.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxBase) {
            Log "Collecting Firefox data for $userName..."
            $ffProfiles = Get-ChildItem -Path $firefoxBase -Directory -ErrorAction SilentlyContinue

            foreach ($profile in $ffProfiles) {
                $destDir = Join-Path $browserDir "$userName\Firefox\$($profile.Name)"
                $ffFiles = @("places.sqlite", "logins.json", "cookies.sqlite", "formhistory.sqlite", "permissions.sqlite", "key4.db")
                foreach ($ff in $ffFiles) {
                    $sourcePath = Join-Path $profile.FullName $ff
                    if (Test-Path $sourcePath) {
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

    # setupapi.dev.log
    $setupapiPath = "${script:TargetRoot}Windows\inf\setupapi.dev.log"
    if (Test-Path $setupapiPath) {
        Log "Collecting setupapi.dev.log..."
        Copy-ForensicFile -SourcePath $setupapiPath -DestDir $usbDir
        Log-Success "Collected setupapi.dev.log"
    } else {
        Log-Warning "setupapi.dev.log not found."
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
        # Scheduled Tasks (live system only)
        Log "Collecting scheduled tasks..."
        Save-CommandOutput -Description "scheduled_tasks" `
            -DestPath (Join-Path $persDir "scheduled_tasks.csv") `
            -Command {
                Get-ScheduledTask -ErrorAction SilentlyContinue |
                    Where-Object { $_.State -ne "Disabled" } |
                    Select-Object TaskName, TaskPath, State, Author,
                        @{Name='Actions';Expression={($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "}},
                        @{Name='Triggers';Expression={($_.Triggers | ForEach-Object { $_.ToString() }) -join "; "}} |
                    ConvertTo-Csv -NoTypeInformation
            }

        # Services
        Log "Collecting services..."
        Save-CommandOutput -Description "services" `
            -DestPath (Join-Path $persDir "services.csv") `
            -Command {
                Get-CimInstance Win32_Service |
                    Select-Object Name, DisplayName, State, StartMode, PathName, StartName, Description |
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

        # Run / RunOnce keys
        Log "Collecting Run/RunOnce registry keys..."
        Save-CommandOutput -Description "run_keys" `
            -DestPath (Join-Path $persDir "run_keys.txt") `
            -Command {
                $runKeys = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
                )
                foreach ($key in $runKeys) {
                    Write-Output "=== $key ==="
                    if (Test-Path $key) {
                        Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | Format-List
                    } else {
                        Write-Output "(key does not exist)"
                    }
                    Write-Output ""
                }
            }

        # Startup folder contents
        Save-CommandOutput -Description "startup_folders" `
            -DestPath (Join-Path $persDir "startup_folders.txt") `
            -Command {
                $startupPaths = @(
                    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
                )
                foreach ($sp in $startupPaths) {
                    Write-Output "=== $sp ==="
                    if (Test-Path $sp) {
                        Get-ChildItem $sp -ErrorAction SilentlyContinue | Format-Table Name, LastWriteTime, Length -AutoSize
                    } else {
                        Write-Output "(path does not exist)"
                    }
                    Write-Output ""
                }
            }

        # WMI Event Subscriptions (persistence mechanism)
        Log "Collecting WMI event subscriptions..."
        Save-CommandOutput -Description "wmi_subscriptions" `
            -DestPath (Join-Path $persDir "wmi_subscriptions.csv") `
            -Command {
                $filters = Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -ErrorAction SilentlyContinue
                $consumers = Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer -ErrorAction SilentlyContinue
                $bindings = Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

                $results = @()
                foreach ($binding in $bindings) {
                    $results += [PSCustomObject]@{
                        Type     = "Binding"
                        Filter   = $binding.Filter
                        Consumer = $binding.Consumer
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
                        Details  = ($consumer | Select-Object * | Out-String).Trim()
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
                Get-WmiObject Win32_SystemDriver |
                    Select-Object Name, DisplayName, PathName, State, StartMode, ServiceType |
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
            $taskFiles = Get-ChildItem -Path $taskSourceDir -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 0 } | Select-Object -First 200
            $taskCount = 0
            foreach ($tf in $taskFiles) {
                Copy-ForensicFile -SourcePath $tf.FullName -DestDir $taskDestDir -DestName $tf.Name
                if (Test-Path (Join-Path $taskDestDir $tf.Name)) { $taskCount++ }
            }
            Log-Success "Collected $taskCount scheduled task XML file(s)."
        }

        # Startup folders from mounted image
        $startupPath = "${script:TargetRoot}ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
        if (Test-Path $startupPath) {
            Save-CommandOutput -Description "startup_folders" `
                -DestPath (Join-Path $persDir "startup_folders.txt") `
                -Command {
                    Write-Output "=== $startupPath ==="
                    Get-ChildItem $startupPath -ErrorAction SilentlyContinue | Format-Table Name, LastWriteTime, Length -AutoSize
                }
        }

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

    # Defender support logs directory
    $defenderSupportDir = "${script:TargetRoot}ProgramData\Microsoft\Windows Defender\Support"
    if (Test-Path $defenderSupportDir) {
        Log "Collecting Defender support logs..."
        $defenderDestDir = Join-Path $avDir "Defender"
        Ensure-Directory $defenderDestDir
        $defenderLogs = Get-ChildItem -Path $defenderSupportDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".log", ".txt", ".etl" -and $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 10
        foreach ($dl in $defenderLogs) {
            Copy-ForensicFile -SourcePath $dl.FullName -DestDir $defenderDestDir
        }
        Log-Success "Collected $($defenderLogs.Count) Defender support log(s)."
    }

    # --- Symantec Endpoint Protection ---
    $sepLogDir = "${script:TargetRoot}ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs"
    if (Test-Path $sepLogDir) {
        Log "Detected Symantec Endpoint Protection -- collecting logs..."
        $sepDestDir = Join-Path $avDir "Symantec_SEP"
        Ensure-Directory $sepDestDir
        $sepLogs = Get-ChildItem -Path $sepLogDir -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($sl in $sepLogs) {
            Copy-ForensicFile -SourcePath $sl.FullName -DestDir $sepDestDir
        }
        Log-Success "Collected $($sepLogs.Count) Symantec SEP log(s)."
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
                $csLogs = Get-ChildItem -Path $csDir -File -Recurse -ErrorAction SilentlyContinue |
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
        $s1Logs = Get-ChildItem -Path $s1LogDir -File -Recurse -ErrorAction SilentlyContinue |
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
        $cbLogs = Get-ChildItem -Path $cbLogDir -File -Recurse -ErrorAction SilentlyContinue |
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
        $mbLogs = Get-ChildItem -Path $mbLogDir -File -Recurse -ErrorAction SilentlyContinue |
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
        $sophosLogs = Get-ChildItem -Path $sophosLogDir -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".log", ".txt", ".xml", ".csv" -and $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($sl in $sophosLogs) {
            Copy-ForensicFile -SourcePath $sl.FullName -DestDir $sophosDestDir
        }
        Log-Success "Collected $($sophosLogs.Count) Sophos log(s)."
    }

    # --- ESET ---
    $esetLogDir = "${script:TargetRoot}ProgramData\ESET\ESET Security\Logs"
    if (-not (Test-Path $esetLogDir)) {
        $esetLogDir = "${script:TargetRoot}ProgramData\ESET\ESET NOD32 Antivirus\Logs"
    }
    if (Test-Path $esetLogDir) {
        Log "Detected ESET -- collecting logs..."
        $esetDestDir = Join-Path $avDir "ESET"
        Ensure-Directory $esetDestDir
        $esetLogs = Get-ChildItem -Path $esetLogDir -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($el in $esetLogs) {
            Copy-ForensicFile -SourcePath $el.FullName -DestDir $esetDestDir
        }
        Log-Success "Collected $($esetLogs.Count) ESET log(s)."
    }

    # --- Kaspersky ---
    $kaspLogDir = "${script:TargetRoot}ProgramData\Kaspersky Lab"
    if (Test-Path $kaspLogDir) {
        Log "Detected Kaspersky -- collecting logs..."
        $kaspDestDir = Join-Path $avDir "Kaspersky"
        Ensure-Directory $kaspDestDir
        $kaspLogs = Get-ChildItem -Path $kaspLogDir -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".log", ".txt", ".rpt", ".csv" -and $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($kl in $kaspLogs) {
            Copy-ForensicFile -SourcePath $kl.FullName -DestDir $kaspDestDir
        }
        Log-Success "Collected $($kaspLogs.Count) Kaspersky log(s)."
    }

    # --- McAfee / Trellix ---
    $mcafeeLogDir = "${script:TargetRoot}ProgramData\McAfee"
    if (-not (Test-Path $mcafeeLogDir)) {
        $mcafeeLogDir = "${script:TargetRoot}ProgramData\Trellix"
    }
    if (Test-Path $mcafeeLogDir) {
        Log "Detected McAfee/Trellix -- collecting logs..."
        $mcafeeDestDir = Join-Path $avDir "McAfee_Trellix"
        Ensure-Directory $mcafeeDestDir
        $mcafeeLogs = Get-ChildItem -Path $mcafeeLogDir -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in ".log", ".txt", ".csv" -and $_.Length -gt 0 } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
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
        $bdLogs = Get-ChildItem -Path $bdLogDir -File -Recurse -ErrorAction SilentlyContinue |
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
        $tmLogs = Get-ChildItem -Path $tmLogDir -File -Recurse -ErrorAction SilentlyContinue |
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
        $wrLogs = Get-ChildItem -Path $wrLogDir -File -Recurse -ErrorAction SilentlyContinue |
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
        $nortonLogs = Get-ChildItem -Path $nortonLogDir -File -Recurse -ErrorAction SilentlyContinue |
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
        $cylLogs = Get-ChildItem -Path $cylLogDir -File -Recurse -ErrorAction SilentlyContinue |
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
if ($script:IsLive) {
    Remove-ShadowCopy
    Log "Removing temporary Defender exclusion..."
    Remove-DefenderExclusion
    Log-Success "Defender exclusion removed."
}

# =============================================================
# Compression
# =============================================================
if (-not $NoCompress) {
    Log "============================================================="
    Log "  COMPRESSING OUTPUT"
    Log "============================================================="
    $zipPath = "$OutputPath.zip"

    # Check for memory dump -- too large for Compress-Archive (>2 GB limit)
    $memDumpFile = Join-Path $OutputPath "Memory\memory_dump.raw"
    $memDumpMovedTo = $null
    if (Test-Path $memDumpFile) {
        $dumpSizeGB = [math]::Round((Get-Item $memDumpFile).Length / 1GB, 2)
        Log "Memory dump detected ($dumpSizeGB GB) -- excluding from zip (too large)."
        # Move dump out of the collection folder temporarily
        $memDumpMovedTo = "${OutputPath}_memory_dump.raw"
        Move-Item -Path $memDumpFile -Destination $memDumpMovedTo -Force
        # Remove empty Memory folder if only the dump was in it
        $memDir = Join-Path $OutputPath "Memory"
        $memDirContents = Get-ChildItem $memDir -File -ErrorAction SilentlyContinue
        if ($memDirContents.Count -eq 0) {
            Remove-Item $memDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Log "Compressing to: $zipPath"
    try {
        Compress-Archive -Path $OutputPath -DestinationPath $zipPath -Force -ErrorAction Stop
        $zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
        Log-Success "Compressed to $zipPath ($zipSize MB)"

        # Stop logging to file before deleting the folder that contains it
        $script:logToFile = $false

        # Clean up uncompressed folder after successful zip
        Log "Removing uncompressed collection folder..."
        Remove-Item -Path $OutputPath -Recurse -Force -ErrorAction Stop
        Log-Success "Cleanup complete. Only the .zip remains."

        if ($memDumpMovedTo -and (Test-Path $memDumpMovedTo)) {
            Log-Success "Memory dump saved separately: $memDumpMovedTo"
            Log "  (Not included in zip due to size. Transfer separately.)"
        }
    } catch {
        Log-Warning "Compression or cleanup issue: $($_.Exception.Message)"
        Log "Output may remain at: $OutputPath"
        # Move dump back if compression failed
        if ($memDumpMovedTo -and (Test-Path $memDumpMovedTo)) {
            $memDir = Join-Path $OutputPath "Memory"
            Ensure-Directory $memDir
            Move-Item -Path $memDumpMovedTo -Destination (Join-Path $memDir "memory_dump.raw") -Force
        }
    }
}

# =============================================================
# Summary
# =============================================================
$endTime = Get-Date
$duration = $endTime - $script:startTime

Log ""
Log "============================================================="
Log "  COLLECTION SUMMARY"
Log "============================================================="
Log "  Target drive:   ${TargetDrive}: ($( if ($script:IsLive) { 'LIVE SYSTEM' } else { 'MOUNTED IMAGE' } ))"
Log "  Computer:       $env:COMPUTERNAME"
Log "  Start time:     $($script:startTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Log "  End time:       $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Log "  Duration:       $($duration.ToString('hh\:mm\:ss'))"
Log "  Files collected: $($script:fileCount)"
Log "  Errors:         $($script:errorCount)"
Log "  Total size:     $([math]::Round($script:totalBytes / 1MB, 2)) MB"
if (-not $NoCompress -and (Test-Path "$OutputPath.zip")) {
    Log "  Output:         $OutputPath.zip"
} else {
    Log "  Output:         $OutputPath"
}
if ($memDumpMovedTo -and (Test-Path $memDumpMovedTo)) {
    $dumpGB = [math]::Round((Get-Item $memDumpMovedTo).Length / 1GB, 2)
    Log "  Memory dump:    $memDumpMovedTo ($dumpGB GB)"
}
Log "  Manifest:       (inside collection)"
Log "============================================================="
Log ""
Log "=== Windows Forensic Triage Collection Complete ==="

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

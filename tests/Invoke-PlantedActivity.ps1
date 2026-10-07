# =============================================================
# Planted-activity test, step 1: plant
# Does a set of harmless, recognizable actions on this machine, so that a
# collection and its timeline can be checked for them afterwards:
#
#   1. This script, in a NORMAL (not elevated) PowerShell window, signed in
#      as the user whose activity should show up:
#        powershell -ExecutionPolicy Bypass -File tests\Invoke-PlantedActivity.ps1
#   2. Run-TriageCollector.bat (live system), then Run-TimelineBuilder.bat
#      on the new collection
#   3. tests\Test-PlantedActivity.ps1 -- checks the timeline
#   4. This script with -Cleanup -- removes what it planted
#
# Every planted name starts with TriageE2E_<id>. Actions (in a new folder
# under Downloads):
#   Run      copy of hostname.exe, run once (hidden)
#   Stomp    copy of hostname.exe with its Created/Modified times set back to
#            2021-03-04 05:06:07 UTC (timestomping)
#   Doc      text file added to Recent items (as when it is opened)
#   Deleted  text file created, then deleted
#   RunKey   HKCU Run value pointing to the Run copy (removed by -Cleanup)
#   Task     disabled scheduled task in the user's name (removed by -Cleanup)
#   Browser  Edge visit to https://example.com/?triage-e2e=<id> (-NoBrowser
#            skips it)
#   Eicar    only with -Eicar: the EICAR antivirus test file, which Defender
#            detects and quarantines (a harmless industry-standard test)
# What each one should produce is in tests\Test-PlantedActivity.ps1.
# The details go to planted.json in the new folder.
# =============================================================
param(
    # Remove everything planted by earlier runs (Run values, tasks, folders,
    # Recent shortcuts). Run after the check.
    [switch]$Cleanup,
    # Also write the EICAR antivirus test file
    [switch]$Eicar,
    # Do not open Edge
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$downloads = Join-Path $env:USERPROFILE "Downloads"
$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$recentDir = Join-Path $env:APPDATA "Microsoft\Windows\Recent"

# --- Cleanup -------------------------------------------------
if ($Cleanup) {
    $folders = @(Get-ChildItem -LiteralPath $downloads -Directory -Filter "TriageE2E_*" -ErrorAction SilentlyContinue)
    $runValues = @((Get-Item -LiteralPath $runKeyPath).GetValueNames() | Where-Object { $_ -like "TriageE2E_*" })
    $tasks = @(Get-ScheduledTask -TaskPath "\" -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "TriageE2E_*" })
    $shortcuts = @(Get-ChildItem -LiteralPath $recentDir -Filter "TriageE2E_*.lnk" -File -ErrorAction SilentlyContinue)
    foreach ($name in $runValues) {
        Remove-ItemProperty -LiteralPath $runKeyPath -Name $name
        Write-Host "Removed Run value: $name"
    }
    foreach ($task in $tasks) {
        Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath "\" -Confirm:$false
        Write-Host "Removed scheduled task: \$($task.TaskName)"
    }
    foreach ($shortcut in $shortcuts) {
        Remove-Item -LiteralPath $shortcut.FullName -Force
        Write-Host "Removed Recent shortcut: $($shortcut.Name)"
    }
    foreach ($folder in $folders) {
        Remove-Item -LiteralPath $folder.FullName -Recurse -Force
        Write-Host "Removed folder: $($folder.FullName)"
    }
    if ($runValues.Count + $tasks.Count + $shortcuts.Count + $folders.Count -eq 0) {
        Write-Host "Nothing to clean up."
    }
    Write-Host "Left as normal history: Prefetch, Recent documents list, Edge history, event logs." -ForegroundColor DarkGray
    exit 0
}

# --- Plant ---------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run this from a normal (not elevated) PowerShell window: the activity should belong to the" -ForegroundColor Red
    Write-Host "signed-in user, and Edge should not run as administrator. (The collector itself runs elevated.)" -ForegroundColor Red
    exit 1
}

# Shell calls: ShellExecuteEx with SEE_MASK_FLAG_LOG_USAGE (the usage count
# behind UserAssist) and SHAddToRecentDocs (what opening a file from the
# shell records). C# 5 for Windows PowerShell 5.1.
if (-not ('TriageE2E.Shell' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace TriageE2E
{
    public static class Shell
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ShellExecuteInfo
        {
            public int cbSize;
            public uint fMask;
            public IntPtr hwnd;
            public string lpVerb;
            public string lpFile;
            public string lpParameters;
            public string lpDirectory;
            public int nShow;
            public IntPtr hInstApp;
            public IntPtr lpIDList;
            public string lpClass;
            public IntPtr hkeyClass;
            public uint dwHotKey;
            public IntPtr hIcon;
            public IntPtr hProcess;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ShellExecuteExW(ref ShellExecuteInfo info);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern void SHAddToRecentDocs(uint flags, string path);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        // Runs a program hidden and waits up to 30 s for it to exit
        public static void Run(string path)
        {
            ShellExecuteInfo info = new ShellExecuteInfo();
            info.cbSize = Marshal.SizeOf(typeof(ShellExecuteInfo));
            // SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_FLAG_LOG_USAGE
            info.fMask = 0x00000040 | 0x00000400 | 0x04000000;
            info.lpVerb = "open";
            info.lpFile = path;
            info.nShow = 0;   // SW_HIDE
            if (!ShellExecuteExW(ref info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (info.hProcess != IntPtr.Zero)
            {
                WaitForSingleObject(info.hProcess, 30000);
                CloseHandle(info.hProcess);
            }
        }

        // SHARD_PATHW
        public static void AddToRecentDocs(string path)
        {
            SHAddToRecentDocs(3, path);
        }
    }
}
'@
}

$id = [guid]::NewGuid().ToString("N").Substring(0, 8)
$base = "TriageE2E_$id"
$folder = Join-Path $downloads $base
$hostnameExe = Join-Path $env:SystemRoot "System32\HOSTNAME.EXE"
$profileName = Split-Path $env:USERPROFILE -Leaf
$steps = [ordered]@{}

function Get-UtcText {
    param([datetime]$Time = [datetime]::UtcNow)
    return $Time.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", [System.Globalization.CultureInfo]::InvariantCulture)
}

# Runs one planting action; its result (and any extra fields it returns)
# goes into planted.json
function Invoke-PlantStep {
    param([string]$Name, [string]$What, [scriptblock]$Action)
    $step = [ordered]@{ Status = "Planted"; TimeUtc = Get-UtcText; Message = "" }
    try {
        $extra = & $Action
        if ($extra -is [System.Collections.IDictionary]) {
            foreach ($key in $extra.Keys) { $step[$key] = $extra[$key] }
        }
        Write-Host ("  OK    {0,-8} {1}" -f $Name, $What) -ForegroundColor Green
    }
    catch {
        $step.Status = "Failed"
        $step.Message = $_.Exception.Message
        Write-Host ("  FAIL  {0,-8} {1}: {2}" -f $Name, $What, $step.Message) -ForegroundColor Yellow
    }
    $steps[$Name] = $step
}

function Skip-PlantStep {
    param([string]$Name, [string]$Reason)
    $steps[$Name] = [ordered]@{ Status = "Skipped"; TimeUtc = Get-UtcText; Message = $Reason }
    Write-Host ("  SKIP  {0,-8} {1}" -f $Name, $Reason) -ForegroundColor DarkGray
}

$startedUtc = Get-UtcText
New-Item -ItemType Directory -Path $folder | Out-Null
Write-Host "Planting activity $base in $folder"

$runPath = Join-Path $folder "${base}_run.exe"
Invoke-PlantStep -Name "Run" -What "copy of hostname.exe run once" -Action {
    [System.IO.File]::Copy($hostnameExe, $runPath)
    $created = Get-UtcText
    [TriageE2E.Shell]::Run($runPath)
    @{ Path = $runPath; CreatedUtc = $created }
}

$stompPath = Join-Path $folder "${base}_stomp.exe"
$stompTime = New-Object DateTime 2021, 3, 4, 5, 6, 7, ([DateTimeKind]::Utc)
Invoke-PlantStep -Name "Stomp" -What "copy of hostname.exe backdated to $(Get-UtcText $stompTime)" -Action {
    [System.IO.File]::Copy($hostnameExe, $stompPath)
    $created = Get-UtcText
    [System.IO.File]::SetCreationTimeUtc($stompPath, $stompTime)
    [System.IO.File]::SetLastWriteTimeUtc($stompPath, $stompTime)
    @{ Path = $stompPath; CreatedUtc = $created; StompTimeUtc = Get-UtcText $stompTime }
}

$docPath = Join-Path $folder "${base}_doc.txt"
$trackDocs = (Get-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction SilentlyContinue).Start_TrackDocs
if ($trackDocs -eq 0) {
    [System.IO.File]::WriteAllText($docPath, "Triage planted-activity test file ($base).`r`n")
    Skip-PlantStep -Name "Doc" -Reason "Windows is set not to track recently opened items (Settings > Personalization > Start)"
} else {
    Invoke-PlantStep -Name "Doc" -What "text file added to Recent items" -Action {
        [System.IO.File]::WriteAllText($docPath, "Triage planted-activity test file ($base).`r`n")
        $created = Get-UtcText
        [TriageE2E.Shell]::AddToRecentDocs($docPath)
        @{ Path = $docPath; CreatedUtc = $created }
    }
}

$deletedPath = Join-Path $folder "${base}_deleted.txt"
Invoke-PlantStep -Name "Deleted" -What "text file created, then deleted" -Action {
    [System.IO.File]::WriteAllText($deletedPath, "Triage planted-activity test file, deleted ($base).`r`n")
    $created = Get-UtcText
    Start-Sleep -Seconds 2
    [System.IO.File]::Delete($deletedPath)
    @{ Path = $deletedPath; CreatedUtc = $created; DeletedUtc = Get-UtcText }
}

Invoke-PlantStep -Name "RunKey" -What "HKCU Run value $base" -Action {
    Set-ItemProperty -LiteralPath $runKeyPath -Name $base -Value "`"$runPath`""
    @{ Key = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"; Value = $base }
}

Invoke-PlantStep -Name "Task" -What "disabled scheduled task \$base" -Action {
    $registeredLocal = Get-Date
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$($registeredLocal.ToString("yyyy-MM-dd'T'HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture))</Date>
    <Author>$([System.Security.SecurityElement]::Escape($env:USERNAME))</Author>
    <Description>Triage planted-activity test task (disabled; never runs)</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2099-01-01T00:00:00</StartBoundary>
      <Enabled>false</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>false</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$([System.Security.SecurityElement]::Escape($runPath))</Command>
    </Exec>
  </Actions>
</Task>
"@
    $null = Register-ScheduledTask -TaskName $base -TaskPath "\" -Xml $taskXml
    # The task file stores whole seconds of local time
    $registeredUtc = $registeredLocal.AddTicks(-($registeredLocal.Ticks % [TimeSpan]::TicksPerSecond)).ToUniversalTime()
    @{ TaskName = "\$base"; RegisteredUtc = Get-UtcText $registeredUtc }
}

$url = "https://example.com/?triage-e2e=$id"
if ($NoBrowser) {
    Skip-PlantStep -Name "Browser" -Reason "-NoBrowser"
} else {
    Invoke-PlantStep -Name "Browser" -What "Edge visit to $url" -Action {
        Start-Process -FilePath "msedge.exe" -ArgumentList $url
        @{ Url = $url }
    }
}

if ($Eicar) {
    Invoke-PlantStep -Name "Eicar" -What "EICAR test file (Defender should detect and quarantine it)" -Action {
        # Stored reversed so this script itself is not detected
        $chars = '*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\4[PA@%P!O5X'.ToCharArray()
        [array]::Reverse($chars)
        $eicarPath = Join-Path $folder "${base}_eicar.txt"
        try {
            [System.IO.File]::WriteAllText($eicarPath, (-join $chars), [System.Text.Encoding]::ASCII)
        } catch {
            # Defender can block the write itself; that is a detection too
            Write-Verbose "EICAR write: $($_.Exception.Message)"
        }
        @{ Path = $eicarPath }
    }
} else {
    Skip-PlantStep -Name "Eicar" -Reason "not requested (-Eicar)"
}

# Prefetch is written about 10 s after a program starts; Edge saves history
# within seconds
Write-Host "Waiting 20 s for Windows to write Prefetch and Edge history..."
Start-Sleep -Seconds 20

$planted = [ordered]@{
    Version     = 1
    Id          = $id
    Base        = $base
    Computer    = $env:COMPUTERNAME
    User        = $profileName
    Folder      = $folder
    StartedUtc  = $startedUtc
    FinishedUtc = Get-UtcText
    Steps       = $steps
}
$plantedFile = Join-Path $folder "planted.json"
[System.IO.File]::WriteAllText($plantedFile, ($planted | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))

$failed = @($steps.Keys | Where-Object { $steps[$_].Status -eq "Failed" })
Write-Host ""
Write-Host "Planted: $plantedFile" -ForegroundColor Cyan
if ($failed.Count -gt 0) { Write-Host "Not planted (the check will skip them): $($failed -join ', ')" -ForegroundColor Yellow }
Write-Host "Next:"
Write-Host "  1. Run-TriageCollector.bat (live system), then Run-TimelineBuilder.bat on the new collection"
Write-Host "  2. powershell -ExecutionPolicy Bypass -File tests\Test-PlantedActivity.ps1"
Write-Host "  3. powershell -ExecutionPolicy Bypass -File tests\Invoke-PlantedActivity.ps1 -Cleanup"
Write-Host "Optional: restart Windows before collecting to also get ShimCache entries (written at shutdown)." -ForegroundColor DarkGray

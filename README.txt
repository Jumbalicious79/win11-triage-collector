# Windows 11 Forensic Triage Collector

A lightweight, dependency-free PowerShell script for collecting forensic
artifacts from a live Windows system. Pure PowerShell -- no KAPE, no external
tools required.

Designed to be used with win11-timeline-builder, which parses this script's
output into a unified chronological timeline and auto-opens it in Timeline
Explorer. Both tools are available as separate repos for independent use.

  Companion project: https://github.com/Jumbalicious79/win11-timeline-builder

Tested on Windows 11 Home Build 26200. Collects ~600 files in ~90 seconds,
compresses to ~65 MB. Supports live system collection and mounted forensic
images.


## Setup

Both tools MUST be sibling directories (same parent folder) for the automatic
workflow to function. The timeline builder locates triage collections by looking
for ..\win11-triage-collector\reports\ relative to its own location.

Required directory structure:

  any-parent-folder\
    win11-triage-collector\       <-- this repo
      triage-collector.ps1
      Run-TriageCollector.bat
      README.txt
      tools\                      <-- optional tools (each in own subfolder)
        winpmem\                  <-- optional: winpmem.exe for memory capture
      reports\                    <-- collections save here
    win11-timeline-builder\       <-- companion repo
      timeline-builder.ps1
      Run-TimelineBuilder.bat
      README.txt
      tools\                      <-- auto-downloaded tools (each in own subfolder)
        sqlite3\                  <-- auto-downloaded: browser history parser
        TimelineExplorer\         <-- auto-downloaded: forensic CSV viewer
        volatility3\              <-- optional: vol.exe for memory analysis
      reports\                    <-- timelines save here

To set up:

  git clone https://github.com/Jumbalicious79/win11-triage-collector
  git clone https://github.com/Jumbalicious79/win11-timeline-builder

Or download both repos and extract them into the same parent folder. The parent
folder can be anywhere -- your desktop, a USB drive, a network share, etc.

If you only need the collector without timeline analysis, it works standalone.
But for the full collect-and-analyze workflow, both directories must be siblings.


## Intended Workflow

These two tools are designed to work together as a complete collect-and-analyze
pipeline:

  1. COLLECT: Run triage-collector on the target system (this tool)
  2. ANALYZE: Run timeline-builder on the collection (companion tool)
  3. REVIEW: Timeline Explorer auto-opens with the timeline loaded

### Live System (Dirty Forensics)

For incident response, triage, or non-legal investigations where speed matters
more than forensic purity:

  1. Copy win11-triage-collector to a USB drive
  2. Plug the USB into the target machine
  3. Double-click Run-TriageCollector.bat (collects to reports\ on the USB)
  4. Unplug the USB and take it to your analysis workstation
  5. Place win11-timeline-builder alongside the collector (or anywhere)
  6. Double-click Run-TimelineBuilder.bat -- it auto-finds the triage zips
  7. Pick a collection, timeline builds, Timeline Explorer opens

This is a "dirty" collection -- the act of running the script modifies the
system (writes files, creates a shadow copy, touches the registry). This is
acceptable for triage and incident response but may not meet evidentiary
standards for legal proceedings.

### Forensic Image (Clean Forensics)

For legal cases, litigation hold, or any situation requiring chain of custody:

  1. Create a forensic image of the target system FIRST
     Use FTK Imager, dd, or your preferred imaging tool
  2. Mount the image as read-only on your analysis workstation (e.g., E:)
  3. Run triage-collector against the mounted drive letter:
     Run-TriageCollector.bat E
     (or: powershell ... -File triage-collector.ps1 -TargetDrive E)
  4. Run timeline-builder against the collection
  5. The collection manifest (SHA256 hashes) provides integrity verification

When collecting from a mounted image, the script auto-detects that the target
is not the live system drive and switches to MOUNTED IMAGE mode:

  Collected (file-copy):
    - Registry hives (from Windows\System32\config\)
    - Event logs (from Windows\System32\winevt\Logs\)
    - Prefetch files, browser data, user activity artifacts
    - Scheduled task XML definitions (from Windows\System32\Tasks\)
    - Startup folder listings (all-users folder + every user profile)
    - AV log files (Defender support logs, third-party AV logs)
    - USB setupapi.dev.log and rotated setupapi.dev.<date>.log files
    - Amcache.hve (+ .LOG1/.LOG2 transaction logs)

  Skipped (requires live system):
    - Network state (DNS, ARP, TCP connections, firewall, Wi-Fi)
    - Live registry queries (Run keys, BAM, RecentApps, USB registry,
      mounted devices) -- the same data is in the collected hives
    - USB PnP device timestamps (usb_storage_devices.csv)
    - Scheduled task run times (scheduled_tasks.csv)
    - WMI queries (services, startup commands, drivers, WMI subscriptions)
    - Defender cmdlets (detections, status, preferences)
    - Shadow copies (not needed -- files are not locked)
    - systeminfo (would report collector host, not target)

### USB Deployment Kit

To prepare a USB drive as a portable forensic triage kit:

  USB_DRIVE\
    win11-triage-collector\
      triage-collector.ps1
      Run-TriageCollector.bat
      README.txt
      tools\                      <-- optional: winpmem\ for memory capture
        winpmem\                  <-- winpmem.exe goes here
      reports\                    <-- collections save here
    win11-timeline-builder\
      timeline-builder.ps1
      Run-TimelineBuilder.bat
      README.txt
      tools\                      <-- sqlite3\, TimelineExplorer\, volatility3\
      reports\                    <-- timelines save here

Both tools output to their own reports\ directories. The timeline builder
auto-discovers triage collections from the sibling directory. No configuration
needed -- plug in, double-click, collect, analyze.


## Quick Start

### Double-click (recommended)

  Run-TriageCollector.bat              -- collect from C: (live system)
  Run-TriageCollector.bat fast         -- skip the USN journal export
  Run-TriageCollector.bat nozip        -- don't compress output
  Run-TriageCollector.bat E            -- collect from E: (mounted image)
  Run-TriageCollector.bat E fast       -- collect from E:, skip the USN journal

  Note: "fast" skips the USN journal, which is the timeline builder's largest
  source of file activity. Registry hives are always collected.

  For memory capture: place winpmem.exe in tools\winpmem\ directory.
  The script prompts on live system runs when a capture tool is detected.
  See the "Optional Tools" section below for setup instructions.

### PowerShell (Admin)

  powershell -ExecutionPolicy Bypass -NoProfile -File "path\to\triage-collector.ps1"
  powershell -ExecutionPolicy Bypass -NoProfile -File "path\to\triage-collector.ps1" -TargetDrive E
  powershell -ExecutionPolicy Bypass -NoProfile -File "path\to\triage-collector.ps1" -SkipLargeFiles
  powershell -ExecutionPolicy Bypass -NoProfile -File "path\to\triage-collector.ps1" -Categories "Network","Persistence","EventLogs"
  powershell -ExecutionPolicy Bypass -NoProfile -File "path\to\triage-collector.ps1" -NoCompress


## How It Handles Windows Defender

Collecting registry hives (SAM, SECURITY) from a live system triggers Defender's
Trojan:Win32/SAMDumpz detection because that's exactly what credential dumping
tools do. This script handles it automatically:

  1. Adds a temporary Defender exclusion for the output folder at script start
  2. Collects all 4 hives (SYSTEM, SOFTWARE, SAM, SECURITY) via "reg save"
  3. Removes the exclusion at script end -- also when the run is stopped
     with Ctrl+C or ends with an error

This is the same approach KAPE uses. The script runs as Administrator, so it has
the privileges to manage Defender exclusions. You do NOT need to manually disable
Defender or add exclusions.

If the exclusion fails (e.g., tamper protection blocks it), the script warns you
and continues -- SYSTEM and SOFTWARE will still collect fine, but SAM/SECURITY
may be blocked by Defender.


## Output

The script compresses everything into a single .zip and removes the uncompressed
folder automatically. Only the .zip remains:

  win11-triage-collector\
    reports\
      TriageCollection_2026-04-08_08-04.zip    (~60 MB)

If memory capture was included, the memory dump is saved separately (too large
for zip -- Compress-Archive has a 2 GB file limit):

  win11-triage-collector\
    reports\
      TriageCollection_2026-04-08_08-04.zip                (~60 MB artifacts)
      TriageCollection_2026-04-08_08-04_memory_dump.raw    (~16-64 GB)

Use -NoCompress to keep the uncompressed folder instead.

Inside the zip:

  TriageCollection_2026-04-08_08-04\
    collection_info.json              -- host, mode, start time, time zones
    collection_log.txt                -- full run log
    collection_manifest.csv           -- SHA256, source, dest, size, source file
                                         times per file (see Output File Formats)
    systeminfo.txt                    -- system info snapshot
    Memory\                               -- only if memory capture was selected
      memory_dump.raw                 -- full RAM dump (saved separately, not in zip)
      memory_acquisition_log.txt      -- capture tool output log
    FileSystem\
      $UsnJrnl_$J.txt                 -- USN Journal (fsutil CSV-style text)
    Registry\
      SYSTEM                          -- hardware, services, USB history, timezone
      SOFTWARE                        -- installed apps, network profiles, Run keys
      SAM                             -- local user accounts, password policy
      SECURITY                        -- security policies, audit settings
      Amcache.hve                     -- program execution history with SHA1 hashes
      Amcache.hve.LOG1/.LOG2          -- transaction logs for dirty hive recovery
      buzz_\                          -- per-user: NTUSER.DAT, UsrClass.dat
    EventLogs\
      System.evtx                     -- service events, shutdowns, driver loads
      Security.evtx                   -- logons, process creation, account changes
      Application.evtx                -- app crashes, errors
      Microsoft-Windows-PowerShell%4Operational.evtx
      Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
      Microsoft-Windows-Windows Defender%4Operational.evtx
      Microsoft-Windows-Bits-Client%4Operational.evtx
      (Sysmon, Task Scheduler -- if present on the system)
    Execution\
      Prefetch\                       -- all .pf files (program execution evidence)
      RecentApps\<user>\RecentApps.reg  -- per logged-in user, only if the key
                                         exists (absent on Windows 11)
      bam_entries.csv                 -- BAM: per-user program paths with
                                         decoded last-execution times (UTC)
      appcompat_cache.reg             -- ShimCache execution artifacts
    Network\
      dns_cache.txt                   -- recently resolved domains
      arp_cache.txt                   -- local network neighbors
      netstat.txt                     -- active connections snapshot
      tcp_connections.csv             -- connections with process info
      network_profiles.txt            -- Wi-Fi/wired network history
      firewall_rules.txt              -- all firewall rules
      wifi_profiles.txt               -- saved Wi-Fi profiles
      network_shares.txt              -- SMB shares
    UserActivity\
      buzz_\
        RecentFiles\                  -- LNK shortcut files (file access history)
        JumpLists\                    -- AutomaticDestinations, CustomDestinations
        ConsoleHost_history.txt       -- PowerShell command history
    Browser\
      buzz_\
        Chrome\                       -- History, Bookmarks, Login Data, etc.
        Edge\                         -- same artifacts as Chrome
      (Firefox -- if installed)
    USB\
      setupapi.dev.log                -- device installation log (first-connect times)
      setupapi.dev.<yyyymmdd_hhmmss>.log  -- older logs rotated by Windows
                                         (all present are collected)
      usb_storage_devices.csv         -- USB storage devices (incl. disconnected)
                                         with first install / arrival / removal
                                         times (UTC)
      usb_storage_devices.txt         -- USB storage device registry entries
      usb_devices.txt                 -- all USB device entries
      mounted_devices.txt             -- volume GUID to drive letter mapping
    Persistence\
      scheduled_tasks.csv             -- all scheduled tasks (incl. disabled) with
                                         run-as account, actions, triggers,
                                         registration/last/next run times
      services.csv                    -- all services with binary paths and
                                         registry key last-write time
      startup_entries.csv             -- startup programs
      run_keys.csv                    -- Run/RunOnce values for HKLM and every
                                         logged-in user, with key last-write time
      run_keys.txt                    -- same keys (plus Shell Folders) as text
      startup_folders.csv             -- Startup folder items for all users and
                                         every profile, with file times (UTC)
      startup_folders.txt             -- same folders as text
      wmi_subscriptions.csv           -- WMI event consumers (persistence)
      drivers.csv                     -- kernel drivers with registry key
                                         last-write time
      loaded_dlls_suspicious.txt      -- DLLs loaded from non-standard paths
    AntiVirus\
      installed_av_products.txt       -- all AV products detected via WMI
      defender_detections.csv         -- Defender threat detection history
      defender_threats.csv            -- Defender threat catalog
      defender_status.txt             -- Defender real-time status
      defender_preferences.txt        -- Defender configuration/exclusions
      Defender\                       -- Defender support logs (last 10)
      Symantec_SEP\                   -- if installed
      CrowdStrike\                    -- if installed
      SentinelOne\                    -- if installed
      CarbonBlack\                    -- if installed
      Malwarebytes\                   -- if installed
      Sophos\                         -- if installed
      ESET\                           -- if installed
      Kaspersky\                      -- if installed
      McAfee_Trellix\                 -- if installed
      Bitdefender\                    -- if installed
      TrendMicro\                     -- if installed
      Webroot\                        -- if installed
      Norton\                         -- if installed
      Cylance\                        -- if installed


## What Gets Collected

### Memory (opt-in, live system only)

  memory_dump.raw    Full physical RAM capture via WinPmem, DumpIt, or Magnet
                     RAM Capture (whichever is found in the tools\ directory).
                     Dump size equals installed RAM. Runs first to capture
                     pristine memory state before other collection.
                     Requires a capture tool in tools\ -- see Optional Tools.
                     Saved separately from the zip due to size.

### FileSystem

  $UsnJrnl:$J   File change journal -- every create, modify, delete, rename.
                Critical for timeline building. Collected via "fsutil usn
                readjournal ... csv" into FileSystem\$UsnJrnl_$J.txt.
  $MFT          Master File Table with all file records including deleted.
                NTFS metafile -- needs a raw-disk reader (see Known
                Limitations); normally not collected.
  $LogFile      NTFS transaction log. Same limitation as $MFT.
  -SkipLargeFiles ("fast") skips the USN journal export.

### Registry Hives

  SYSTEM        Hardware, services, mounted devices, USB, timezone.
  SOFTWARE      Installed apps, OS version, network profiles, Run keys.
  SAM           Local accounts, group memberships, last login times.
  SECURITY      Security policies, audit settings, LSA secrets.
  NTUSER.DAT    Per-user: recent docs, typed URLs, UserAssist, MRU lists.
                Locked for active user -- requires VSS.
  UsrClass.dat  ShellBags (folder browsing history). Locked for active user.
  Amcache.hve   Program execution history with SHA1 hashes and install dates.
                Transaction logs (.LOG1/.LOG2) collected for dirty hive recovery.

### Event Logs

  System.evtx                Service starts/stops, shutdowns, driver loads.
  Security.evtx              Logons (4624/4625), process creation, audit changes.
  Application.evtx           App crashes, errors, warnings.
  PowerShell Operational     Script block and module logging.
  Sysmon (if installed)      Process, network, file, registry activity.
  Task Scheduler             Task creation/modification/execution.
  TerminalServices           RDP logins (lateral movement).
  Windows Defender           Detections, scans, exclusion changes.
  BITS Client                Background transfers (stealthy downloads).

### Execution Artifacts

  Prefetch (.pf)             Last 8 execution times per program.
  BAM                        Background Activity Moderator: last execution
                             time per program per user (all user SIDs, decoded
                             to UTC in bam_entries.csv). Live system only.
  AppCompatCache             ShimCache -- program presence/execution evidence.
  RecentApps                 Recently launched apps with run counts, for every
                             logged-in user. The key does not exist on Windows
                             11 and recent Windows 10 builds; nothing is written
                             then.

### Network

  DNS cache                  Recently resolved domains (C2 indicators).
  ARP cache                  Local network neighbors.
  netstat / TCP connections  Active connections with process info.
  Network profiles           Wi-Fi/wired network history.
  Firewall rules             Allowed/blocked traffic rules.
  Wi-Fi profiles             Saved wireless networks.
  Network shares             Active SMB shares.

### User Activity

  LNK files                  File access with timestamps and original paths.
  Jump Lists                 Recent/frequent files per application.
  PowerShell history         PSReadLine command history (plaintext).

### Browser

  History, Bookmarks, Login Data, Cookies, Downloads, Preferences.
  Supports Chrome, Edge, Brave, Opera, Opera GX, Vivaldi (all Chromium-based)
  and Firefox. Per-user, per-profile.

### USB

  setupapi.dev*.log          Device install timestamps (first USB connect).
                             Windows rotates setupapi.dev.log into
                             setupapi.dev.<yyyymmdd_hhmmss>.log files; all of
                             them are collected with their original names.
  USB storage PnP times      usb_storage_devices.csv: every USB storage disk
                             known to Plug and Play, including devices that are
                             not connected, with first install, install, last
                             arrival and last removal times. Live system only.
  USB storage/device registry  Serial numbers, vendor IDs, mount points.
  Mounted devices            Volume GUID to drive letter mapping.

### Persistence

  Scheduled tasks            All tasks, including disabled ones, with run-as
                             account, actions, triggers, registration date and
                             last/next run time and last result.
  Services                   Service binary paths, startup types, accounts, and
                             last-write time of each service's registry key.
  Startup entries            Registry and folder-based autostart.
  Run/RunOnce keys           Registry autostart keys for HKLM and for every
                             logged-in user (not just the account running the
                             collector), with key last-write times.
  Startup folders            All-users Startup folder and every user profile's
                             Startup folder (live system and mounted images),
                             with created/modified times. Hidden items are
                             listed; desktop.ini is skipped.
  WMI subscriptions          Event-driven persistence.
  Drivers                    Kernel and filesystem drivers, with last-write
                             time of each driver's registry key.
  Loaded DLLs               DLLs from non-standard paths (sideloading).

### AntiVirus / Endpoint Security

  Installed AV products      All registered AV products via WMI SecurityCenter2.
  Windows Defender           Detection history, threat catalog, real-time status,
                             configured preferences/exclusions, and support logs.
  Third-party AV logs        Auto-detected and collected if installed:
                             Symantec SEP, CrowdStrike Falcon, SentinelOne,
                             Carbon Black, Malwarebytes, Sophos, ESET,
                             Kaspersky, McAfee/Trellix, Bitdefender, Trend Micro,
                             Webroot, Norton, Cylance.
  AV event logs              Windows event logs from AV products (Symantec,
                             CrowdStrike) collected via wevtutil if present.


## Output File Formats

All times in the JSON and CSV files below are UTC in ISO 8601 round-trip
format, e.g. 2026-10-07T01:52:50.0000000Z. A blank field means the time is
unknown or does not apply. CSV files are UTF-8 with a header row and standard
quoting (Import-Csv, Excel and Timeline Explorer read them directly). A CSV
with only a header row means the query ran and found nothing.

### collection_info.json

Written at the start of the run, at the root of the collection:

  SchemaVersion        1
  ComputerName         Machine running the collector
  CollectorUser        Account that ran the collector
  Mode                 "Live" or "MountedImage"
  TargetDrive          Drive letter collected from, e.g. "C"
  TargetRoot           Windows root on that drive, e.g. "C:\"
  CollectionStartUtc   Start of the run
  CollectorTimeZoneId  Time zone of the collecting machine
  CollectorCulture     Culture (locale) of the collecting machine, e.g. "en-US"
  TargetTimeZoneId     Time zone of the examined Windows install. Live: same
                       as CollectorTimeZoneId. Mounted image: TimeZoneKeyName
                       from the image's SYSTEM hive, or null if unreadable.

The timeline builder uses these to convert local-time text (USN journal,
setupapi logs) correctly even when the analysis machine uses a different
time zone or locale.

### collection_manifest.csv

  SHA256               Hash of the collected copy
  SourcePath           Original path; "HKLM\..." / "HKU\..." for reg save,
                       "(shadow)..." for shadow copies, "(command: ...)" for
                       command output
  DestPath             Full path of the copy at collection time
  SizeBytes            Size of the copy
  CollectedAt          Collector's local time when the file was recorded
  RelativePath         Path inside the collection, e.g.
                       Execution\Prefetch\CMD.EXE-0BD30981.pf
  SourceCreatedUtc     Created / modified / accessed times of the ORIGINAL
  SourceModifiedUtc    file (the copies in the collection get new times).
  SourceAccessedUtc    Blank for command output, reg save exports, or unknown.

The first five columns are unchanged from earlier versions; the last four are
appended.

### Execution\bam_entries.csv  (live system only)

  Sid                  SID of the user the BAM entry belongs to
  User                 Account name (profile folder name), blank if unknown
  Path                 Program path as recorded by BAM
                       (\Device\HarddiskVolumeN\...) or app ID
  LastExecutionUtc     Last execution time

Replaces bam_entries.txt from earlier versions, which lost the times (only the
first 4 of the 8 FILETIME bytes were written).

### Persistence\scheduled_tasks.csv  (live system only)

  TaskName, TaskPath, State, Author
  UserId               Account the task runs as (group name for group tasks)
  Actions              Command lines; COM handler actions as
                       "ComHandler {CLSID} <data>"
  Triggers             Trigger types
  RegistrationDateUtc  Task registration date (RegistrationInfo Date,
                       recorded in the system's local time); blank if not set
  LastRunTimeUtc       Blank if the task never ran
  NextRunTimeUtc       Blank if nothing is scheduled
  LastTaskResult       Result code of the last run (decimal; 0 = success,
                       267011 = has not run yet)

Disabled tasks are included (State = Disabled). On mounted images the task
XML files are collected instead (Persistence\ScheduledTasks_XML\).

### Persistence\services.csv and drivers.csv  (live system only)

Same columns as before plus KeyLastWriteUtc: last-write time of
HKLM\SYSTEM\CurrentControlSet\Services\<Name>. A recent time can point to a
newly installed or changed service or driver, but Windows also updates these
keys during normal operation (updates, start type changes), so treat it as a
lead, not proof.

### Persistence\run_keys.csv  (live system only)

  Hive                 "HKLM" or "HKU\<SID>"
  User                 Account name for HKU rows (blank for HKLM)
  KeyPath              Path relative to the hive, e.g.
                       SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  ValueName            Value name ("(Default)" for the default value)
  Command              Value data as stored (environment variables such as
                       %USERPROFILE% are not expanded)
  KeyLastWriteUtc      Last-write time of the key (the whole key, not the
                       single value)

Keys covered, for HKLM and for every loaded user hive (local and Entra ID
accounts): Run, RunOnce, WOW6432Node Run/RunOnce, Policies\Explorer\Run.
run_keys.txt lists the same keys plus Shell Folders / User Shell Folders.

### Persistence\startup_folders.csv  (live system and mounted images)

  Scope                "AllUsers" or "User"
  User                 Profile folder name (blank for AllUsers)
  Folder               Full path of the Startup folder
  Name                 File or folder name (desktop.ini skipped)
  CreatedUtc           Created time of the item
  ModifiedUtc          Modified time of the item

### USB\usb_storage_devices.csv  (live system only)

  FriendlyName         e.g. "PNY USB 3.1 FD USB Device"
  InstanceId           USBSTOR\DISK&VEN_...&PROD_...&REV_...\<serial>&0
  Serial               Last part of the instance ID without the "&0" suffix
                       (if its second character is "&", Windows generated it
                       because the device reports no serial number)
  FirstInstallUtc      First time the device was installed on this system
  InstallUtc           Last (re)install time
  LastArrivalUtc       Last time the device was connected
  LastRemovalUtc       Last time the device was removed

Devices that are no longer connected are included.


## Analyzing the Output

### With win11-timeline-builder (recommended)

The fastest path from collection to analysis:

  1. Double-click Run-TimelineBuilder.bat (no arguments needed)
  2. It auto-finds triage zips in the sibling reports\ directory
  3. Pick a collection number
  4. If a memory dump is detected alongside the zip and Volatility 3 is
     installed, the script prompts to include memory analysis
  5. Timeline builds (~2 minutes for ~56,000 events, longer with memory)
  6. Color-coded Excel (.xlsx) is generated with rows colored by EventType
  7. Choose a viewer: Excel (colored), Timeline Explorer, Both, or None
  8. Filter, sort, pivot, investigate

  The timeline builder produces both CSV (full data) and Excel (color-coded).
  It parses only the triage collection data -- never queries the local system.

  Companion project: https://github.com/Jumbalicious79/win11-timeline-builder

### With Eric Zimmerman's Tools (manual deep-dive)

  MFTECmd.exe -f "Collection\FileSystem\$MFT" --csv ".\parsed" --csvf mft.csv
  PECmd.exe -d "Collection\Execution\Prefetch" --csv ".\parsed" --csvf prefetch.csv
  EvtxECmd.exe -d "Collection\EventLogs" --csv ".\parsed" --csvf evtx.csv
  RECmd.exe --bn BatchExamples\RECmd_Batch_MC.reb -d "Collection\Registry" --csv ".\parsed"
  AmcacheParser.exe -f "Collection\Registry\Amcache.hve" --csv ".\parsed"

  Download EZ Tools: https://ericzimmerman.github.io/


## What This Script Does NOT Do

  - No analysis -- collection only. Use timeline-builder for analysis.
  - No network capture -- use Wireshark or "netsh trace" for packets.
  - No memory dump by default -- enable by placing a capture tool in tools\
    (see Optional Tools section). When enabled, memory capture runs first.
  - No disk imaging -- collects specific artifacts, not a full image.
    For a full image, use FTK Imager or dd.
  - No malware scanning -- does not identify or classify malware.
  - No cloud artifacts -- OneDrive, Teams, cloud data not collected.
  - No remediation -- does not remove, quarantine, or modify anything.


## Known Limitations and Expected Warnings

  - $MFT and $LogFile are NTFS metafiles. They cannot be read through normal
    file copy APIs, not even from a Volume Shadow Copy, so this script does
    not get them. Collecting them needs a raw-disk reader (e.g., FTK Imager)
    or a full disk image. The USN Journal is collected via fsutil instead and
    is the timeline builder's main source of file activity.

  - Per-user live registry data (Run/RunOnce keys, RecentApps) covers every
    user whose hive is loaded, i.e. users logged in at collection time, not
    only the account running the collector. For users who are not logged in,
    the same keys are in their NTUSER.DAT under Registry\<user>\.

  - The temporary Defender exclusion and the shadow copy are removed even if
    the run is stopped with Ctrl+C or ends with an error. If the console
    window is closed or the machine loses power mid-run, cleanup may not get
    to run: check Windows Security exclusions and "vssadmin list shadows".

  - NTUSER.DAT and UsrClass.dat for the active user are locked. The script
    tries reg save via HKU\SID (works for logged-in users), then VSS shadow
    copy, then direct copy. On most systems reg save succeeds.

  - System service accounts (e.g., WsiAccount) may have locked or inaccessible
    hive files. Shadow copy attempts will fail for these. This is normal --
    these are not real user accounts and contain minimal forensic data.
    Warning: "Shadow copy of Users\WsiAccount\NTUSER.DAT did not produce output"

  - Hidden files are collected, including the Amcache.hve transaction logs
    (.LOG1/.LOG2) and the hidden NTUSER.DAT / UsrClass.dat of users who are
    not logged in. (Earlier versions copied hidden files and then deleted
    them as "empty".) The Amcache logs can still fail to collect if locked;
    if the hive is dirty without logs, the timeline builder skips Amcache
    parsing for that collection.
    Warning: "Could not copy (locked): ...Amcache.hve.LOG1"

  - Some LNK shortcut files in the Recent folder may be locked by active
    applications (e.g., Snipping Tool screenshots). The script collects all
    unlocked files and warns about the locked ones. Most files are collected.
    Warning: "Could not copy (locked): ...ms-screensketchedit...lnk"

  - Sysmon and Task Scheduler logs only collected if present on the system.
    These are not installed by default on Windows 11 Home.
    Message: "Skipping Microsoft-Windows-Sysmon%4Operational.evtx (not present)"

  - The collection manifest hashes are computed on destination copies, not source
    files. For "reg save" exports, the hash represents the saved snapshot.


## Legal and Authorization

IMPORTANT: Only run this script on systems you are authorized to examine.

  - Obtain written authorization before collecting forensic artifacts.
  - This script accesses sensitive data including password databases (SAM),
    security policies, browser credentials, and user activity history.
  - Collected artifacts may contain PII subject to privacy regulations.
  - Maintain chain of custody documentation if used in legal proceedings.
  - The collection manifest provides SHA256 hashes for integrity verification.
  - Store collected data securely. Limit access to authorized personnel.
  - The script temporarily manages a Windows Defender exclusion (logged).

For legal cases, create a forensic image FIRST, then run this script against
the mounted image for a non-invasive collection.


## Parameters

  -TargetDrive     Single drive letter to collect from (e.g., C, E, F).
                   Default: system drive (usually C).
                   Use this to collect from a mounted forensic image.
                   The script auto-detects live vs mounted and adjusts
                   collection methods accordingly.
  -OutputPath      Where to save collected artifacts.
                   Default: reports\TriageCollection_<timestamp>
  -SkipLargeFiles  Skip the USN journal export ($UsnJrnl:$J) for faster
                   runs ("fast" in the .bat). The USN journal is the
                   timeline builder's largest source. Registry hives are
                   still collected.
  -NoCompress      Keep uncompressed folder (don't zip and delete).
  -Categories      Specific categories to collect. Default: all (except Memory).
                   Valid: Memory, FileSystem, Registry, EventLogs, Execution,
                   Network, UserActivity, Browser, USB, Persistence,
                   AntiVirus
                   Note: Memory is opt-in. On live systems, the script prompts
                   if a capture tool is found in tools\. For automation, pass
                   -Categories "Memory","FileSystem","Registry",...


## Optional Tools (tools\ directory)

The script supports optional third-party tools for capabilities that require
kernel-mode access (e.g., memory capture). These tools are NOT included in
the repo -- you must download and place them manually.

  win11-triage-collector\
    tools\                         <-- create this folder
      winpmem\                     <-- subfolder per tool
        winpmem.exe                <-- memory capture tool

Each tool gets its own subfolder, matching the timeline builder's layout.
Tools placed here travel with the script on USB drives. If a tool is not
present, the script skips that capability and continues normally.


### Memory Capture Setup

Memory capture requires a kernel-mode driver to read physical RAM. The
script auto-detects supported tools in the tools\ directory. On a live
system, if a tool is found, the script prompts you to include memory
capture before collection begins.

  Recommended: WinPmem (open-source, signed driver, Windows 11 compatible)
    1. Download from: https://github.com/Velocidex/WinPmem/releases
    2. Download the latest winpmem_mini_x64.exe (or winpmem_x64.exe)
    3. Rename to winpmem.exe
    4. Place in: win11-triage-collector\tools\winpmem\winpmem.exe

  Alternative: DumpIt (Magnet Forensics, free, signed driver)
    1. Download from: https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/
    2. Place in: win11-triage-collector\tools\dumpit\dumpit.exe

  Alternative: Magnet RAM Capture (Magnet Forensics, free)
    1. Download from: https://www.magnetforensics.com/resources/magnet-ram-capture/
    2. Place in: win11-triage-collector\tools\magnetram\MagnetRAMCapture.exe

  Tool priority: If multiple tools are present, the script uses the first
  one found in this order: WinPmem > DumpIt > Magnet RAM Capture.

  Output: Memory\memory_dump.raw in the collection output
  Storage: Dump size equals installed RAM (16 GB RAM = ~16 GB file).
           Ensure the output drive has enough free space.
  Timing: Adds 2-5 minutes depending on RAM size.
  Ordering: Runs FIRST to capture pristine RAM before other collection.
  Live only: Memory capture is skipped for mounted forensic images.

  If no tool is found in tools\, the script does not prompt and proceeds
  with standard artifact collection. No errors, no noise.


## Requirements

  - Windows 10 or Windows 11
  - PowerShell 5.1 or later (built into Windows)
  - Administrator privileges (the .bat launcher handles elevation)
  - No external dependencies -- no binaries to download or install


## Windows Built-In Tools Used

This script uses only tools that ship with Windows. No third-party binaries
are downloaded, bundled, or required.

  fsutil.exe           Collects USN Journal ($UsnJrnl:$J) in CSV format.
                       Used as fallback when Volume Shadow Copy fails.
                       Ships with all Windows versions.

  reg.exe              Exports registry hives (SYSTEM, SOFTWARE, SAM,
                       SECURITY) via "reg save". Produces clean hive copies
                       without requiring VSS. Ships with all Windows versions.

  wevtutil.exe         Exports event log files (.evtx) from the live system.
                       Handles locked log files properly.
                       Ships with all Windows versions.

  vssadmin.exe /       Creates and removes Volume Shadow Copy snapshots for
  Win32_ShadowCopy     accessing locked files ($MFT, NTUSER.DAT, etc.).
                       Uses WMI Win32_ShadowCopy class via PowerShell.

  robocopy.exe         Not used. Considered but requires Backup privileges
                       not available on Windows 11 Home.

  PowerShell cmdlets   Get-CimInstance (WMI queries), Get-ScheduledTask,
                       Get-ScheduledTaskInfo (task run times),
                       Get-PnpDevice / Get-PnpDeviceProperty (USB device
                       install/arrival/removal times),
                       Get-NetTCPConnection, Get-DnsClientCache,
                       Get-NetFirewallRule, Add/Remove-MpPreference
                       (Defender exclusion management).

  RegQueryInfoKey      Windows API (advapi32.dll), called through a small
  (Add-Type)           Add-Type definition to read registry key last-write
                       times (services, drivers, Run keys).


## Credits and Acknowledgments

  Buzz Hillestad,      Design, testing, forensic workflow, and artifact
  GCFE                 selection. Defined the collection categories, triage
                       methodology, USB deployment workflow, and integration
                       with the win11-timeline-builder companion project.

  Claude Code          Code generation and implementation. All PowerShell
  (Anthropic)          scripts, batch launchers, and supporting code were
                       written by Claude Code (claude.ai/code).

  Eric Zimmerman       This script's output is designed to be parsed by Eric
                       Zimmerman's forensic tools (EZ Tools) and by the
                       companion win11-timeline-builder project.
                       EZ Tools: https://ericzimmerman.github.io/

  Velocidex /          WinPmem is an open-source memory acquisition tool
  WinPmem              with a signed kernel driver. Optionally used for
                       live RAM capture when placed in the tools\ directory.
                       https://github.com/Velocidex/WinPmem

  Magnet Forensics     DumpIt and Magnet RAM Capture are free memory
                       acquisition tools. Optionally supported as
                       alternatives to WinPmem in the tools\ directory.
                       https://www.magnetforensics.com/

  KAPE                 The artifact collection categories and Defender
  (Kroll)              exclusion approach are inspired by KAPE's Targets
                       and Modules workflow.
                       https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape

  DFIR community       Artifact selection and forensic value descriptions
                       are informed by the broader DFIR community's research
                       and documentation, including SANS forensic posters
                       and the Forensic Artifact Reference.


## What It Modifies on the System

This script is read-only by design, with these minimal exceptions:

  - Creates the output directory and files (in reports\ next to the script)
  - Creates and removes a Volume Shadow Copy snapshot (for locked file access)
  - Adds and removes a temporary Windows Defender exclusion (output path only)
  - Compiles a small Add-Type helper (registry key times); Windows PowerShell
    writes and deletes temporary compiler files in %TEMP% for this
  - All modifications are cleaned up at script end, also when the run is
    stopped with Ctrl+C or ends with an error

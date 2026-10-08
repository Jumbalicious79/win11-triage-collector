# Windows 11 Forensic Triage Collector

A lightweight, dependency-free PowerShell script for collecting forensic
artifacts from a live Windows system. Pure PowerShell -- no KAPE, no external
tools required.

Designed to be used with win11-timeline-builder, which parses this script's
output into a unified chronological timeline and auto-opens it in Timeline
Explorer. Both tools are available as separate repos for independent use.

  Companion project: https://github.com/Jumbalicious79/win11-timeline-builder

Tested on Windows 11 Home Build 26200 (x64) and Windows 11 Pro 26100 (ARM64,
Parallels on Apple silicon). A typical run collects ~450-500 files in about
1-2 minutes; the zip size depends mostly on the raw $MFT (often 100 MB to
several GB). Supports live system collection and mounted forensic images.


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
        dumpit\                   <-- optional: DumpIt for memory capture
                                      (download yourself; see its README.txt)
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
    - Raw $MFT, $LogFile and $UsnJrnl:$J, read from the volume itself, when
      the image is mounted as an NTFS volume whose root is the drive letter
      (skipped for nested layouts such as E:\C\Windows)
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
      tools\                      <-- optional: memory capture tool
        dumpit\                   <-- DumpIt download extracted here
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
  Run-TriageCollector.bat fast         -- skip the raw NTFS copies and the
                                          USN journal export
  Run-TriageCollector.bat nozip        -- don't compress output
  Run-TriageCollector.bat E            -- collect from E: (mounted image)
  Run-TriageCollector.bat E fast       -- collect from E:, skip the raw NTFS
                                          copies and the USN journal export

  Note: "fast" skips the raw NTFS copies ($MFT, $LogFile, $UsnJrnl:$J) and
  the fsutil USN journal export -- the timeline builder's largest sources of
  file activity, and the largest files in the collection. Registry hives are
  always collected.

  For memory capture: extract Magnet DumpIt into tools\dumpit\ (see
  tools\dumpit\README.txt). The script prompts on live system runs when a
  capture tool is detected. See the "Optional Tools" section below.

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

If memory capture was included, the memory dump is saved next to the zip,
not inside it (it is as large as the machine's RAM):

  win11-triage-collector\
    reports\
      TriageCollection_2026-04-08_08-04.zip                (artifacts)
      TriageCollection_2026-04-08_08-04_memory_dump.dmp    (= RAM size; DumpIt)

DumpIt writes a Microsoft crash dump (.dmp); WinPmem and Magnet RAM Capture
write a raw image (memory_dump.raw).

Use -NoCompress to keep the uncompressed folder instead.

Entry names in the zip use "/" as the ZIP format requires, so tools on Linux
and macOS (unzip, Python zipfile) extract the folders too. Zips from earlier
versions run by the .bat launcher (Windows PowerShell 5.1) use "\"; Windows
tools and the timeline builder read both. If compression fails, the
incomplete zip is deleted, the uncompressed folder is kept and the log says
why.

Inside the zip:

  TriageCollection_2026-04-08_08-04\
    collection_info.json              -- host, mode, start time, time zones
    collection_log.txt                -- full run log
    collection_manifest.csv           -- SHA256, source, dest, size, source file
                                         times per file (see Output File Formats)
    systeminfo.txt                    -- system info snapshot
    Memory\                               -- only if memory capture was selected
      memory_dump.dmp / .raw          -- full RAM dump (saved separately, not in zip)
      memory_acquisition_log.txt      -- capture tool output log
    FileSystem\
      $MFT                            -- Master File Table, raw copy
      $LogFile                        -- NTFS transaction log, raw copy
      $UsnJrnl_$J                     -- USN Journal, raw copy of the
                                         allocated part (binary records)
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
          <profile>\Network\Cookies   -- cookies (current Chromium location)
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

  memory_dump.dmp    Full physical RAM capture: a Microsoft crash dump from
                     DumpIt (preferred), or memory_dump.raw from WinPmem or
                     Magnet RAM Capture -- whichever is found in tools\.
                     Dump size equals installed RAM. Runs first to capture
                     pristine memory state before other collection.
                     Requires a capture tool in tools\ -- see Optional Tools.
                     Saved separately from the zip due to size.

### FileSystem

  NTFS metafiles cannot be opened through the normal file APIs (not even in a
  Volume Shadow Copy). The script reads them straight from the volume with a
  built-in raw NTFS reader (C# compiled at run time via Add-Type, no
  third-party tools): it finds $MFT from the boot sector, then each metafile's
  file record and the clusters of its data, including data split across
  several MFT records ($ATTRIBUTE_LIST). The copies are the on-disk bytes, for
  the timeline builder's $MFT timeline and for external tools such as
  MFTECmd (see Analyzing the Output).

  $MFT          FileSystem\$MFT -- Master File Table: one record per file and
                folder, including deleted ones whose records are not yet
                reused (names, parent folders, $STANDARD_INFORMATION and
                $FILE_NAME times, sizes). Typically 100 MB to a few GB.
  $LogFile      FileSystem\$LogFile -- NTFS transaction log (recent metadata
                changes). Usually 64 MB.
  $UsnJrnl:$J   FileSystem\$UsnJrnl_$J -- USN change journal: every create,
                modify, delete, rename. $J is a sparse stream: Windows frees
                the oldest part as the journal grows, so its logical size can
                be many GB while only the newest part (typically tens of MB)
                is stored. The copy holds only that allocated part, in order;
                the freed (all-zero) part is left out. MFTECmd and similar
                tools parse this layout directly.
                The same journal is also exported as text with "fsutil usn
                readjournal ... csv" into FileSystem\$UsnJrnl_$J.txt, which
                the timeline builder parses.

  Raw copies need Administrator rights and an NTFS volume: the live system
  drive, or a mounted image whose Windows folder is at the root of its drive
  letter. Anything else (no access, damaged metadata, nested image layout)
  is logged and the collection goes on; the fsutil export runs regardless.
  -SkipLargeFiles ("fast") skips the raw copies and the fsutil export.

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
  Cookies of the Chromium-based browsers: current versions keep them in
  <profile>\Network\Cookies (collected to <profile>\Network\Cookies, with
  Network\Cookies-journal if present); the profile-root Cookies file of
  older versions is collected too when it exists.

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
                       command output, "(raw NTFS \\.\C: $MFT)" etc. for the
                       raw NTFS copies
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
  MFTECmd.exe -f "Collection\FileSystem\$UsnJrnl_$J" -m "Collection\FileSystem\$MFT" --csv ".\parsed" --csvf usn.csv
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

  - $MFT, $LogFile and $UsnJrnl:$J are read raw from the volume. On a live
    system they are copied while Windows keeps changing them, so they are a
    near point-in-time snapshot, not an atomic one (the same holds for other
    live raw-copy tools). The raw copies are skipped (logged, collection goes
    on) when the volume cannot be opened (e.g., blocked by endpoint security),
    when the target is not an NTFS volume, or for nested image layouts such
    as E:\C\Windows -- mount the image so the volume itself has a drive
    letter to get them.
    Warning: "Raw $MFT, $LogFile and $UsnJrnl:$J not collected: cannot open \\.\C: (...)"

  - Very large volumes (millions of files) can have a $MFT of several GB.
    The zip handles files that large (Zip64), but a FAT32 output drive
    (common on USB sticks) cannot hold any file over 4 GB, so on FAT32 such
    a copy, or a zip that would grow past 4 GB, fails: use an NTFS or exFAT
    output drive. When the zip step fails, the incomplete zip is deleted and
    the uncompressed collection folder is kept (see the log), so it can be
    compressed with another tool; -NoCompress skips the zip step.

  - Per-user live registry data (Run/RunOnce keys, RecentApps) covers every
    user whose hive is loaded, i.e. users logged in at collection time, not
    only the account running the collector. For users who are not logged in,
    the same keys are in their NTUSER.DAT under Registry\<user>\.

  - The temporary Defender exclusion and the shadow copy are removed even if
    the run is stopped with Ctrl+C or ends with an error. If the console
    window is closed or the machine loses power mid-run, cleanup may not get
    to run: check Windows Security exclusions and "vssadmin list shadows".

  - Locked files (live system): when a normal copy fails because a program
    has the file open, the script tries, in order:
      1. the Volume Shadow Copy (point-in-time snapshot, made on first need)
      2. a raw NTFS read: the file is looked up in the $MFT (a name index
         built on first use, a few seconds) and its data is read straight
         from the volume, which file locks don't prevent. Used for files the
         shadow copy can't provide -- created after the snapshot was taken,
         or no snapshot possible on that machine.
    A raw read is not a point-in-time snapshot: a file being written during
    the read can come out inconsistent. NTFS-compressed and EFS-encrypted
    files cannot be read this way. Empty files are skipped (there is nothing
    to collect; Chromium browsers keep 0-byte SQLite journals open). A file
    that is 0 bytes in the shadow copy is skipped the same way and is not
    counted as an error; the live file is still tried next, in case it has
    grown since the snapshot.
    Log: "Collected by raw NTFS read (file in use, not available from a
    shadow copy)"

  - NTUSER.DAT and UsrClass.dat for the active user are locked. The script
    tries reg save via HKU\SID (works for logged-in users), then VSS shadow
    copy, then direct copy. On most systems reg save succeeds. Each hive
    gets one outcome line naming the method that collected it. A locked
    file that the direct copy reads by raw NTFS read (see above) also gets
    that read's own line, with the path.
    Log: "Collected NTUSER.DAT for <user> via reg save" (or "via shadow
    copy", "via direct copy", "via raw NTFS read")

  - Hives of system service accounts (e.g., WsiAccount) are usually not
    loaded, so reg save does not apply; they are taken from the shadow copy.
    These are not real user accounts and contain minimal forensic data. If
    the shadow copy cannot provide a hive, the direct copy is tried next
    (for a locked file it falls back to a raw NTFS read). When the direct
    copy succeeds, nothing is counted as an error (if the shadow copy
    failed, the line gives its reason). Only a hive that no method
    collects gives a warning and counts as one error. If the direct copy
    logged a warning of its own ("Could not copy ..."), that warning comes
    first, and the error is still counted once.
    Log: "Collected NTUSER.DAT for WsiAccount via shadow copy"
    Warning: "Could not collect NTUSER.DAT for WsiAccount -- shadow copy: <reason>"

  - Hidden files are collected, including the Amcache.hve transaction logs
    (.LOG1/.LOG2) and the hidden NTUSER.DAT / UsrClass.dat of users who are
    not logged in. Folder listings of artifacts (Prefetch, Recent LNK files,
    jump lists, browser profiles, scheduled task XML, Defender and
    third-party AV logs) include hidden and system files. (Earlier versions
    skipped those in listings, and copied hidden files and then deleted
    them as "empty".) Amcache.hve and its logs are taken from the shadow
    copy, else by direct copy (raw NTFS read for a locked file), with one
    outcome line per file as for the user hives; if the hive is still
    dirty without its logs, the timeline builder skips Amcache parsing for
    that collection. It is normal for one of .LOG1/.LOG2 to be 0 bytes
    (Windows can write only one of them for long periods): an empty log
    holds nothing to collect, is logged as skipped (info) and is not
    counted as an error. A hive or log missing from the target altogether
    (e.g. no Amcache in an image of an older Windows) is a warning, not an
    error.
    Log: "Skipped empty file (0 bytes in the shadow copy): Windows\AppCompat\Programs\Amcache.hve.LOG2"
    Warning: "Amcache.hve not found at <path>"

  - A file is reported as not collected only when the normal copy, the
    shadow copy and the raw NTFS read all fail.
    Warning: "Could not copy (locked; shadow copy and raw NTFS read also failed)"

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
  -SkipLargeFiles  Skip the raw NTFS copies ($MFT, $LogFile, $UsnJrnl:$J)
                   and the fsutil USN journal export for faster, smaller
                   runs ("fast" in the .bat). These are the timeline
                   builder's largest sources. Registry hives are still
                   collected.
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
the repo -- their licenses don't allow redistribution, so you download and
place them yourself. The repo ships each expected tool folder with a
README.txt (download link and layout); git ignores everything else in tools\,
so a downloaded tool is never committed.

  win11-triage-collector\
    tools\
      dumpit\                      <-- in the repo: README.txt only
        README.txt                 <-- where to get DumpIt and how it's used
        ARM64\DumpIt.exe           <-- you add these (extract the download)
        x64\DumpIt.exe
        x86\DumpIt.exe

Each tool gets its own subfolder, matching the timeline builder's layout.
Tools placed here travel with the script on USB drives. If a tool is not
present, the script skips that capability and continues normally.


### Memory Capture Setup

Memory capture requires a kernel-mode driver to read physical RAM. The
script auto-detects supported tools in the tools\ directory. On a live
system, if a tool is found, the script prompts you to include memory
capture before collection begins.

  Recommended: Magnet DumpIt (free, signed; native x86, x64 and ARM64)
    1. Request it (registration form; the link arrives by email):
       https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/
    2. Extract the download into win11-triage-collector\tools\dumpit\ as-is
       (tools\dumpit\ARM64\DumpIt.exe, tools\dumpit\x64\DumpIt.exe, ...)
    The script runs the build that matches the CPU, with
    /TYPE DMP /NOCOMPRESS /QUIET, producing a Microsoft crash dump.
    Details: tools\dumpit\README.txt

  Alternative: WinPmem (open-source, signed driver; x86/x64 only)
    1. Download from: https://github.com/Velocidex/WinPmem/releases
    2. Download the latest winpmem_mini_x64.exe (or winpmem_x64.exe)
    3. Rename to winpmem.exe
    4. Place in: win11-triage-collector\tools\winpmem\winpmem.exe

  Alternative: Magnet RAM Capture (Magnet Forensics, free; x86/x64 only)
    1. Download from: https://www.magnetforensics.com/resources/magnet-ram-capture/
    2. Place in: win11-triage-collector\tools\magnetram\MagnetRAMCapture.exe

  Tool priority: If multiple tools are present, the script uses the first
  one found in this order: DumpIt > WinPmem > Magnet RAM Capture.

  Windows on ARM: a capture tool loads a kernel driver, and x64 drivers don't
  load on ARM64 Windows. On ARM64 the script only uses ARM64 builds (DumpIt)
  and skips the others with a note.

  Output: Memory\memory_dump.dmp (DumpIt) or memory_dump.raw, saved next to
          the zip as <collection>_memory_dump.dmp / .raw
  Storage: Dump size equals installed RAM (16 GB RAM = ~16 GB file).
           Ensure the output drive has enough free space.
  Timing: Adds 2-5 minutes depending on RAM size.
  Ordering: Runs FIRST to capture pristine RAM before other collection.
  Live only: Memory capture is skipped for mounted forensic images.
  Analysis: win11-timeline-builder analyzes x64 dumps with Volatility 3.
            Volatility 3 cannot analyze Windows ARM64 memory; open ARM64
            dumps in WinDbg instead.

  If no tool is found in tools\, the script does not prompt and proceeds
  with standard artifact collection. No errors, no noise.


## Tests

  tests\Test-RawCopy.ps1 (run as Administrator; also runs in CI)
    Creates test files on the system drive, locks them so a normal copy
    fails, and checks that the collector still collects them byte for byte
    by reading the volume directly (the fallback after the shadow copy):
    files in clusters and inside the MFT record, a non-ASCII name, a sparse
    file, a file extended past its written data, and an NTFS-compressed
    file, which the raw read must decline cleanly.

  tests\Test-ShadowCopy.ps1 (no admin needed; also runs in CI)
    Checks how a copy from the shadow copy is reported, with a folder
    standing in for the snapshot: a hidden file is copied and listed in the
    manifest with its hash and original time; an empty one is logged as
    skipped and is not an error; a missing one is "Not present"; a locked
    one gives a warning with the reason and counts one error; with -Quiet
    nothing is logged or counted.
      powershell -ExecutionPolicy Bypass -File tests\Test-ShadowCopy.ps1

  tests\Test-CollectionLogging.ps1 (no admin needed; also runs in CI)
    Checks what is logged and counted when a hive (Amcache.hve and its
    logs, NTUSER.DAT, UsrClass.dat) is taken from the shadow copy or by
    direct copy, with folders standing in for the snapshot and the volume
    and a stand-in for the raw NTFS read: one outcome line per hive naming
    the method (also "via raw NTFS read" for a locked file); an empty one
    is info; a shadow copy failure that the direct copy recovers is no
    error; a hive that no method collects is a warning and one error, even
    when the direct copy has logged and counted its own failure. Also
    checks that the LNK, jump-list, Prefetch and task XML counts include a
    file saved under a shortened name or with [ ] in its name.
      powershell -ExecutionPolicy Bypass -File tests\Test-CollectionLogging.ps1

  tests\Test-CollectionZip.ps1 (no admin needed; also runs in CI)
    Zips a small folder the way the collector zips the collection and
    checks the zip: every entry name uses "/" and starts with the folder
    name; an empty folder has its own entry; a hidden system file, a
    non-ASCII name and a name with [ ] are included; contents (SHA256) and
    file times (within 2 seconds) match. A zip path inside the folder is
    refused, and a zip that fails (a locked file) is deleted. In Windows
    PowerShell 5.1 it also checks that ZipFile.CreateFromDirectory, used by
    earlier versions, writes "\" there.
      powershell -ExecutionPolicy Bypass -File tests\Test-CollectionZip.ps1

  Planted-activity test (both tools, end to end, on a live machine)
    1. In a normal (not elevated) PowerShell window, as the user to test:
         powershell -ExecutionPolicy Bypass -File tests\Invoke-PlantedActivity.ps1
       It does harmless, recognizable actions, all named TriageE2E_<id>: runs
       a renamed copy of hostname.exe, backdates (timestomps) another copy,
       adds a file to Recent items, creates and deletes a file, adds a Run
       value and a disabled scheduled task, and opens an Edge page.
       -Eicar also writes the EICAR antivirus test file (Defender detects
       and quarantines it); -NoBrowser skips Edge.
    2. Run-TriageCollector.bat, then Run-TimelineBuilder.bat on the new
       collection (win11-timeline-builder next to this repository).
    3. powershell -ExecutionPolicy Bypass -File tests\Test-PlantedActivity.ps1
       Finds each action in the timeline by source and time. Required checks
       fail the test; best-effort ones (BAM, Amcache, ShimCache, UserAssist,
       jump list, deleted MFT record) depend on when Windows writes them and
       are only reported. Restart before collecting to get ShimCache.
    4. powershell -ExecutionPolicy Bypass -File tests\Invoke-PlantedActivity.ps1 -Cleanup
       Removes the Run value, the task, the Recent shortcut and the files.


## Requirements

  - Windows 10 or Windows 11
  - PowerShell 5.1 or later (built into Windows)
  - Administrator privileges (the .bat launcher handles elevation)
  - No external dependencies -- no binaries to download or install


## Windows Built-In Tools Used

This script uses only tools that ship with Windows. No third-party binaries
are downloaded, bundled, or required.

  fsutil.exe           Exports the USN Journal ($UsnJrnl:$J) as CSV-style
                       text ($UsnJrnl_$J.txt), next to the raw copy.
                       Ships with all Windows versions.

  reg.exe              Exports registry hives (SYSTEM, SOFTWARE, SAM,
                       SECURITY) via "reg save". Produces clean hive copies
                       without requiring VSS. Ships with all Windows versions.

  wevtutil.exe         Exports event log files (.evtx) from the live system.
                       Handles locked log files properly.
                       Ships with all Windows versions.

  vssadmin.exe /       Creates and removes Volume Shadow Copy snapshots for
  Win32_ShadowCopy     accessing locked files (NTUSER.DAT, browser
                       databases, etc.).
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

  Raw NTFS reader      Built into the script (C# compiled via Add-Type). Opens
  (CreateFile,         the volume (\\.\C:) read-only with the kernel32.dll
  Add-Type)            CreateFile API and reads $MFT, $LogFile and
                       $UsnJrnl:$J from the NTFS structures directly.


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

  Magnet Forensics     DumpIt (the preferred capture tool, with native
                       x86/x64/ARM64 builds) and Magnet RAM Capture are free
                       memory acquisition tools, used when placed in the
                       tools\ directory. Not redistributed with this repo.
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
  - Compiles small Add-Type helpers (registry key times, raw NTFS reader);
    Windows PowerShell writes and deletes temporary compiler files in %TEMP%
    for this
  - All modifications are cleaned up at script end, also when the run is
    stopped with Ctrl+C or ends with an error

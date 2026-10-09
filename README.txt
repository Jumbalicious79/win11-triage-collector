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
     With memory capture the dump, as large as the RAM, goes there too:
     FAT32 (common on USB sticks) cannot hold a file of 4 GB or more, so
     use an NTFS or exFAT drive. The memory prompt checks the free space
     first and offers another drive when the dump does not fit.
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
    - SRUM database and its logs (Windows\System32\sru)
    - Defender DetectionHistory files and quarantine metadata
      (Quarantine\Entries; never the quarantined files)
    - Email: attachment copies and listings (see Email below)

  Skipped (requires live system):
    - Network state (DNS, ARP, TCP connections, firewall, Wi-Fi)
    - Live registry queries (Run keys, BAM, RecentApps, USB registry,
      mounted devices) -- the same data is in the collected hives (the
      timeline builder reads MountedDevices from the SYSTEM hive)
    - USB PnP device timestamps (usb_storage_devices.csv)
    - Scheduled task run times (scheduled_tasks.csv)
    - WMI queries (services, startup commands, drivers, WMI subscriptions)
    - Defender cmdlets (detections, status, preferences)
    - OutlookSecureTempFolder lookup (the Content.Outlook folders are
      listed instead; the value is in the collected NTUSER.DAT)
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
  powershell -ExecutionPolicy Bypass -NoProfile -File "path\to\triage-collector.ps1" -MemoryOutputPath D:\TriageMemory

  -MemoryOutputPath and -MinFreeSpaceGB (see Parameters) are only available
  this way: the .bat passes only the drive letter and fast / nozip. Its
  memory prompt offers another drive for the dump by itself when needed.


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

With -MemoryOutputPath <folder> (or another drive chosen at the memory
prompt) the dump is written to that folder from the start, under the same
<collection>_memory_dump.dmp name; Memory\memory_acquisition_log.txt stays
in the collection. The summary names the dump's location (also with
-NoCompress). The timeline builder finds the dump through the collection
manifest: collection_manifest.csv records its full path and size wherever
it ends up (next to the zip, or in that folder). -MemoryDumpPath is needed
only when the dump is moved or the collection is analyzed on another
machine; copying the dump next to the zip under its
<collection>_memory_dump.dmp name works too.

Use -NoCompress to keep the uncompressed folder instead.

Entry names in the zip use "/" as the ZIP format requires, so tools on Linux
and macOS (unzip, Python zipfile) extract the folders too. Zips from earlier
versions run by the .bat launcher (Windows PowerShell 5.1) use "\"; Windows
tools and the timeline builder read both. A file already at the zip path
(an earlier run with the same -OutputPath) is replaced, and the log says so.
If compression fails, the incomplete zip is deleted, the uncompressed folder
is kept and the log says why; a memory dump moved out for the zip is moved
back into Memory\, and its manifest row with it. If the memory dump cannot
be moved out of the collection folder (another program has it open), the
folder is not zipped, so the dump does not end up in the zip; the log and
the summary say where it is.

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
      Windows PowerShell.evtx         -- classic PowerShell log
      Microsoft-Windows-WMI-Activity%4Operational.evtx
      Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx
      Microsoft-Windows-NTLM%4Operational.evtx
      Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx
      Microsoft-Windows-Shell-Core%4Operational.evtx
      (Sysmon, Task Scheduler, OAlerts -- if present on the system)
    Execution\
      Prefetch\                       -- all .pf files (program execution evidence)
      RecentApps\<user>\RecentApps.reg  -- per logged-in user, only if the key
                                         exists (absent on Windows 11)
      bam_entries.csv                 -- BAM: per-user program paths with
                                         decoded last-execution times (UTC)
      appcompat_cache.reg             -- ShimCache execution artifacts
      SRUM\                           -- SRUDB.dat (SRUM database) with its
                                         checkpoint, logs and flush map
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
          <profile>\Preferences, Secure Preferences, Favicons, Sessions\,
            Extensions\<id>\<version>\manifest.json
                                      -- settings, extensions, open and
                                         closed tabs (secrets blanked)
          Local State, Snapshots\     -- browser settings; pre-update copies
                                         of History and Favicons
        Edge\                         -- same artifacts as Chrome
      (Firefox -- if installed; also extensions.json, addons.json, prefs.js
       and session files)
    USB\
      setupapi.dev.log                -- device installation log (first-connect times)
      setupapi.dev.<yyyymmdd_hhmmss>.log  -- older logs rotated by Windows
                                         (all present are collected)
      usb_storage_devices.csv         -- USB storage devices (incl. disconnected)
                                         with first install / arrival / removal
                                         times (UTC)
      usb_storage_devices.txt         -- USB storage device registry entries
      usb_devices.txt                 -- all USB device entries
      mounted_devices.csv             -- MountedDevices, decoded: each drive
                                         letter and volume GUID with its GPT
                                         partition, MBR disk and offset, or
                                         device path
      mounted_devices.txt             -- same rows as text
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
        DetectionHistory\<nn>\        -- one file per Defender detection
        Quarantine\Entries\           -- quarantine metadata (encrypted)
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
    Email\                            -- per user, only where email data exists
      <user>\
        Outlook\
          outlook_temp_files.csv      -- classic Outlook attachment temp
                                         folder listing (Content.Outlook)
          SecureTemp\<folder>\        -- copied attachments (capped)
          outlook_data_files.csv      -- OST/PST files (listed, not copied)
        NewOutlook\
          olk_files.csv               -- listing of the new Outlook's Olk
          UserSettings.json           -- signed-in accounts
          Attachments\                -- copied attachments (capped)
        Thunderbird\
          profiles.ini
          <profile>\prefs.js          -- account settings
          <profile>\global-messages-db.sqlite
                                      -- search index, only with
                                         -IncludeThunderbirdIndex
          thunderbird_mail_files.csv  -- Mail\ and ImapMail\ listing
        WindowsMail\
          windows_mail_files.csv      -- Windows Mail store listing


## What Gets Collected

### Memory (opt-in, live system only)

  memory_dump.dmp    Full physical RAM capture: a Microsoft crash dump from
                     DumpIt (preferred), or memory_dump.raw from WinPmem or
                     Magnet RAM Capture -- whichever is found in tools\.
                     Dump size equals installed RAM. Runs first to capture
                     pristine memory state before other collection.
                     Requires a capture tool in tools\ -- see Optional Tools.
                     Saved separately from the zip due to size. The free
                     space is checked before the capture and the dump
                     after it (see Memory Capture Setup).
  Acquisition log    memory_acquisition_log.txt: the capture tool's output,
                     for DumpIt the only record of its SHA-256 of the dump
                     and its NtStatus. Kept in the zip and listed in the
                     manifest.

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
  Windows PowerShell         Classic PowerShell log: engine starts with the
                             command line that started them (400), pipeline
                             details (800), PowerShell 2.0 downgrades.
  WMI-Activity               WMI event subscriptions (permanent ones are a
                             persistence method).
  RDP client                 Outbound RDP connections made from this machine.
  NTLM                       NTLM authentication, in and out (written only
                             when NTLM auditing is enabled).
  Windows Firewall           Firewall rule and setting changes.
  Shell-Core                 Run / RunOnce and Active Setup commands started
                             at logon.
  OAlerts (if Office)        Alerts shown by Office applications (macro and
                             Protected View prompts, ...) and add-in events.

  The seven logs above, from Windows PowerShell on, are collected like the
  others (wevtutil on a live system, a file copy from a mounted image), but
  with a 256 MB limit: their default maximum size is 1 MB (15 MB for Windows
  PowerShell), so a larger one was enlarged on purpose. Of such a log only
  the newest events, about 256 MB of them, are exported with wevtutil (also
  from a mounted image's .evtx file), with a warning that names the record
  range; one whose events cannot be read is skipped with a warning. A log
  that does not exist on the target is an info line. The other logs have no
  size limit.

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
  SRUM                       System Resource Usage Monitor: bytes sent and
                             received and CPU/disk use per application and
                             user, recorded about once an hour and usually
                             kept for 30-60 days. Every file of
                             Windows\System32\sru goes to Execution\SRUM\:
                             the ESE database SRUDB.dat with its checkpoint
                             (SRU.chk), logs (SRU*.log, SRUtmp.log,
                             SRUres*.jrs) and flush map (SRUDB.jfm), so the
                             timeline builder can replay the logs into a
                             copy of the open database. Live system: when
                             SRUDB.dat can be read from the shadow copy,
                             every file comes from there (one moment);
                             otherwise from the volume (raw NTFS read if
                             locked), and the log says they may be from
                             slightly different moments. Files over 16 GB
                             (2 GB with -SkipLargeFiles) are skipped and
                             logged. Live system and mounted images.

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
  and Firefox. Per-user, per-profile (Default, Profile <n> and the Guest
  profile).
  Cookies of the Chromium-based browsers: current versions keep them in
  <profile>\Network\Cookies (collected to <profile>\Network\Cookies, with
  Network\Cookies-journal if present); the profile-root Cookies file of
  older versions is collected too when it exists.

  Extensions, sessions, settings and history snapshots, for the timeline
  builder. Every file has a size cap; skipped files are logged.
    Chromium, per profile    Preferences and Secure Preferences (settings,
                             installed extensions; 32 MB each), Favicons
                             (256 MB), Sessions\Session_* and Tabs_* (also
                             the older Current/Last Session and Tabs files;
                             newest first, 64 MB in all), and
                             Extensions\<id>\<version>\manifest.json with
                             the default locale's messages.json (1 MB each;
                             no other locales, no extension code).
    Chromium, per browser    Local State (32 MB) and the pre-update copies
                             Snapshots\<version>\<profile>\History and
                             Favicons, which can hold history deleted since
                             (newest version first, 1 GB in all).
    Firefox, per profile     extensions.json and addons.json (32 MB each),
                             prefs.js (16 MB), sessionstore.jsonlz4 and
                             sessionstore-backups\ (newest first, 64 MB in
                             all).

  Browser secrets are blanked in the copies of these files, so the copies
  are not byte-identical to the originals (the manifest has the original
  path and times and the hash of the copy; the log names each file):
    - Local State, Preferences, Secure Preferences: the encrypted keys that
      protect saved passwords and cookies (os_crypt), password hashes, the
      sync encryption keys, and every member named like a token, salt or
      encrypted key
    - Firefox prefs.js: the value of every pref whose name contains
      "token", "secret", "password" or "userAgentID"
    - Chromium session files: the page state (form contents, POST data) of
      every entry is zeroed; URLs, titles and times are kept
    - Firefox session files: session cookies, form data, session storage,
      POST data, page state and typed address-bar text are emptied (the
      copy is a valid mozLz4 file stored uncompressed, so it is larger)
  A file that cannot be read well enough to blank it (damaged, or an
  encrypted Chromium session file) is not collected. These files are read
  in place with sharing, without the shadow copy or raw NTFS fallback.
  Login Data, Cookies and Web Data are still copied unchanged.

  With -IncludeSecrets the blanking above is skipped: every one of these
  files is copied unaltered through the normal copy path (with the shadow
  copy / raw NTFS fallbacks), so each copy is byte-for-byte the original and
  its manifest hash equals the original's. The size caps still apply. See
  "Secrets" below and the -IncludeSecrets parameter.

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
  Mounted devices            MountedDevices, decoded (mounted_devices.csv):
                             each drive letter and volume GUID with the GPT
                             partition GUID, the MBR disk signature and
                             partition offset, or the device path (for a USB
                             disk with vendor, product and serial). Live
                             system only; for a mounted image the timeline
                             builder reads the collected SYSTEM hive.

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
                             From the live system and mounted images also
                             the DetectionHistory files (one per detection:
                             threat, resources, user, process, SHA-256,
                             times; Defender deletes them after 15 days by
                             default) and the quarantine metadata in
                             Quarantine\Entries (original path, threat
                             name, quarantine time; encrypted, decoded by
                             the timeline builder). Files over 1 MB and
                             empty files are skipped, and at most the newest
                             2,000 per folder are collected (logged). The
                             quarantined files themselves
                             (Quarantine\ResourceData) and
                             Quarantine\Resources are never collected.
  Third-party AV logs        Auto-detected and collected if installed:
                             Symantec SEP, CrowdStrike Falcon, SentinelOne,
                             Carbon Black, Malwarebytes, Sophos, ESET,
                             Kaspersky, McAfee/Trellix, Bitdefender, Trend Micro,
                             Webroot, Norton, Cylance.
  AV event logs              Windows event logs from AV products (Symantec,
                             CrowdStrike) collected via wevtutil if present.

### Email

  Per user profile, on the live system and on mounted images, into
  Email\<user>\ (only for users with email data; others get an info line).
  Mail contents are never copied: OST/PST files, Thunderbird mailboxes and
  the new Outlook's and Windows Mail's mail stores are only listed. Parsing
  OST/PST content is deferred.

  Outlook attachments        Classic Outlook saves an attachment to its
  (classic)                  temp folder (INetCache\Content.Outlook\
                             <random>\) when it is opened. Every file there
                             is listed in Outlook\outlook_temp_files.csv and
                             copied to Outlook\SecureTemp\. Live system: the
                             folder each logged-on user's Outlook is set to
                             (OutlookSecureTempFolder under HKU\<SID>\
                             Software\Microsoft\Office\<version>\Outlook\
                             Security) is read too, with that user's own
                             environment variables; a value that is not a
                             folder below a drive or share root (such as
                             "C:\") is refused and logged.
  New Outlook (olk)          AppData\Local\Microsoft\Olk: UserSettings.json
                             (signed-in accounts) and Attachments\ (opened,
                             sent and received attachments) are copied; the
                             whole folder is listed in
                             NewOutlook\olk_files.csv (its mail data in
                             EBWebView\ is listed, not copied).
  Outlook data files         *.ost / *.pst in AppData\Local\Microsoft\Outlook
                             and *.pst in Documents\Outlook Files (also
                             under OneDrive*\): listed in
                             Outlook\outlook_data_files.csv, never copied.
  Thunderbird                profiles.ini and each profile's prefs.js
                             (account settings) are copied; Mail\ and
                             ImapMail\ are listed in
                             Thunderbird\thunderbird_mail_files.csv. The
                             search index global-messages-db.sqlite (with
                             its -wal/-journal, up to 1 GB) is copied only
                             with -IncludeThunderbirdIndex, because it holds
                             the text of the indexed messages; without the
                             switch only its size is logged.
  Windows Mail               The app's LocalState and AppData\Local\Comms\
                             UnistoreDB are listed in
                             WindowsMail\windows_mail_files.csv.

  Caps: attachments are copied newest first, up to 50 MB per file, 500 MB
  per user (both Outlooks together) and 2 GB for all users together (10 MB,
  100 MB and 500 MB with -SkipLargeFiles). A listing stops at 20,000 files
  per folder (attachment folders keep the newest). Skipped files are logged
  with the reason (the first 25 per user); all of them are in the listing
  CSVs. Junctions and symbolic links are never followed, and OneDrive
  placeholders are listed but not read (reading one would download it).

  The copied attachments are files someone opened, sent or received by mail
  and can be malware; handle the collection accordingly.

### Secrets (opt-in: -IncludeSecrets, authorized examinations only)

  Collected only with -IncludeSecrets, into a top-level Secrets\ folder, on
  both live systems and mounted images. This is the DPAPI credential material
  an examiner needs to decrypt the unredacted browser copies (and the user's
  other DPAPI-protected data) offline.

    Per user (Secrets\<user>\...)
      AppData\Roaming\Microsoft\Protect    DPAPI master keys: the <SID>\
                                           subfolder (the master key GUID
                                           files, including hidden/system
                                           ones), Preferred and CREDHIST
      AppData\Roaming\Microsoft\Credentials   roaming credential blobs
      AppData\Local\Microsoft\Credentials     local credential blobs
      AppData\Local\Microsoft\Vault            Windows Vault (vcrd/vpol)
    System (Secrets\System\...)
      System32\Microsoft\Protect\S-1-5-18  the machine DPAPI master keys and
                                           their User\ subfolder. These are
                                           hidden/system files that current
                                           Windows lets administrators read, so
                                           they copy directly; on a hardened
                                           system where access is denied, the
                                           shadow-copy / raw-NTFS fallback is a
                                           safety net and anything that still
                                           cannot be read is logged.

  All of these files are small. A shared total cap guards against anything
  unexpected and skips are logged; junctions and symbolic links out of a
  profile are never followed (a credential folder that is itself a link is
  skipped and logged). Collected copies keep the original path and times in
  the manifest, and (unlike the blanked browser copies) their hashes match the
  originals.

  Not collected: SYSTEM-account Credential Manager and machine Vault stores
  (systemprofile and ServiceProfiles AppData, ProgramData\Microsoft\Vault).
  The machine (S-1-5-18) master keys above decrypt them, but the vaults
  themselves are out of scope here; collect them separately if a case needs
  them.

  Why this is enough for offline decryption of the user's data: the per-user
  Protect master keys are encrypted with a key derived from the user's
  password (or escrowed to the domain's DPAPI backup key), so with the user's
  password or the domain backup key the saved passwords and session cookies in
  the unredacted browser copies can be decrypted on the analysis machine --
  the Registry hives are not needed for that. The machine (S-1-5-18) master
  keys instead need DPAPI_SYSTEM from the SECURITY hive, unlocked with the boot
  key from the SYSTEM hive; SAM holds local password hashes. SYSTEM, SECURITY
  and SAM are collected by the Registry category (selected by default), so for
  the machine keys include that category. The one thing none of this gives you
  is Chrome/Edge App-Bound Encryption, which can only be undone on the live
  machine (see Known Limitations).

  A prominent warning is logged at the start of a run with -IncludeSecrets:
  the collection then holds secrets equivalent to a password store and must
  be handled, stored and transferred accordingly.


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
  SecretsIncluded      true when the run used -IncludeSecrets: the browser
                       copies are unredacted and the collection holds the
                       Secrets\ folder (DPAPI credential material). The
                       timeline builder logs one line when this is true and
                       reads nothing under Secrets\.
  ThunderbirdIndexIncluded  true when the run used -IncludeThunderbirdIndex
                       (Thunderbird's search index was copied).

SecretsIncluded and ThunderbirdIndexIncluded are additive fields;
SchemaVersion stays 1. The timeline builder uses the time-zone and culture
fields to convert local-time text (USN journal, setupapi logs) correctly even
when the analysis machine uses a different time zone or locale.

### collection_manifest.csv

  SHA256               Hash of the collected copy
  SourcePath           Original path; "HKLM\..." / "HKU\..." for reg save,
                       "(shadow)..." for shadow copies, "(command: ...)" for
                       command output, "(raw NTFS \\.\C: $MFT)" etc. for the
                       raw NTFS copies, "(memory dump via <tool>)" and
                       "(memory capture tool output: <tool>)" for the memory
                       dump and Memory\memory_acquisition_log.txt
  DestPath             Full path of the copy at collection time; for the
                       memory dump, where it is at the end of the run (next
                       to the zip, in the -MemoryOutputPath folder, or in
                       Memory\ when the folder is not zipped). The timeline
                       builder finds the dump through this row.
  SizeBytes            Size of the copy
  CollectedAt          Collector's local time when the file was recorded
  RelativePath         Path inside the collection, e.g.
                       Execution\Prefetch\CMD.EXE-0BD30981.pf; blank for a
                       memory dump outside the collection (next to the zip,
                       or written to -MemoryOutputPath)
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

### USB\mounted_devices.csv  (live system only)

One row per value of HKLM\SYSTEM\MountedDevices, the key that maps drive
letters (\DosDevices\E:) and volume GUIDs (\??\Volume{...}) to the volumes
they belong to. Entries of devices that are no longer connected stay in it.

  Name                 Value name, e.g. \DosDevices\E: or \??\Volume{...}
  Kind                 How the data was decoded:
                         GPT         a GPT partition (also dynamic volumes)
                         MBR         a partition on an MBR disk
                         DevicePath  a device path, e.g. a USB disk
                         Other       none of these (see HexData)
  DiskSignature        MBR: disk signature, 8 hex digits
  PartitionOffset      MBR: start of the partition, in bytes from the start
                       of the disk
  PartitionGuid        GPT: partition GUID, {...}
  DevicePath           DevicePath: the path as stored, e.g.
                       _??_USBSTOR#Disk&Ven_...&Prod_...&Rev_...#<serial>&0#{...}
                       (a "/" in a name is stored as "#": Prod_SD#MMC is the
                       product "SD/MMC")
  DataLength           Size of the value data in bytes (0 for a value that is
                       not binary; its data is in HexData)
  HexData              The value data as hex (as text for a value that is
                       not binary)
  KeyLastWriteUtc      Last-write time of the key (the whole key, not the
                       single value)

mounted_devices.txt lists the same rows as text. Earlier versions wrote only
mounted_devices.txt, which showed the first 4 bytes of each value. The
volume GUIDs also appear under each user's MountPoints2 key (NTUSER.DAT);
MountedDevices is what links them to a disk or a device.

### Email\<user>\...\*_files.csv  (live system and mounted images)

outlook_temp_files.csv, outlook_data_files.csv, olk_files.csv,
thunderbird_mail_files.csv and windows_mail_files.csv, one row per file:

  User                 Profile folder name
  Program              "Classic Outlook", "New Outlook", "Thunderbird" or
                       "Windows Mail"
  Store                SecureTemp (attachment temp folder), DataFile
                       (OST/PST), Olk, ThunderbirdMail or WindowsMail
  Profile              Thunderbird profile folder (blank otherwise)
  Path                 Full original path
  RelativePath         Path below the listed folder
  SizeBytes            File size
  CreatedUtc           Created / modified / accessed times of the file,
  ModifiedUtc          read before it was copied
  AccessedUtc
  Status               Copied; Listed (listing only, by design); "Skipped:
                       <reason>" (over a cap, empty file, link or cloud
                       placeholder); "Not copied: copy failed (see
                       collection_log.txt)"
  CollectedAs          Path of the copy inside the collection (Copied rows)


## Analyzing the Output

### With win11-timeline-builder (recommended)

The fastest path from collection to analysis:

  1. Double-click Run-TimelineBuilder.bat (no arguments needed)
  2. It auto-finds triage zips in the sibling reports\ directory
  3. Pick a collection number
  4. If the collection's memory dump is found (next to the zip, or where
     collection_manifest.csv says it was written, e.g. D:\TriageMemory)
     and Volatility 3 is installed, the script prompts to include memory
     analysis
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

  - Very large volumes (millions of files) can have a $MFT of several GB,
    and the SRUM database (copied up to 16 GB) can also pass 4 GB.
    The zip handles files that large (Zip64), but a FAT32 output drive
    (common on USB sticks) cannot hold any file over 4 GB, so on FAT32 such
    a copy, or a zip that would grow past 4 GB, fails: use an NTFS or exFAT
    output drive. When the zip step fails, the incomplete zip is deleted and
    the uncompressed collection folder is kept (see the log), so it can be
    compressed with another tool; -NoCompress skips the zip step.

  - Memory capture is skipped, and counted as an error, when the dump would
    not fit where it goes: less than 1 GB would be left, or the drive is
    FAT32 and the dump is 4 GB or more. It is also skipped as an error when
    a file is already at the dump's path (an earlier dump is never
    overwritten). The other artifacts are still collected. With less than
    the system drive's reserve left it runs with a warning (on a run
    without the prompt, e.g. -Categories Memory).
    Error: "Memory capture skipped: less than 1 GB would be left free on C:\. ..."
    Error: "Memory capture skipped: a file is already at <dump path> (an earlier run?). ..."
    Warning: "Capturing anyway: C:\ would be left with ~3.9 GB free, less than the 20 GB to keep free on the system drive. ..."

  - A memory dump that fails the checks after the capture (see Memory
    Capture Setup) is an error, is not recorded in the manifest and is not
    zipped: an empty one is deleted, anything else is renamed to
    <name>.incomplete -- for a dump in Memory\, next to the collection
    folder (<collection>_memory_dump.dmp.incomplete); for one written with
    -MemoryOutputPath (or to a drive chosen at the prompt), in that folder
    (<collection>_memory_dump.dmp.incomplete there). If it cannot be
    renamed it is deleted. One that can be neither renamed nor deleted
    (another program has it open) is tried again at the end of the run; if
    it is then still in the collection folder, the folder is not zipped.
    The summary names a failed dump as INCOMPLETE; one still under the
    dump's name must be deleted by hand before the collection is analyzed.
    Error: "Memory capture failed: DumpIt reported NtStatus 0xC000007F; ..."
    Warning: "Could not delete the incomplete memory dump, delete it by hand (it is not complete, do not analyze it): ..."

  - The memory dump's row in collection_manifest.csv is changed when the
    dump is moved next to the zip (and back if the zip fails). If the
    manifest cannot be changed (another program has it open), it is kept
    as it was, the row still names the path in Memory\, and the log warns.
    The dump is still next to the zip, where the timeline builder also
    looks.
    Warning: "Could not update the memory dump's row in collection_manifest.csv, it still names ...: ..."

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

  - Sysmon, Task Scheduler and OAlerts logs only collected if present on the
    system. Sysmon and Task Scheduler are not installed by default on
    Windows 11 Home; OAlerts.evtx exists only where Office is installed.
    Message: "Skipping Microsoft-Windows-Sysmon%4Operational.evtx (not present on target)"

  - The Phase 2 event logs (Windows PowerShell, WMI-Activity, RDP client,
    NTLM, Firewall, Shell-Core, OAlerts) have a 256 MB limit; of a larger
    one only the newest events are collected.
    Warning: "Collected only the newest events of <log>.evtx (<n> MB, over
    the 256 MB limit for this log): records <first>-<newest> of
    <oldest>-<newest>"

  - SRUM: on a live system SRUDB.dat is open, so its copy is normally in
    "dirty shutdown" state; its logs are collected with it from the same
    shadow copy and the timeline builder replays them into a temp copy.
    When SRUDB.dat cannot be read from the shadow copy (the line gives the
    reason when the copy failed), the files come from the volume and may be
    from slightly different moments; the builder may then have to repair
    its copy, which can lose the newest records. A file that is 0 bytes in
    the shadow copy is skipped with an info line and is not counted as an
    error (it is not taken from the volume instead, so all files stay from
    one moment); a failed copy from the shadow copy gives a warning with
    the reason. A system without the sru folder gets an info line, not a
    warning.
    Message: "SRUDB.dat could not be read from the shadow copy -- the SRUM files are copied from the volume ..."
    Warning: "Skipped SRUM file ... larger than the 16384 MB size cap"

  - Copied email attachments can be malware. Antivirus on the analysis
    machine may quarantine them when the zip is extracted; the listing CSVs
    and the manifest still record them.

  - The collection manifest hashes are computed on destination copies, not source
    files. For "reg save" exports, the hash represents the saved snapshot.
    Browser settings and session files are copied with their secret values
    blanked (see Browser), so their hashes do not match the originals.
    Log: "Collected with N secret value(s) blanked (keys, tokens, password
    hashes): <path>"
    With -IncludeSecrets these files are copied unaltered instead, so their
    manifest hashes DO match the originals (see Secrets).

  - -IncludeSecrets (authorized examinations only): the collection holds
    DPAPI credential material (Secrets\) and unredacted browser files, i.e.
    secrets equivalent to saved passwords and session cookies. Handle, store
    and transfer the whole collection like a password store. A prominent
    warning is logged at the start of such a run.
    Warning: "-IncludeSecrets is set: browser settings and session files are
    collected UNREDACTED ..."

  - App-Bound Encryption (Chrome/Edge): newer Chromium versions wrap the
    profile encryption key with an App-Bound Encryption key that is itself
    tied to the machine and can only be unwrapped by code running as the
    logged-in user on that live machine. -IncludeSecrets does NOT try to work
    around this: it collects the DPAPI material (which still protects older
    keys and everything else), but App-Bound-protected Chrome/Edge passwords
    and cookies cannot be decrypted from an offline copy. Decrypt those on the
    live machine before collecting if the case needs them.

  - The system DPAPI master keys (System32\Microsoft\Protect\S-1-5-18) are
    hidden/system files that current Windows lets administrators read, so they
    are normally copied directly. On a hardened system where access is denied,
    the collector falls back to the shadow copy / raw NTFS read (the raw read
    bypasses the ACL); if a folder there cannot even be listed (a shadow copy
    preserves the volume's ACLs, so the listing fallback does not get past
    them), what could not be read is logged and the run goes on.
    Warning: "Could not list (collected credential material may be incomplete): <path>"


## Legal and Authorization

IMPORTANT: Only run this script on systems you are authorized to examine.

  - Obtain written authorization before collecting forensic artifacts.
  - This script accesses sensitive data including password databases (SAM),
    security policies, browser credentials, email attachments, and user
    activity history.
  - -IncludeSecrets additionally collects DPAPI master keys, Windows
    Credentials and Vault, and copies the browser settings/session files
    unredacted. With SAM/SECURITY and the user's password or the domain DPAPI
    backup key, this is enough to decrypt saved passwords and session cookies
    offline. Use it only where that is authorized (e.g. infostealer and
    session/token-theft cases, authorized cloud-evidence access, and evidence
    integrity where copies must hash-match the originals), and treat the
    output as a password store.
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
                   collected. Also lowers the SRUM cap from 16 GB to 2 GB
                   per file and the email attachment caps to 10 MB per
                   file, 100 MB per user and 500 MB in all.
  -NoCompress      Keep uncompressed folder (don't zip and delete).
  -Categories      Specific categories to collect. Default: all (except Memory).
                   Valid: Memory, FileSystem, Registry, EventLogs, Execution,
                   Network, UserActivity, Browser, USB, Persistence,
                   AntiVirus, Email
                   Note: Memory is opt-in. On live systems, the script prompts
                   if a capture tool is found in tools\. For automation, pass
                   -Categories "Memory","FileSystem","Registry",...
  -Unattended      No prompts, for scripts and tests: the target is the live
                   system drive unless -TargetDrive is given, memory is
                   captured only when -Categories includes Memory, and the
                   script never waits for a key press (at the end, or when
                   it stops early, e.g. without Administrator rights).
  -IncludeThunderbirdIndex
                   Email category: also copy Thunderbird's search index
                   (global-messages-db.sqlite, up to 1 GB). Off by default
                   because it holds the text of the indexed messages, not
                   only their headers; the timeline builder reads only the
                   headers from it (date, addresses, subject, attachment
                   names).
  -IncludeSecrets  AUTHORIZED EXAMINATIONS ONLY. Two changes, both off by
                   default (see "What Gets Collected" > "Secrets" and "Known
                   Limitations"):
                     1. The browser settings and session files (Chromium Local
                        State, Preferences and Secure Preferences; Firefox
                        prefs.js; Firefox and Chromium session files) are
                        copied UNREDACTED -- no private or secret value is
                        blanked -- so each copy is byte-for-byte the original
                        and its manifest hash equals the original's. The size
                        caps still apply. (Without the switch these copies have
                        their encrypted keys, tokens, password hashes, cookies,
                        form data and page state blanked, as always.)
                     2. DPAPI credential material is collected into a top-level
                        Secrets\ folder: per user the master keys
                        (AppData\Roaming\Microsoft\Protect\<SID>\, including
                        Preferred and CREDHIST), Credentials (roaming and
                        local) and Vault, and the system master keys
                        (%SystemRoot%\System32\Microsoft\Protect\S-1-5-18).
                   With the user's password or the domain DPAPI backup key,
                   this is everything needed to decrypt the unredacted browser
                   secrets -- saved passwords and session cookies -- offline;
                   the Registry hives are not needed for the per-user data. The
                   machine (S-1-5-18) master keys instead need SYSTEM and
                   SECURITY (boot key and the DPAPI_SYSTEM LSA secret; SAM for
                   local hashes), collected by the Registry category (selected
                   by default), so include that category if the machine keys
                   are needed. The whole collection then holds secrets
                   equivalent to a password store: handle, store and transfer
                   it accordingly. A prominent warning is logged at the start
                   of the run, and collection_info.json records
                   "SecretsIncluded": true.
                   Use it for infostealer cases (which saved passwords and
                   cookies were exposed), session/token-theft cases (cookie
                   decryption), authorized access to cloud evidence, and
                   evidence integrity (copies that hash-match the originals).
  -MemoryOutputPath
                   Folder for the memory dump, e.g. D:\TriageMemory on a
                   second drive (created if missing; must be outside the
                   collection folder). The dump is written there as
                   <collection>_memory_dump.dmp (.raw for WinPmem and Magnet
                   RAM Capture); the acquisition log stays in the
                   collection, and collection_manifest.csv records the
                   dump's full path, where the timeline builder finds it.
                   Default: Memory\ in the collection, moved next to the
                   zip at the end.
  -MinFreeSpaceGB  Free space in GB to keep on the system drive after the
                   memory dump and the collection. Default: -1 (automatic:
                   10% of the volume, at least 4 and at most 20 GB). 0
                   keeps only the 1 GB that every drive keeps.

  -MemoryOutputPath and -MinFreeSpaceGB are not passed by the .bat; run the
  script directly to use them (see Quick Start, PowerShell (Admin)).


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
          the zip as <collection>_memory_dump.dmp / .raw. With
          -MemoryOutputPath <folder> (or another drive chosen at the
          prompt), written to that folder under that name from the start.
          The acquisition log always stays in the collection, and
          collection_manifest.csv records where the dump ends up.
  Storage: Dump size equals installed RAM (16 GB RAM = ~16 GB file).
           Before the capture the script checks the free space where the
           dump goes, for the dump (RAM + 1 MB for DumpIt, RAM x 1.05 for
           a raw image) and, on the collection's drive, ~5 GB for the
           collection and its zip (4 GB with the raw NTFS copies, else
           1 GB; x 1.25 unless -NoCompress). That is a typical size, not
           an upper limit: the parts with size caps of their own are not
           counted at those caps (e-mail attachments, up to 2 GB; SRUM;
           the browser history snapshots; the larger event logs;
           -IncludeThunderbirdIndex) and can add several GB. On the system
           drive it keeps a reserve free, since Windows keeps writing
           there: 10% of the volume, at least 4 and at most 20 GB, or
           -MinFreeSpaceGB (raise it when those parts are expected to be
           large). On other drives 1 GB. The prompt shows these numbers,
           for example
             Free space on C:\: 40.8 GB; memory dump ~31.9 GB + collection
             ~5 GB would leave ~3.9 GB (to keep free on the system drive:
             20 GB)
           and, when the dump does not fit or would eat into the reserve,
           offers other drives where it fits ([1] D:\TriageMemory --
           recommended, [2] here anyway, [3] skip). The check is repeated
           right before the capture and logged; if the dump does not fit
           then, the capture is skipped as an error and the rest of the
           collection still runs. The output drive is also checked for the
           collection at the start of every run (a warning only).
           Writing the dump to the system drive being examined overwrites
           free space that can still hold deleted files: another drive is
           better. FAT32 (common on USB sticks) cannot hold a dump of 4 GB
           or more.
  Checks: After the capture, DumpIt's "Error:" lines are copied into the
          log, and the dump is kept only when it exists, is not empty,
          DumpIt reported NtStatus 0x00000000 and the size the file has,
          and it holds at least 95% of the RAM. Otherwise the capture is an
          error, and the dump is set aside (see Known Limitations).
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

  tests\Test-Collect*.ps1 (run as Administrator; all six also run in CI)
    Each builds a fake mounted image in a temporary folder (a
    Windows\System32 tree with test artifacts), maps it to a free drive
    letter with subst, runs the collector on it with -Unattended
    -NoCompress and one category, and checks what was and was not
    collected (byte for byte, with manifest rows: original path, hash of
    the copy, original times). The drive letter and the files are removed
    afterwards. Without Administrator rights, pass -CollectorPath with a
    copy of the collector that has no admin check (e.g. under the
    git-ignored reports\ folder). Only Test-CollectEmail.ps1 changes the
    machine it runs on, and only in CI or with -AllowSystemChanges.

  tests\Test-CollectEventLogs.ps1 (-Categories EventLogs)
    Every exported channel is copied with a manifest row; a missing
    OAlerts.evtx is only an info line. Of a 300 MB Shell-Core log only the
    newest events are collected (warning with the record range), a 300 MB
    log of zeros is skipped with a warning, and a 300 MB System log is
    copied whole. Also checks, on this machine, that each channel is
    stored under the file name the collector expects ("/" as "%4").

  tests\Test-CollectBrowser.ps1 (-Categories Browser)
    Chrome, Edge, Opera and Firefox profiles: the extension, session,
    settings and snapshot files are collected within their caps; other
    locales, extension code, oversized files and folders that are not
    browser profiles are not. A canary string in every secret or private
    value must appear nowhere in the collection, while the other settings,
    URLs and titles are kept; a damaged Firefox session file is not
    collected.

  tests\Test-CollectEmail.ps1 (-Categories Email)
    Classic and new Outlook, Thunderbird and Windows Mail data: the
    attachment copies and caps (newest first), the listing CSVs, and that
    mailboxes, OST/PST files, mail contents and link targets are never
    copied. A second run with -IncludeThunderbirdIndex -SkipLargeFiles
    copies the search index and applies the lower caps. The collector's
    listing and path helpers are also checked directly. Live part (CI, or
    -AllowSystemChanges): sets OutlookSecureTempFolder for three made-up
    Office versions under HKCU (a custom folder, one with %LOCALAPPDATA%,
    the drive root), runs a live collection, checks that the first two
    are listed and copied and the drive root is refused, and removes the
    keys. Needs about 1.1 GB free in %TEMP% for a moment.

  tests\Test-CollectSrum.ps1 (-Categories Execution)
    Every file of the sru folder is copied; a file over the 16 GB cap
    (sparse, no disk space used; 2 GB with -SkipLargeFiles) and a subfolder
    are not; an image without an sru folder gives only an info line. The
    live shadow-copy logic is checked with the collector's own functions
    and a folder standing in for the shadow copy.

  tests\Test-CollectDefender.ps1 (-Categories AntiVirus)
    DetectionHistory and Quarantine\Entries files are collected; a file
    over 1 MB, an empty file and anything from Quarantine\ResourceData or
    Quarantine\Resources are not; of 2,001 DetectionHistory files only the
    newest 2,000 are; a folder the account may not open gives an "access
    denied" warning.

  tests\Test-CollectSecrets.ps1 (-Categories Browser, run with and without
    -IncludeSecrets)
    Browser settings/session files holding canary secret values, DPAPI
    master key files (Protect\<SID>\<GUID>, hidden+system), Preferred,
    CREDHIST, Credentials, Vault, and the system keys
    System32\Microsoft\Protect\S-1-5-18. Without the switch: the canary is
    in no browser copy, there is no Secrets folder, and SecretsIncluded is
    false. With the switch: the browser copies are byte-for-byte the
    originals (manifest hash equals the original's), every credential file is
    collected with a manifest row and original times, SecretsIncluded is
    true, the warning is logged, and a junction out of the profile is not
    followed.

    powershell -ExecutionPolicy Bypass -File tests\Test-CollectBrowser.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-CollectEmail.ps1 -AllowSystemChanges

  tests\Test-ShadowCopy.ps1 (no admin needed; also runs in CI)
    Checks how a copy from the shadow copy is reported, with a folder
    standing in for the snapshot: a hidden file is copied and listed in the
    manifest with its hash and original time; an empty one is logged as
    skipped and is not an error; a missing one is "Not present"; a locked
    one gives a warning with the reason and counts one error; with -Quiet
    nothing is logged or counted. Also checks the SRUM collection, which
    reports these outcomes itself: an empty SRUM file in the snapshot is an
    info line, not an error; a locked one is a warning with the reason;
    with SRUDB.dat locked in the snapshot, the files come from the volume
    and the info line gives the reason.
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
    file saved under a shortened name or with [ ] in its name, and that
    the browser copies made within a size cap (session files, history
    snapshots, extension manifests) count such a file and its size toward
    the cap.
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

  tests\Test-MountedDevices.ps1 (no admin needed; also runs in CI)
    Decodes synthetic MountedDevices values: GPT, MBR (one offset above 4
    GiB), USB and "\??\" device paths with and without a trailing NUL, and
    values that are none of these. Then saves the same values from a test
    key under HKCU (removed afterwards) and checks mounted_devices.csv (the
    columns the timeline builder reads, the key's last-write time),
    mounted_devices.txt (every value whole), the manifest and the log line;
    a missing key gives a header-only CSV and a warning. Also checks that
    the collector lifts $FormatEnumerationLimit for the run, so lists in
    the .txt files are not cut after 4 items, also when it is run from an
    open PowerShell window, and restores it afterwards.
      powershell -ExecutionPolicy Bypass -File tests\Test-MountedDevices.ps1

  tests\Test-MemoryAcquisitionLog.ps1 (no admin needed; also runs in CI)
    Runs a stand-in capture tool (a .cmd file that prints DumpIt-like
    lines, one of them on stderr) and saves its output the way the
    collector does: every line is in Memory\memory_acquisition_log.txt,
    which is listed in the manifest with its hash and size, with no log
    line and no error; a tool that prints nothing gives a log with a note,
    also listed. The collection folders have [ ] in their names. Also
    checks that the collector saves the log only this way, right after
    the tool runs and before it checks the dump (so a failed capture also
    has its log), and writes nothing to it afterwards, so the hash in the
    manifest matches the file.
      powershell -ExecutionPolicy Bypass -File tests\Test-MemoryAcquisitionLog.ps1

  tests\Test-MemorySpaceCheck.ps1 (no admin needed; also runs in CI)
    Checks the free space check before a memory capture and the check of
    its result, without capturing anything. The space check with run 2's
    numbers (C: 40.8 GB free, 32 GB of RAM: low reserve) and other cases:
    no room, another drive, a FAT32 stick, -MinFreeSpaceGB, unknown free
    space or RAM, the collection's share, and the log line. Free space read
    from the temp folder's drive, its UNC admin share (when reachable) and
    a missing drive. The prompt, with stand-ins for the drives and the
    answers: the numbers, the system drive warning, other drives offered
    (D: for run 2, not a FAT32 or too-small drive). The result check on a
    redacted DumpIt log (tests\fixtures\memory) and a failing variant
    (nonzero NtStatus, short file, an "Error:" line). The memory section
    with a stand-in tool: no room (an error, no capture), low reserve (a
    warning), a complete, failed, empty or missing dump, an earlier dump at
    the path, -MemoryOutputPath, WinPmem and Magnet RAM Capture, a failed
    dump that cannot be renamed or is held open; the dump's manifest row
    has its full path, size and hash. The summary and compression step:
    the dump moved next to the zip (the manifest in the zip then names that
    path), or the folder kept unzipped (and the summary corrected) when it
    cannot be moved; moved back with its manifest row when the zip fails;
    the rest of the manifest unchanged, and kept as it was (a warning) when
    it cannot be changed; the line that the timeline builder finds the dump
    through the manifest only for a dump that is not next to the zip; a
    failed dump still in the folder set aside then, or the folder not
    zipped. The prompt asks again after a bad answer (also a number too
    large for an [int]) and is not shown with -Unattended.
      powershell -ExecutionPolicy Bypass -File tests\Test-MemorySpaceCheck.ps1

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
       -PlantedFile <planted.json>  which planting to check (default: the
                                    newest TriageE2E_* folder in Downloads)
       -TimelinePath <timeline.csv> which timeline to check (default: the
                                    newest one in a win11-timeline-builder
                                    folder next to this repository)
       -ToleranceSeconds <n>        allowed difference between a planted
                                    time and its timeline time (default 120)
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
  - With memory capture: the capture tool loads its kernel driver, and the
    dump (as large as the RAM) is written to the output drive or to
    -MemoryOutputPath; on the system drive this overwrites free space that
    can hold deleted files
  - Compiles small Add-Type helpers (registry key times, raw NTFS reader);
    Windows PowerShell writes and deletes temporary compiler files in %TEMP%
    for this
  - All modifications are cleaned up at script end, also when the run is
    stopped with Ctrl+C or ends with an error

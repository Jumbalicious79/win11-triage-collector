MAGNET DUMPIT FOR WINDOWS -- memory capture tool (optional)
=============================================================

This folder is where the triage collector looks for DumpIt. The tool itself
is NOT included in this repository: Magnet Forensics distributes it under
its own End User License Agreement (https://www.magnetforensics.com/legal/),
so each user downloads it directly. Everything in this folder except this
README is ignored by git and never committed.


GET IT
------
  1. Request it from Magnet Forensics (free; registration form, the
     download link arrives by email):
       https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/
  2. Extract the download into this folder AS-IS. The expected layout:

       tools\dumpit\
         ARM64\DumpIt.exe      <-- Windows on ARM (e.g. Parallels on Apple silicon)
         x64\DumpIt.exe        <-- 64-bit Intel/AMD Windows
         x86\DumpIt.exe        <-- 32-bit Windows
         (plus Dmp2Bin.exe, Bin2Dmp.exe, Z2Dmp.exe, ... per architecture)
         Comae.psm1, LICENSE.txt, README.txt

     A single DumpIt.exe placed directly in tools\dumpit\ also works.


HOW THE COLLECTOR USES IT
-------------------------
  - On a live system, the collector finds DumpIt and asks
    "Include memory capture?" before collection starts. Memory is
    captured FIRST, to preserve the RAM state.
  - It runs the build that matches the machine's CPU
    (tools\dumpit\<ARM64|x64|x86>\DumpIt.exe). Memory capture loads a
    kernel driver, and drivers must match the CPU: an x64 build cannot
    capture on Windows on ARM.
  - Command line: DumpIt.exe /TYPE DMP /NOCOMPRESS /QUIET /OUTPUT <file>
  - Output: a full Microsoft crash dump, saved NEXT TO the collection zip
    as reports\TriageCollection_<timestamp>_memory_dump.dmp (it is as large
    as the machine's RAM, so it is not zipped). With -MemoryOutputPath
    <folder>, or another drive chosen at the prompt, it is written to that
    folder under the same name.
  - Free space: before the capture the collector checks that the dump (RAM
    + 1 MB) and the rest of the collection fit, and on the system drive
    keeps a reserve free (10% of the volume, 4 to 20 GB; -MinFreeSpaceGB).
    The prompt shows the numbers and offers other drives when it does not
    fit; DumpIt's own check only makes sure the file fits. A FAT32 drive
    cannot hold a dump of 4 GB or more. See the main README.txt, "Memory
    Capture Setup".
  - After the capture the collector copies DumpIt's "Error:" lines into its
    log and keeps the dump only if DumpIt reported NtStatus 0x00000000 and
    the size the file has, and it holds at least 95% of the RAM.
  - DumpIt is preferred over WinPmem and Magnet RAM Capture because it is
    signed and has native x86, x64 and ARM64 builds.


ANALYZING THE DUMP
------------------
  - win11-timeline-builder analyzes x64 dumps with Volatility 3
    (see that project's tools\volatility3\README.txt).
  - Windows ARM64 dumps can be captured but Volatility 3 cannot analyze
    Windows ARM64 memory; open the .dmp in WinDbg instead.
  - Dmp2Bin.exe (in the DumpIt download) converts a .dmp to a raw image
    if another tool needs one.

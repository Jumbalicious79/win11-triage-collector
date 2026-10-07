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
    as the machine's RAM, so it is not zipped). Make sure the output drive
    has at least that much free space.
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

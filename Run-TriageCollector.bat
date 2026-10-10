@echo off
:: Launches triage-collector.ps1 as Administrator with execution policy bypass
:: Users can double-click this file -- no PowerShell knowledge needed
::
:: Usage:
::   Double-click                    -- collect from C: (live system); when a
::                                      mounted Windows image is attached, a
::                                      menu lets you pick it (or Cancel)
::   Run-TriageCollector.bat fast    -- skip raw NTFS copies and the USN export
::   Run-TriageCollector.bat nozip   -- don't compress output (a folder: drop it
::                                      on Run-TimelineBuilder.bat)
::   Run-TriageCollector.bat E       -- collect from E: (mounted image; E: or E:\ too)
::   Run-TriageCollector.bat E fast  -- collect from E:, skip raw NTFS and USN
::
:: The words can come in any order and together (E fast nozip). Anything else
:: stops with this list, before the collection starts.
::
:: FileSystem\ gets raw copies of the NTFS metafiles, read from the volume by a
:: built-in reader (no extra tools): $MFT (file records, including deleted
:: files not yet overwritten), $LogFile (NTFS transaction log) and $UsnJrnl_$J
:: (USN change journal, allocated part only -- its sparse, already-freed part
:: is left out). They feed the timeline builder's $MFT timeline and tools such
:: as MFTECmd. $UsnJrnl_$J.txt is the same journal exported as text by fsutil.
::
:: Note: "fast" skips the raw NTFS copies ($MFT, $LogFile, $UsnJrnl:$J) and
:: the fsutil USN export, the timeline builder's largest sources.

setlocal
:: Windows PowerShell builds its default module path when PSModulePath is not
:: set. Started from PowerShell 7, cmd.exe passes PowerShell 7's path on, and
:: Windows PowerShell then loads PowerShell 7's modules (no Get-FileHash).
set "PSModulePath="
:: This file's path and folder, read before any argument is shifted
set "TRIAGE_BAT=%~f0"
set "TRIAGE_DIR=%~dp0"
set "DRIVE_ARG="
set "FAST_ARG="
set "NOZIP_ARG="

:: Read every argument; checked here, before Administrator rights are asked for.
:: shift /1 keeps %0 (a plain shift would move the first argument into it).
:args
if "%~1"=="" goto :argsdone
set "TRIAGE_ARG=%~1"
shift /1
if /i "%TRIAGE_ARG%"=="fast" goto :argfast
if /i "%TRIAGE_ARG%"=="nozip" goto :argnozip
:: A drive letter, with or without its colon (E, E: or E:\)
if "%TRIAGE_ARG:~1%"==":\" set "TRIAGE_ARG=%TRIAGE_ARG:~0,1%"
if "%TRIAGE_ARG:~1%"==":" set "TRIAGE_ARG=%TRIAGE_ARG:~0,1%"
for %%L in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do if /i "%TRIAGE_ARG%"=="%%L" goto :argdrive
goto :usage

:argfast
set "FAST_ARG=fast"
goto :args

:argnozip
set "NOZIP_ARG=nozip"
goto :args

:argdrive
if not defined DRIVE_ARG goto :argdriveset
if /i not "%DRIVE_ARG%"=="%TRIAGE_ARG%" goto :usage
:argdriveset
set "DRIVE_ARG=%TRIAGE_ARG%"
goto :args

:usage
echo.
echo ERROR: Unknown or extra argument: "%TRIAGE_ARG%"
echo.
echo Usage (the words can come in any order and together):
echo   Run-TriageCollector.bat           collect from C: (live system)
echo   Run-TriageCollector.bat fast      skip the raw NTFS copies and the USN export
echo   Run-TriageCollector.bat nozip     don't compress the output
echo   Run-TriageCollector.bat E         collect from E: (a mounted image; E: or E:\ too)
echo   Run-TriageCollector.bat E fast nozip
echo.
pause
exit /b 1

:argsdone
:: The arguments as this file reads them (passed on to its elevated copy)
set "TRIAGE_ARGS=%DRIVE_ARG% %FAST_ARG% %NOZIP_ARG%"

net session >nul 2>&1
if %errorlevel% equ 0 goto :elevated

:: Not elevated: relaunch this file elevated through cmd.exe. The path and the
:: arguments reach PowerShell as environment variables (not inside its command
:: string), so spaces, apostrophes and parentheses in them are safe.
echo Requesting Administrator privileges...
powershell.exe -NoProfile -Command "$q = [char]34; $cmdArgs = '/c ' + $q + $q + $env:TRIAGE_BAT + $q + ' ' + $env:TRIAGE_ARGS + $q; try { Start-Process -FilePath ($env:SystemRoot + '\System32\cmd.exe') -ArgumentList $cmdArgs -Verb RunAs -ErrorAction Stop } catch { Write-Host ('Could not elevate: ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }"
if errorlevel 1 pause
exit /b

:elevated
set "DRIVE_PARAM="
set "FAST_PARAM="
set "NOZIP_PARAM="
if defined DRIVE_ARG set "DRIVE_PARAM=-TargetDrive %DRIVE_ARG%"
if defined FAST_ARG set "FAST_PARAM=-SkipLargeFiles"
if defined NOZIP_ARG set "NOZIP_PARAM=-NoCompress"

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%TRIAGE_DIR%triage-collector.ps1" %DRIVE_PARAM% %FAST_PARAM% %NOZIP_PARAM%
set "TRIAGE_RC=%errorlevel%"

:: The collector waits for a key itself at its end ("Press any key to
:: exit..."). This file waits only when it stopped with an error, so the
:: message stays on screen.
if "%TRIAGE_RC%"=="0" exit /b 0
echo.
echo The collector stopped with an error (exit code %TRIAGE_RC%) -- see the messages above.
echo Press any key to exit...
pause >nul
exit /b %TRIAGE_RC%

@echo off
:: Launches triage-collector.ps1 as Administrator with execution policy bypass
:: Users can double-click this file -- no PowerShell knowledge needed
::
:: Usage:
::   Double-click                    -- collect from C: (live system)
::   Run-TriageCollector.bat fast    -- skip the USN journal export
::   Run-TriageCollector.bat nozip   -- don't compress output
::   Run-TriageCollector.bat E       -- collect from E: (mounted image)
::   Run-TriageCollector.bat E fast  -- collect from E:, skip the USN journal
::
:: Note: "fast" skips the USN journal, the timeline builder's largest source.

net session >nul 2>&1
if %errorlevel% equ 0 goto :elevated

:: Not elevated: relaunch this file elevated through cmd.exe. The path and the
:: arguments reach PowerShell as environment variables (not inside its command
:: string), so spaces, apostrophes and parentheses in them are safe.
echo Requesting Administrator privileges...
set "TRIAGE_BAT=%~f0"
set "TRIAGE_ARGS=%*"
powershell.exe -NoProfile -Command "$q = [char]34; $cmdArgs = '/c ' + $q + $q + $env:TRIAGE_BAT + $q + ' ' + $env:TRIAGE_ARGS + $q; try { Start-Process -FilePath ($env:SystemRoot + '\System32\cmd.exe') -ArgumentList $cmdArgs -Verb RunAs -ErrorAction Stop } catch { Write-Host ('Could not elevate: ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }"
if errorlevel 1 pause
exit /b

:elevated
set "DRIVE_PARAM="
set "MODE_PARAM="

:: Check if first argument is a single drive letter (A-Z)
set "ARG1=%~1"
set "ARG2=%~2"
if defined ARG1 (
    echo.%ARG1%| findstr /r "^[A-Za-z]$" >nul 2>&1
    if not errorlevel 1 (
        set "DRIVE_PARAM=-TargetDrive %ARG1%"
        set "ARG1=%ARG2%"
    )
)

if /i "%ARG1%"=="fast"  set "MODE_PARAM=-SkipLargeFiles"
if /i "%ARG1%"=="nozip" set "MODE_PARAM=-NoCompress"

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0triage-collector.ps1" %DRIVE_PARAM% %MODE_PARAM%

echo.
echo Press any key to exit...
pause >nul

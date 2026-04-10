@echo off
:: Launches triage-collector.ps1 as Administrator with execution policy bypass
:: Users can double-click this file — no PowerShell knowledge needed
::
:: Usage:
::   Double-click                    — collect from C: (live system)
::   Run-TriageCollector.bat fast    — skip large files ($MFT, hives)
::   Run-TriageCollector.bat nozip   — don't compress output
::   Run-TriageCollector.bat E       — collect from E: (mounted image)
::   Run-TriageCollector.bat E fast  — collect from E:, skip large files

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    if "%~1"=="" (
        powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    )
    exit /b
)

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

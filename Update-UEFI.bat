@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%Update_UEFI-CA2023.ps1"

if not exist "%PS_SCRIPT%" (
   echo ERROR: Script not found: "%PS_SCRIPT%"
   exit /b 2
)

pushd "%SCRIPT_DIR%" >nul 2>&1
if errorlevel 1 (
   echo ERROR: Unable to access script directory: "%SCRIPT_DIR%"
   exit /b 3
)

set "PS_EXE="
where pwsh.exe >nul 2>&1
if not errorlevel 1 set "PS_EXE=pwsh.exe"

if not defined PS_EXE (
   where powershell.exe >nul 2>&1
   if not errorlevel 1 set "PS_EXE=powershell.exe"
)

if not defined PS_EXE (
   echo ERROR: Neither pwsh.exe nor powershell.exe was found in PATH.
   popd
   exit /b 4
)

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
set "EXIT_CODE=%ERRORLEVEL%"

popd
exit /b %EXIT_CODE%

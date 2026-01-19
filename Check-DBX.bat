@echo off
where pwsh >nul 2>nul
if %errorlevel% equ 0 (
   pwsh -nop -ep bypass -noexit -f "%~dp0\Check_DBXUpdate.bin.ps1" %*
) else (
   powershell -nop -ep bypass -noexit -f "%~dp0\Check_DBXUpdate.bin.ps1" %*
)

@echo off
if %errorlevel% equ 0 (
   pwsh -nop -ep bypass -noexit -f "%~dp0\Update_UEFI-CA2023.ps1" %*
) else (
   powershell -nop -ep bypass -noexit -f "%~dp0\Update_UEFI-CA2023.ps1" %*
)

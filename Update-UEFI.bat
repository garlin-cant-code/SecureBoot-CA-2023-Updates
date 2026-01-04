@echo off
if %errorlevel% equ 0 (
   pwsh -nop -ep bypass -f "%~dp0\Update_UEFI-CA2023.ps" %*
) else (
   powershell -nop -ep bypass -f "%~dp0\Update_UEFI-CA2023.ps" %*
)

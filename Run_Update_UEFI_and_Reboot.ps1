param(
    [switch]$NoReboot
)

$ScriptName = 'Update_UEFI-CA2023.ps1'
$ScriptPath = Join-Path $PSScriptRoot $ScriptName

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    Write-Error "Required script not found: $ScriptPath"
    exit 1
}

# Choose appropriate host (pwsh for PowerShell Core, powershell for Windows PowerShell)
if ($PSVersionTable.PSVersion.Major -ge 6) { $HostExe = 'pwsh' } else { $HostExe = 'powershell' }

$Args = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

# Detect elevation / SYSTEM account so SCCM (System) can run this wrapper without UAC prompts
$IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$IsSystem = ($env:USERNAME -eq 'SYSTEM')

try {
    if ($IsElevated -or $IsSystem) {
        Write-Output 'Running update script directly (elevated or System account).'
        & $HostExe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath
        $ExitCode = $LASTEXITCODE
    }
    else {
        Write-Output 'Requesting elevation to run update script.'
        $proc = Start-Process -FilePath $HostExe -ArgumentList $Args -Verb RunAs -Wait -PassThru
        $ExitCode = $proc.ExitCode
    }
}
catch {
    Write-Error "Failed to start update script: $($_.Exception.Message)"
    exit 1
}

# Create marker file on successful completion for SCCM detection
$MarkerDir = 'C:\ProgramData\SecureBoot-CA-2023-Updates'
if ($ExitCode -eq 0) {
    try {
        New-Item -Path $MarkerDir -ItemType Directory -Force | Out-Null
        Set-Content -Path (Join-Path $MarkerDir 'update_completed.txt') -Value (Get-Date).ToString() -Force
        Write-Output "Marker file created: $MarkerDir\update_completed.txt"
    }
    catch {
        Write-Warning "Failed to create marker file: $($_.Exception.Message)"
    }
}
else {
    Write-Warning "Update script exited with code $ExitCode"
}

## Detect if this is running under SCCM (client) so SCCM can manage restarts
$IsSCCM = (($null -ne (Get-Process -Name 'CCMExec' -ErrorAction SilentlyContinue)) -or (Test-Path 'C:\Windows\CCM') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM'))

if (-not $NoReboot -and $ExitCode -eq 0) {
    if ($IsSCCM) {
        Write-Output 'Running under SCCM — skipping forced reboot; SCCM should manage restarts.'
    }
    else {
        Write-Output 'Update finished — rebooting now.'
        Restart-Computer -Force
    }
}

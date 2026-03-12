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

try {
    Start-Process -FilePath $HostExe -ArgumentList $Args -Verb RunAs -Wait
}
catch {
    Write-Error "Failed to start update script: $($_.Exception.Message)"
    exit 1
}

if (-not $NoReboot) {
    Write-Output 'Update finished — rebooting now.'
    Restart-Computer -Force
}

# Runbook: Deploy SecureBoot CA-2023 Update via SCCM

**Scope:** Deploy `Update_UEFI-CA2023.ps1` (wrapped by `Run_Update_UEFI_and_Reboot.ps1`) to targets using SCCM. Ensure KB5066791 is installed before the update.

**Prerequisites:**
- SUP/WSUS synchronized and KB5066791 available in your Software Library.
- Scripts and package content placed on a UNC share accessible by SCCM DPs.
- Test devices or pilot collection for validation.

**Package layout (content share):**
- [Run_Update_UEFI_and_Reboot.ps1](Run_Update_UEFI_and_Reboot.ps1)
- [Update_UEFI-CA2023.ps1](Update_UEFI-CA2023.ps1)
- [Create_Villeurbanne_Marker.ps1](Create_Villeurbanne_Marker.ps1)

**Step A — Deploy prerequisite KB (KB5066791)**
- Console: Software Library → Software Updates → All Software Updates → search `KB5066791`.
- Right-click → Create Software Update Group → name `KB5066791 - PreReq`.
- Distribute content to DP(s) and Deploy to target Collection as **Required**, schedule as Soon As Possible, allow restart per your policy.

PowerShell (on SCCM server, adjust site drive/collection/DP):
```
Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'
cd 'ABC:'  # replace ABC with your site code
$kb = Get-CMSoftwareUpdate -ArticleID 'KB5066791'
$group = New-CMSoftwareUpdateGroup -Name 'KB5066791 - PreReq'
Add-CMSoftwareUpdateToGroup -SoftwareUpdateGroupName $group.Name -SoftwareUpdate $kb
Start-CMContentDistribution -SoftwareUpdateGroupName $group.Name -DistributionPointName 'DP01'
New-CMSoftwareUpdateDeployment -CollectionName 'Pilot-Collection' -SoftwareUpdateGroupName $group.Name -DeployPurpose Required -ScheduleActionAsSoonAsPossible $true
```

**Step B — Create SCCM Application (recommended) or Package**
- Create Application → Deployment Type: Script Installer.
- Content location: `\\server\share\SecureBoot-CA-2023-Updates` (your UNC).
- Installation program:
  - `powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -File "Run_Update_UEFI_and_Reboot.ps1" -NoReboot`
  - Note: wrapper detects running as SYSTEM and skips UAC; `-NoReboot` ensures SCCM controls reboot policy.
- Run installation program: **Run as System** / **Hidden** / Whether user is logged on: **No**.
- Requirements: Windows 10/11 x64 as appropriate.
- Maximum run time: 60 minutes (adjust based on testing).

**Detection method (Script - returns $true when installed)**
Use a simple script that checks the marker file created by the wrapper:
```
$marker = 'C:\ProgramData\SecureBoot-CA-2023-Updates\update_completed.txt'
if (Test-Path $marker) { Write-Output $true } else { Write-Output $false }
```
Set the detection method type to `Script` (PowerShell) and supply the script above.

**User Experience / Restart handling**
- Because KB deployment and the SecureBoot update may require restarts, let SCCM manage restarts.
- In the Application deployment settings set **User notifications** minimal and **Allow clients to restart outside maintenance window** per policy, or choose to enforce restart at deadline.

**Distribution**
- Distribute the Application/Package to the necessary DPs or DP groups.

**Testing checklist (pilot)**
- Deploy KB5066791 to a pilot collection and confirm compliance.
- Deploy SecureBoot Application to pilot collection with `-NoReboot` and monitor logs:
  - Client logs: `C:\Windows\CCM\Logs\AppEnforce.log` and `UpdatesDeployment.log`.
- Verify marker file created:
  - `C:\ProgramData\SecureBoot-CA-2023-Updates\update_completed.txt`
- Verify UEFI cert changes on one test machine and confirm it boots normally.

**Troubleshooting**
- If deployment fails, collect `AppEnforce.log` and `execmgr.log` from client.
- If the wrapper doesn't run under SCCM, verify process `CCMExec` exists and the Detection script returns `$true`.

**Rollback / Uninstall**
- There is no automatic uninstall for UEFI updates. Test thoroughly on pilot devices and use BIOS/UEFI vendor recovery procedures if needed.

**Screenshots to capture and include in runbook**
1. **Software Update Search**: Software Library → Software Updates → search `KB5066791` (show result list). Capture selection and Create Software Update Group dialog.
2. **Create Software Update Group**: Name and confirmation screen.
3. **Deploy Software Update Group**: Deployment Wizard — collection, scheduling, user experience pages.
4. **Application Deployment Type**: Script Installer page showing Content location and Installation program field.
5. **Detection Rule**: Script detection editor with the marker-check script.
6. **Deployment Settings**: Deployment purpose, restart behavior, schedule page.
7. **Distribution**: Content Distribution progress (Distribute Content wizard).
8. **Client Logs**: Example AppEnforce.log snippet showing start and exit of the wrapper.

For each screenshot: capture full Console window; annotate with arrows/notes showing fields to set. Save images into the package content share under `docs\screenshots` and reference them in this runbook.

---
If you want, I can also:
- generate a printable PDF of this runbook,
- create the Application using SCCM PowerShell commands tailored to your site code/collection/DP, or
- produce the annotated screenshots template (PNG placeholders) you can fill.

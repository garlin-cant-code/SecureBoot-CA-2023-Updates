<#PSScriptInfo

.VERSION 2026.08.18

.GUID 7c7848ed-3952-4726-8f23-8644881c2c91

.AUTHOR garlin

.COPYRIGHT

.TAGS UEFI, Secure Boot, PK, KEK, DB, DBX, SVN, Windows Boot Manager

.RELEASENOTES

#>

<#
.SYNOPSIS
    Script to install Secure Boot CA 2023 certificates in UEFI, and revoke PCA 2011 certificate if needed.

.DESCRIPTION
    Run this script to bring Windows into compliance with UEFI CA 2023 changes.

.PARAMETER Version
    Print the script's version number and exit.

.PARAMETER UpdatesFolder
    Provide a different source folder for the Post-Signed object (.bin) files.

.PARAMETER Audit
    Perform an audit report of the UEFI variables and Windows Boot Manager version.  Identify any missing UEFI certs, and validate if current boot file is
    allowed by enabling Secure Boot mode.

    Identify all required actions to bring system into compliance for upcoming Windows CA 2023 changes.

    If Secure Boot is currently disabled, audit report will simulate conditions where Secure Boot is enabled.

.PARAMETER Force
    Ignore the safety blocks for ConfidenceLevel = "Temporarily Paused" or "Not Supported", or when your PC matches a list of models with known problems.
    A BIOS could be corrupted or damaged in certain cases by proceeding.  Not recommended for general use.

.PARAMETER Revoke
    Revoke [Microsoft Windows Production PCA 2011] certificate by adding the cert to the UEFI DBX.
    To allow dual-booting of [Production PCA 2011] & [UEFI CA 2023] media, do not use the -Revoke option.

.PARAMETER Latest
    Download latest version of DBXUpdate.bin and DBXUpdateSVN.bin, from Microsoft's Secure Boot Objects GitHub before proceeding.

.PARAMETER SkuSiPolicy
    Deploy \Windows\System32\SecureBootUpdates\SkuSiPolicy.p7b to EFI partition.

.PARAMETER BootMedia
    Check boot files on all mounted removable media, and replace with [UEFI CA 2023] version if needed.

.PARAMETER Log
    Save script output to a file named "YYYY-MM-DD [Model] Update UEFI.log"

.EXAMPLE
    Update_UEFI-CA2023.ps1
.EXAMPLE
    Update_UEFI-CA2023.ps1 -Audit
.EXAMPLE
    Update_UEFI-CA2023.ps1 -Revoke
.EXAMPLE
    Update_UEFI-CA2023.ps1 -Revoke -Latest -Log
#>

[CmdletBinding(DefaultParameterSetName='Default')]
param (
    [Parameter(Mandatory=$false,ParameterSetName='Version')]
    [switch]$Version,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [ValidateScript({ if (Test-Path $_ ) { $true } else { throw "Folder `"$_`" not found." } })]
    [string]$UpdatesFolder = $(if ([Environment]::Is64BitProcess) { "$env:SystemRoot\System32\SecureBootUpdates" } else { "$env:SystemRoot\SysNative\SecureBootUpdates" }),

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Audit,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Force,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Revoke,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Latest,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$SkuSiPolicy,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$BootMedia,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Log,

    [Parameter(Mandatory=$false,ParameterSetName='Default',DontShow,ValueFromRemainingArguments=$true)]
    [string[]]$ignored
)

$ScriptVersion = '2026.08.18'

# https://github.com/microsoft/secureboot_objects/blob/main/Archived/dbx_info_msft_4_09_24_svns.csv
$EFI_BOOTMGR_SVN_GUID = '01612B139DD5598843AB1C185C3CB2EB92'
$EFI_CDBOOT_SVN_GUID =  '019D2EF8E827E15841A4884C18ABE2F284'
$EFI_WDSMGR_SVN_GUID =  '01C2CA99C9FE7F6F4981279E2A8A535976'

$VMWARE_GUID = 'a3d5e95b-0a8f-4753-8735-445afb708f62'

$CN_Regex = '(CN=)([^,]+)'

$Tab4 = ' ' * 4

$Arch = $env:PROCESSOR_ARCHITECTURE.ToLower()

switch ($Arch) {
    'amd64' { $EDK2_Arch = 'x64' }
    'x86'   { $EDK2_Arch = 'ia32' }
    'arm64' { $EDK2_Arch = 'aarch64' }
    'arm'   { $EDK2_Arch = 'arm' }
}

$EDK2_Version = 'v1.6.5'
$EDK2_bin_URL = "https://github.com/microsoft/secureboot_objects/releases/download/$EDK2_Version/edk2-${EDK2_Arch}-secureboot-binaries.zip"
$PK_DER_URL = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der'

$KEKUpdateMap_URL = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/KEK/kek_update_map.json'
$KEK_DER_URL = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/KEK/Certificates/microsoft%20corporation%20kek%202k%20ca%202023.der'

$DBXUpdate_bin_URL = "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/DBX/$Arch/DBXUpdate.bin"
$DBXUpdateSVN_bin_URL = "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/Optional/DBX/DBXUpdateSVN.bin"

if ($Version) {
    '{0} version ({1}){2}' -f $MyInvocation.MyCommand.Name, $ScriptVersion, $(if ($MyInvocation.Line -ne '') { "`n" })
    exit 0
}

if ($psISE -ne $null) {
    Write-Host 'ERROR: Script cannot be executed in PowerShell ISE.  Please use powershell.exe or pwsh.exe.' -ForegroundColor Red
    exit 0
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($PSVersionTable.PSVersion.Major -gt 5) {
        $PS = 'pwsh'
    }
    else {
        $PS = 'powershell'
    }

    $args = ($MyInvocation.BoundParameters.Keys.GetEnumerator() | where { $_ -notmatch 'UpdatesFolder|ignored' } | foreach { '-{0}' -f $_ }) -join ' '

    if ($MyInvocation.BoundParameters.'UpdatesFolder' -ne $null) {
        $args += ' -UpdatesFolder "{0}"' -f (Get-Item $MyInvocation.BoundParameters.'UpdatesFolder' -ErrorAction SilentlyContinue).FullName
    }

    Start-Process $PS -ArgumentList "-nop -ep bypass -NoLogo -NoExit -f `"$($MyInvocation.MyCommand.Path)`" $args" -Verb RunAs
    exit 0
}

$System = Get-CimInstance -ClassName Win32_ComputerSystem
$SystemDrive = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

function Confirm-MinimumUBR {
    $Build = $CurrentVersion.CurrentBuildNumber
    $UBR = $CurrentVersion.UBR
    $Release = $CurrentVersion.DisplayVersion

    switch ($Build) {
        14393 {
            if ($UBR -lt 9234) {
                return "Update Windows $Release to KB5094122 (Jun 2026) or later"
            }
        }

        17763 {
            if ($UBR -lt 8880) {
                return "Update Windows $Release to KB5094123 (Jun 2026) or later"
            }
        }

        { $_ -in 19044,19045 } {
            if ($UBR -lt 7417) {
                return "Update W10 $Release to KB5094127 (Jun 2026) or later"
            }
        }

        20348 {
            if ($UBR -lt 5020) {
                return "Update Server 2022 to KB5082142 (Apr 2026) or later"
            }
        }

        22000 {
            if ($UBR -lt 3260) {
                return "Update W11 21H2 to KB5044280 (Oct 2025) or later"
            }
        }

        22621 {
            if ($UBR -lt 6060) {
                return "Update W11 $Release to KB5066793 (Oct 2025) or later"
            }
        }

        22631 {
            if ($UBR -lt 7219) {
                return "Update W11 $Release to KB5093998 (Jun 2026) or later"
            }
        }

        25398 {
            if ($UBR -lt 2274) {
                return "Update Server 23H2 to KB5082060 (Apr 2026) or later"
            }
        }

        { $_ -in 26100,26200 } {
            if ($UBR -lt 8655) {
                return "Update W11 $Release to KB5094126 (Jun 2026) or later"
            }
        }

        28000 {
            if ($UBR -lt 2269) {
                return "Update W11 26H1 to KB5095051 (Jun 2026) or later"
            }
        }

        { $_ -gt 26200 } {
            return "Cannot confirm if W11 $Release (${Build}.$UBR) has the latest files"
        }

        default {
            return "Windows $Release ${Build}.$UBR is unsupported"
        }
    }

    return $true
}

function Suspend-Protection {
    $ProtectionStatus = (Get-BitLockerVolume -MountPoint $SystemDrive).ProtectionStatus

    if ($ProtectionStatus -eq 'On') {
        $DeviceGuard_Running = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning

        if ($DeviceGuard_Running -eq 1) {
            'Suspending BitLocker for two reboots (Device Guard).'
            $RebootCount = 3
        }
        else {
            'Suspending BitLocker for one reboot.'
            $RebootCount = 1
        }

        try {
            $null = Suspend-BitLocker -MountPoint $SystemDrive -RebootCount $RebootCount
        }
        catch {
            $_.Exception.Message
            exit 1
        }
    }
}

function Get-HarddiskVolume {
    <#
        https://superuser.com/a/1401025
        Original Author: phant0m
        Modified By: garlin (@garlin-cant-code)
    #>

    param (
        [Parameter(Mandatory)]
        [string]$VolumeGUID
    )

    Add-Type -MemberDefinition @'
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetVolumePathNamesForVolumeNameW([MarshalAs(UnmanagedType.LPWStr)] string lpszVolumeName,
            [MarshalAs(UnmanagedType.LPWStr)] [Out] StringBuilder lpszVolumeNamePaths, uint cchBuferLength, ref UInt32 lpcchReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr FindFirstVolume([Out] StringBuilder lpszVolumeName, uint cchBufferLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FindNextVolume(IntPtr hFindVolume, [Out] StringBuilder lpszVolumeName, uint cchBufferLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
'@ -Name Kernel32 -Namespace Win32 -Using System.Text

    [UInt32]$Max = 65535

    $VolumeName = New-Object System.Text.StringBuilder($Max, $Max)
    $PathName = New-Object System.Text.StringBuilder($Max, $Max)
    $MountPoint = New-Object System.Text.StringBuilder($Max, $Max)
    [IntPtr]$VolumeHandle = [Win32.Kernel32]::FindFirstVolume($VolumeName, $Max)

    do {
        $Volume = $VolumeName.toString()
        $ReturnLength = [Win32.Kernel32]::QueryDosDevice($Volume.Substring(4, $Volume.Length - 5), $PathName, [UInt32]$Max)

        if ($ReturnLength) {
            if ($VolumeName -match $VolumeGUID) {
                $DevicePath = '\\.\{0}' -f ($PathName -split '\\')[-1]
                return $DevicePath
            }
        }
    } while ([Win32.Kernel32]::FindNextVolume([IntPtr] $VolumeHandle, $VolumeName, $Max))

    return $null
}

function Get-FileVersion {
    param (
        [Parameter(Mandatory)]
        [string]$File
    )

    $FileVersionRaw = (Get-Item -LiteralPath $File).VersionInfo.FileVersionRaw
    $FileVersion = '{0}.{1}' -f $FileVersionRaw.Build, $FileVersionRaw.Revision

    return $FileVersion
}

function Print-Header {
    param (
        [Parameter(Mandatory=$false)]
        [switch]$Bold,

        [Parameter(Mandatory)]
        [string]$Header
    )

    if ($Bold) {
        $Separator = '='
    }
    else {
        $Separator = '-'
    }

    return ("{0}`n{1}" -f $Header, ($Header -replace "`n" -replace '(.)',$Separator))
}

function Get-UefiDatabaseSignatures {
    <#
        .SYNOPSIS
        Parses UEFI Signature Databases into logical Powershell objects
        # https://github.com/cjee21/Check-UEFISecureBootVariables

        .DESCRIPTION
        Original Author: Matthew Graeber (@mattifestation)
        Modified By: Jeremiah Cox (@int0x6)
        Modified By: Joel Roth (@nafai)
        Modified By: garlin (@garlin-cant-code)
        Additional Source: https://gist.github.com/mattifestation/991a0bea355ec1dc19402cef1b0e3b6f
        Additional Source: https://www.powershellgallery.com/packages/SplitDbxContent/1.0
        License: BSD 3-Clause

        .PARAMETER Variable
        Specifies an UEFI variable, an instance of which is returned by calling the Get-SecureBootUEFI cmdlet.

        .PARAMETER BytesIn
        Specifies a byte array consisting of the PKDefault, KEKDefault, dbDefault, dbxDefault, PK, KEK, db, or dbx UEFI variable contents.

        .EXAMPLE
        $DbxBytes = [IO.File]::ReadAllBytes('.\dbx.bin')
        Get-UEFIDatabaseSignatures -BytesIn $DbxBytes

        .EXAMPLE
        Get-UEFIDatabaseSignatures -Filename ".\DBXUpdate-20230314.x64.bin"

        .EXAMPLE
        Get-SecureBootUEFI -Name db | Get-UEFIDatabaseSignatures

        .EXAMPLE
        Get-SecureBootUEFI -Name dbx | Get-UEFIDatabaseSignatures

        .EXAMPLE
        Get-SecureBootUEFI -Name pk | Get-UEFIDatabaseSignatures

        .EXAMPLE
        Get-SecureBootUEFI -Name kek | Get-UEFIDatabaseSignatures

        .INPUTS
        Microsoft.SecureBoot.Commands.UEFIEnvironmentVariable
        Accepts the output of Get-SecureBootUEFI over the pipeline.

        .OUTPUTS
        UefiSignatureDatabase
        Outputs an array of custom powershell objects describing a UEFI Signature Database. "77fa9abd-0359-4d32-bd60-28f4e78f784b" refers to Microsoft as the owner.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'UEFIVariable')]
        [ValidateScript({ ($_.GetType().Fullname -eq 'Microsoft.SecureBoot.Commands.UEFIEnvironmentVariable') -and ($_.Name -in 'PKDefault','KEKDefault','dbDefault','dbxDefault','pk','kek','db','dbx') })]
        $Variable,

        [Parameter(Mandatory, ParameterSetName = 'ByteArray')]
        [Byte[]]
        [ValidateNotNullOrEmpty()]
        $BytesIn,

        [Parameter(Mandatory, ParameterSetName = 'File')]
        [string]
        [ValidateScript({ (Resolve-Path "$_").where({Test-Path $_}).Path })]
        $Filename
    )

    $PSVersion = $PSVersionTable.PSVersion.Major

    $SignatureTypeMapping = @{
        'C1C41626-504C-4092-ACA9-41F936934328' = 'EFI_CERT_SHA256_GUID' # Most often used for dbx
        'A5C059A1-94E4-4AA7-87B5-AB155C2BF072' = 'EFI_CERT_X509_GUID'   # Most often used for db
    }

    $Bytes = $null

    if ($Filename)
    {
        if ($PSVersion -gt 5) {
            $Bytes = Get-Content -AsByteStream $Filename -ErrorAction Stop
        }
        else {
            $Bytes = Get-Content -Encoding Byte $Filename -ErrorAction Stop
        }
    }
    elseif ($Variable)
    {
        $Bytes = $Variable.Bytes
    }
    else
    {
        $Bytes = $BytesIn
    }

    # Modified from Split-Dbx
    if (($Bytes[40] -eq 0x30) -and ($Bytes[41] -eq 0x82))
    {
        Write-Debug "Removing signature."

        # Signature is known to be ASN size plus header of 4 bytes
        $sig_length = $Bytes[42] * 256 + $Bytes[43] + 4

        if ($sig_length -gt ($Bytes.Length + 40)) {
            Write-Error "Signature longer than file size!" -ErrorAction Stop
        }

        # Skip past Microsoft's "dbx" serialized header
        # https://github.com/microsoft/secureboot_objects/issues/400#issuecomment-4298521163

        $dbx_Bytes = [Byte[]]@(0x64, 0x00, 0x62, 0x00, 0x78, 0x00)

        if ([System.Linq.Enumerable]::SequenceEqual([Byte[]]@($Bytes[($sig_length + 40)..($sig_length + 45)]), $dbx_Bytes)) {
            $offset = 42
        }
        else {
            $offset = 0
        }

        ## Unsigned db store
        [System.Byte[]]$Bytes = @($Bytes[($sig_length + 40 + $offset)..($Bytes.Length - 1)].Clone())
    }
    else
    {
        Write-Debug "Signature not found. Assuming it's already split."
    }

    try
    {
        $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$Bytes)
        $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $MemoryStream, ([Text.Encoding]::Unicode)
    }
    catch
    {
        throw $_
        return
    }

    # What follows will be an array of EFI_SIGNATURE_LIST structs

    while ($BinaryReader.PeekChar() -ne -1) {
        $SignatureType = $SignatureTypeMapping[([Guid][Byte[]] $BinaryReader.ReadBytes(16)).Guid]
        $SignatureListSize = $BinaryReader.ReadUInt32()
        $SignatureHeaderSize = $BinaryReader.ReadUInt32()
        $SignatureSize = $BinaryReader.ReadUInt32()

        $SignatureHeader = $BinaryReader.ReadBytes($SignatureHeaderSize)

        # 0x1C is the size of the EFI_SIGNATURE_LIST header
        $SignatureCount = ($SignatureListSize - 0x1C) / $SignatureSize

        $SignatureList = 1..$SignatureCount | ForEach-Object {
            $SignatureDataBytes = $BinaryReader.ReadBytes($SignatureSize)

            $SignatureOwner = [Guid][Byte[]] $SignatureDataBytes[0..15]

            switch ($SignatureType) {
                'EFI_CERT_SHA256_GUID' {
                    $SignatureData = ([Byte[]] $SignatureDataBytes[0x10..0x2F] | ForEach-Object { $_.ToString('X2') }) -join ''
                }

                'EFI_CERT_X509_GUID' {
                    try {
                        $SignatureData = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,([Byte[]] $SignatureDataBytes[16..($SignatureDataBytes.Count - 1)]))
                    }
                    catch {
                        Write-Host "Skipping an invalid $Variable X509 certificate."
                    }
                }
            }

            [PSCustomObject] @{
                PSTypeName = 'EFI.SignatureData'
                SignatureOwner = $SignatureOwner
                SignatureData = $SignatureData
            }
        }

        [PSCustomObject] @{
            PSTypeName = 'EFI.SignatureList'
            SignatureType = $SignatureType
            SignatureList = $SignatureList
        }
    }
}

function Get-UEFICert {
    param (
        [Parameter(Mandatory)]
        [ValidateSet('PKDefault','KEKDefault','dbDefault','dbxDefault','PK','KEK','db','dbx')]
        [string]$Variable
    )

    try {
        $SignatureList = (Get-SecureBootUEFI $Variable | Get-UefiDatabaseSignatures).SignatureList
    }
    catch {
        if ($_.Exception.Message -match '0xC0000100') {
            return @()
        }
        else {
            throw $_.Exception.Message
        }
    }

    $Subject = $SignatureList.SignatureData.Subject

    if ($Verbose -or $Variable -match 'PK') {
        $Filter_Regex = '.*'
    }
    else {
        $Filter_Regex = 'Microsoft|Mosby'
    }

    $Certs = $Subject | where { $_ -match $Filter_Regex } | foreach { $null = $_ -match $CN_Regex; $Matches[2] }

    if ($Variable -match 'PK') {
        if ($SignatureList.SignatureData -eq $null -and $SignatureList.SignatureOwner.Guid -eq $VMWARE_GUID) {
            $Certs = @('VMware Default PK')
        }
        elseif ($Subject -match 'VirtualBox') {
            $Certs = @('VirtualBox UEFI PK')
        }
    }

    return $Certs
}

function Get-PFXCert {
    param (
        [Parameter(Mandatory)]
        [string]$FileName
    )

    try {
        $Issuer = (Get-PfxCertificate -LiteralPath $FileName).Issuer
    }
    catch {
        $_.Exception.Message
        exit 1
    }

    if ($Issuer -match $CN_Regex) {
        return $Matches[2]
    }
    else {
        return $Issuer
    }
}

function Check-UntrustedPK {
    try {
        $PKSignatureList = (Get-SecureBootUEFI PK | Get-UefiDatabaseSignatures).SignatureList
    }
    catch {
        if ($_.Exception.Message -match '0xC0000100') {
            return $null
        }
        else {
            throw $_.Exception.Message
        }
    }

    if ($PKSignatureList.SignatureData.Subject -match 'DO NOT |Example') {
        return $true
    }
    else {
        return $false
    }
}

function Get-SignatureDataSVN {
    param (
        [Parameter(Mandatory)]
        [string]$SignatureData
    )

    # https://github.com/microsoft/secureboot_objects/blob/main/scripts/utility_functions.py
    [version]$SVN = '{0}.{1}' -f [System.Convert]::ToUInt16($SignatureData.Substring(40,2) + $SignatureData.Substring(38,2), 16), [System.Convert]::ToUInt16($SignatureData.Substring(36,2) + $SignatureData.Substring(34,2), 16)

    return $SVN
}

function Get-SecureBootUEFI_SVN {
    param (
        [Parameter(Mandatory)]
        [string]$SVN_GUID
    )

    try {
        $Signatures = (Get-SecureBootUEFI dbx | Get-UEFIDatabaseSignatures)
    }
    catch {
        if ($_.Exception.Message -match '0xC0000100') {
            return $null
        }
        else {
            throw $_.Exception.Message
        }
    }

    $SignatureData = $Signatures.SignatureList.SignatureData -match "^$SVN_GUID"

    if ($SignatureData) {
        $LatestSVN = $SignatureData | foreach { Get-SignatureDataSVN $_ } | sort | select -Last 1
        [version]$SVN = '{0}.{1}' -f $LatestSVN.Major, $LatestSVN.Minor
    }
    else {
        $SVN = $null
    }

    return $SVN
}

function Get-DBXUpdateSVN {
    $DBXUpdateSVN_File = "$UpdatesFolder\DBXUpdateSVN.bin"

    try {
        $Signatures = Get-UEFIDatabaseSignatures -BytesIn ([IO.File]::ReadAllBytes($DBXUpdateSVN_File)) | where { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' }
    }
    catch {
        $_.Exception.Message
        exit 1
    }

    $SignatureData = $Signatures.SignatureList.SignatureData -match "^$EFI_BOOTMGR_SVN_GUID"

    if ($SignatureData) {
        [version]$SVN = Get-SignatureDataSVN $($SignatureData)
    }
    else {
        $SVN = $null
    }

    return $SVN
}

function Get-BootManagerSVN {
    param (
        [Parameter(Mandatory)]
        [string]$BootMgr_File
    )

    # Get-SecureBootSVN is only available in W11 Feb 2026 Preview or later releases
    try {
        [version]$BootMgrSVN = (Get-SecureBootSVN -BootManagerPath $BootMgr_File).BootManagerSVN
    }
    catch {
        $BootMgrSVN = $null
    }

    return $BootMgrSVN
}

function Match-DBXSignatureData {
    <#
        .SYNOPSIS
        Parses EFI signatures from a DBX Update .bin file and compares the entire list against the current UEFI DBX.

        .DESCRIPTION
        https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0#file-check-dbx-ps1

        Modified By: github.com/cjee21
        Modified By: garlin (@garlin-cant-code)

        .PARAMETER DBXUpdate_File
        Specifies a filename containing signed DBX Update signatures

        .OUTPUTS
        $true or $false
    #>

    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DBXUpdate_File
    )

    if (-not (Test-Path $DBXUpdate_File)) {
        Write-Host "DBX update file `"$DBXUpdate_File`" not found." -ForegroundColor Red
        exit 1
    }

    try {
        $RequiredSignatures = Get-UEFIDatabaseSignatures -BytesIn ([IO.File]::ReadAllBytes($DBXUpdate_File)) | where { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' }
    }
    catch {
        Write-Host "No EFI_CERT_SHA256 signatures in $DBXUpdate_File" -ForegroundColor Red
        return $true
    }

    try {
        $DBXSignatureData = (Get-SecureBootUEFI dbx | Get-UEFIDatabaseSignatures).SignatureList.SignatureData
    }
    catch {
        if ($_.Exception.Message -match '0xC0000100') {
            return $false
        }
        else {
            throw $_.Exception.Message
        }
    }

    $RequiredSignatureData = $RequiredSignatures.SignatureList.SignatureData
    $RequiredCount = $RequiredSignatureData.Count

    if ($RequiredCount -eq 0) {
        Write-Host "No DBX signatures in $DBXUpdate_File" -ForegroundColor Red
        return $true
    }

    $Matched = 0

    foreach ($RequiredSig in $RequiredSignatureData) {
        if ($DBXSignatureData -contains $RequiredSig) {
            $Matched++
        }
        else {
            switch -Regex ($RequiredSig) {
                "^$EFI_BOOTMGR_SVN_GUID" {
                    $CurrentSVN = Get-SecureBootUEFI_SVN $EFI_BOOTMGR_SVN_GUID
                    $RequiredSVN = Get-SignatureDataSVN $RequiredSig

                    if ($CurrentSVN -ge $RequiredSVN) {
                        $Matched++
                    }
                }

                "^$EFI_CDBOOT_SVN_GUID" {
                    $CurrentSVN = Get-SecureBootUEFI_SVN $EFI_CDBOOT_SVN_GUID
                    $RequiredSVN = Get-SignatureDataSVN $RequiredSig

                    if ($CurrentSVN -ge $RequiredSVN) {
                        $Matched++
                    }
                }

                "^$EFI_WDSMGR_SVN_GUID" {
                    $CurrentSVN = Get-SecureBootUEFI_SVN $EFI_WDSMGR_SVN_GUID
                    $RequiredSVN = Get-SignatureDataSVN $RequiredSig

                    if ($CurrentSVN -ge $RequiredSVN) {
                        $Matched++
                    }
                }
            }
        }
    }

    if ($Matched -eq $RequiredCount) {
        return $true
    }
    else {
        return $false
    }
}

function Get-SbatLevel {
    try {
        $SbatLevel_Bytes = [byte[]](Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\SBAT' -Name 'SbatLevel' -ErrorAction Stop)
    }
    catch {
        $SbatLevel_Bytes = $null
    }

    if ($SbatLevel_Bytes.Count) {
        $SbatLevel = [System.Text.Encoding]::ASCII.GetString($SbatLevel_Bytes) -replace ' ' -replace "`0"

        if ($SbatLevel -match '!SBATnotfound') {
            $SbatLevel = $null
        }
    }
    else {
        $SbatLevel = $null
    }

    return $SbatLevel
}

function Get-SkuSiPolicyVersion {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]$BinaryFilePath
    )

    $Bytes = [IO.File]::ReadAllBytes($BinaryFilePath)

    if ([System.Text.Encoding]::ASCII.GetString($bytes) -replace "`0" -match '\d+(\.\d+)+') {
        $Version = $Matches[0]
    }
    else {
        $Version = $null
    }

    return $Version
}

function Audit-UEFI {
    $CheckList = $null
    $index = 1

    if ($SetupMode) {
        $CheckList += "{0,-3} UEFI is in Setup Mode`n" -f ('{0}.' -f $index++)

        if ($WindowsHello) {
            $CheckList += "{0,-3} Windows Hello must be disabled when in UEFI Setup Mode`n" -f ('{0}.' -f $index++)
        }
    }

    try {
        $State = (Get-ScheduledTask -TaskName 'Secure-Boot-Update' -ErrorAction Stop).State
        $SecureBoot_TaskState = $State.ToString().ToUpper()
    }
    catch {
        $SecureBoot_TaskState = 'REMOVED'
    }

    if ($SecureBoot_TaskState -ne 'Ready') {
        $CheckList += "{0,-3} `"Secure-Boot-Update`" scheduled task is $SecureBoot_TaskState.`n" -f ('{0}.' -f $index++)
    }

    if ($PK_Untrusted) {
        $CheckList += "{0,-3} [{1}] is UNTRUSTED`n" -f ('{0}.' -f $index++), $PK_Cert
    }

    if ('Microsoft Corporation KEK 2K CA 2023' -notin $KEK_Certs) {
        $CheckList += "{0,-3} [Microsoft Corporation KEK 2K CA 2023] is missing from UEFI KEK`n" -f ('{0}.' -f $index++)
    }

    if ('Windows UEFI CA 2023' -notin $db_Certs) {
        $CheckList += "{0,-3} [Windows UEFI CA 2023] is missing from UEFI DB (dbupdate2024.bin)`n" -f ('{0}.' -f $index++)
    }

    if ('Microsoft UEFI CA 2023' -notin $db_Certs) {
        $CheckList += "{0,-3} [Microsoft UEFI CA 2023] is missing from UEFI DB (DBUpdate3P2023.bin)`n" -f ('{0}.' -f $index++)
    }

    if ('Microsoft Option ROM UEFI CA 2023' -notin $db_Certs) {
        $CheckList += "{0,-3} [Microsoft Option ROM UEFI CA 2023] is missing from UEFI DB (DBUpdateOROM2023.bin)`n" -f ('{0}.' -f $index++)
    }

    if ('Microsoft Windows Production PCA 2011' -notin $dbx_Certs) {
        $CheckList += "{0,-3} [Production PCA 2011] is missing from UEFI DBX (DBXUpdate2024.bin)`n" -f ('{0}.' -f $index++)
    }

    if (($dbx_BytesCount -eq 0) -or -not (Match-DBXSignatureData "$UpdatesFolder\dbxupdate.bin")) {
        $CheckList += "{0,-3} DBX Updates are missing from UEFI DBX (dbxupdate.bin)`n" -f ('{0}.' -f $index++)
    }

    $global:UEFI_SVN = Get-SecureBootUEFI_SVN $EFI_BOOTMGR_SVN_GUID

    if ($UEFI_SVN -eq $null) {
        $CheckList += "{0,-3} Windows BootMgr SVN is missing from UEFI DBX (DBXUpdateSVN.bin)`n" -f ('{0}.' -f $index++)
    }
    elseif ((Get-DBXUpdateSVN) -gt $UEFI_SVN) {
        $CheckList += "{0,-3} SecureBootUpdates SVN is higher than UEFI DBX`n" -f ('{0}.' -f $index++)
    }

    $BootMgrEX_File_Hash = (Get-FileHash $BootMgrEX_File).Hash
    $BootMgr_File_Hash = (Get-FileHash -LiteralPath $BootMgr_File).Hash

    if (($PFXCert -notmatch 'Windows UEFI CA 2023') -or ($BootMgrSVN -lt $UEFI_SVN) -or ($BootMgrSVN -eq $UEFI_SVN -and $BootMgr_File_Hash -ne $BootMgrEX_File_Hash)) {
        $CheckList += "{0,-3} Windows Boot Manager [{1}] is wrong version`n" -f ('{0}.' -f $index++), ($PFXCert -replace 'Microsoft Windows ')
    }

    if ($VBS_Enabled) {
        if ((Test-Path -LiteralPath $EFI_SkuSiPolicy_File)) {
            $SkuSiPolicyFile_Hash = (Get-FileHash $SkuSiPolicy_File).Hash
            $EFI_SkuSiPolicyFile_Hash = (Get-FileHash -LiteralPath $EFI_SkuSiPolicy_File).Hash

            $SkuSiPolicyFile_Version = Get-SkuSiPolicyVersion $SkuSiPolicy_File
            $EFI_SkuSiPolicyFile_Version = Get-SkuSiPolicyVersion $EFI_SkuSiPolicy_File

            if (($EFI_SkuSiPolicyFile_Hash -ne $SkuSiPolicyFile_Hash) -and ([Version]$SkuSiPolicyFile_Version -gt [Version]$EFI_SkuSiPolicyFile_Version)) {
                $CheckList += "{0,-3} SkuSiPolicy.p7b is not updated`n" -f ('{0}.' -f $index++)
                $script:UpdateSkuSiPolicy = $true
            }
        }
        else {
            $CheckList += "{0}[OPTIONAL] SkuSiPolicy.p7b (for VBS) is missing from EFI`n" -f $(if ($index) { "`n" })
        }
    }

    return $CheckList
}

function Download-EDK2bin {
    $ZIP_File = "$EDK2_Folder\edk2-secureboot-binaries.zip"

    if (-not (Test-Path $EDK2_Folder)) {
        $null = New-Item -Path $EDK2_Folder -Type Directory -Force
    }

    try {
        'Downloading "{0}" from GitHub.' -f ($EDK2_bin_URL -split '/')[-1]
        Invoke-WebRequest -UseBasicParsing -Uri $EDK2_bin_URL -OutFile $ZIP_File
    }
    catch {
        $_.Exception.Message
        exit 1
    }

    $DefaultBin_Files = @('Default3PDb.bin', 'DefaultDbx.bin', 'DefaultKek.bin', 'DefaultPk.bin')

    $objShell = New-Object -ComObject 'Shell.Application'
    $objFolder = $objShell.NameSpace($EDK2_Folder)

    foreach ($File in $DefaultBin_Files) {
        $objFolder.CopyHere("$ZIP_File\LegacyFirmwareDefaults\Firmware\$File", 0x14)
    }
}

function Set-SecureBootSignedFile {
    param (
        [Parameter(Mandatory)]
        [ValidateSet('PK','KEK','db','dbx')]
        [string]$Variable,

        [Parameter(Mandatory)]
        [string]$Filename
    )

    if (-not (Test-Path $Filename)) {
        "$Filename not found."
        exit 1
    }

    try {
        # https://github.com/microsoft/secureboot_objects/blob/main/scripts/windows/InstallSecureBootKeys.ps1
        $null = Set-SecureBootUEFI -Name $Variable -ContentFilePath $Filename -Time '2015-08-28T00:00:00Z'
    }
    catch {
        $ErrorMessage = 'ERROR: Failed to write "{0}" to UEFI {1}.' -f (Split-Path $Filename -Leaf), $Variable.ToUpper()
        Write-Host $ErrorMessage -ForegroundColor Red

        if ($_.Exception.Message -match '0xC0000022') {
            Write-Host 'Wrong signature for this UEFI variable.' -ForegroundColor Red
        }
        else {
            $_.Exception.Message
        }

        exit 1
    }

    'Successfully wrote "{0}" to UEFI {1}.' -f (Split-Path $Filename -Leaf), $Variable
    $script:UEFI_Updated = $true

    Suspend-Protection
}

function Append-SecureBootSignedFile {
    <#
        .SYNOPSIS
        Appends a signed UEFI update package to an UEFI variable

        .DESCRIPTION
        Original Author: Microsoft Secure Boot Team, https://www.powershellgallery.com/packages/SplitDbxContent/1.0
        Modified By: ManubrioTenorio
        Modified By: garlin

        .PARAMETER Variable
        Specifies an UEFI variable, an instance of which is returned by calling the Get-SecureBootUEFI cmdlet.

        .PARAMETER Filename
        Specifies a signed UEFI update package.

        .EXAMPLE
        Append-SecureBootSignedFile -Variable db -Filename ".\DBXUpdate-20230314.x64.bin"
    #>

    param (
        [Parameter(Mandatory)]
        [ValidateSet('PK','KEK','db','dbx')]
        [string]$Variable,

        [Parameter(Mandatory)]
        [string]$Filename
    )

    $PSVersion = $PSVersionTable.PSVersion.Major

    $CertName = (Split-Path $Filename -Leaf) -replace '.bin'

    if (-not (Test-Path $Filename)) {
        "$Filename not found."
        exit 1
    }

    if ($PSVersion -gt 5) {
        $Bytes = Get-Content -AsByteStream $Filename -ErrorAction Stop
    }
    else {
        $Bytes = Get-Content -Encoding Byte $Filename -ErrorAction Stop
    }

    # Identify file signature
    if (($Bytes[40] -ne 0x30) -or ($Bytes[41] -ne 0x82)) {
        Write-Error "Cannot find signature!" -ErrorAction Stop
    }

    # Signature is known to be ASN size plus header of 4 bytes
    $sig_length = $Bytes[42] * 256 + $Bytes[43] + 4

    if ($sig_length -gt ($Bytes.Length + 40)) {
        Write-Error "Signature longer than file size!" -ErrorAction Stop
    }

    # Skip past Microsoft's "dbx" serialized header
    # https://github.com/microsoft/secureboot_objects/issues/400#issuecomment-4298521163

    $dbx_Bytes = [Byte[]]@(0x64, 0x00, 0x62, 0x00, 0x78, 0x00)

    if ([System.Linq.Enumerable]::SequenceEqual([Byte[]]@($Bytes[($sig_length + 40)..($sig_length + 45)]), $dbx_Bytes)) {
        $offset = 42
    }
    else {
        $offset = 0
    }

    $SigFile = '{0}\{1}.signature.p7' -f $env:TEMP, $CertName
    $ContentFile = '{0}\{1}.content.bin' -f $env:TEMP, $CertName

    # Build and write signature output file
    if ($PSVersion -gt 5) {
        Set-Content -AsByteStream -Path $SigFile -Value ([Byte[]] $Bytes[40..($sig_length + 40 - 1)]) -ErrorAction Stop
    }
    else {
        Set-Content -Encoding Byte -Path $SigFile -Value ([Byte[]] $Bytes[40..($sig_length + 40 - 1)]) -ErrorAction Stop
    }

    # Build and write variable content output file
    if ($PSVersion -gt 5) {
        Set-Content -AsByteStream -Path $ContentFile -Value ([Byte[]] $Bytes[($sig_length + 40 + $offset)..($Bytes.Length - 1)]) -ErrorAction Stop
    }
    else {
        Set-Content -Encoding Byte -Path $ContentFile -Value ([Byte[]] $Bytes[($sig_length + 40 + $offset)..($Bytes.Length - 1)]) -ErrorAction Stop
    }

    try {
        # https://github.com/microsoft/secureboot_objects/discussions/158
        $null = Set-SecureBootUEFI -Name $Variable -ContentFilePath $ContentFile -SignedFilePath $SigFile -Time '2010-03-06T19:17:21Z' -AppendWrite
    }
    catch {
        $ErrorMessage = 'ERROR: Failed to append "{0}.bin" to UEFI {1}.' -f $CertName, $Variable.ToUpper()
        Write-Host $ErrorMessage -ForegroundColor Red

        switch -Regex ($_.Exception.Message) {
            # Incorrect authentication data: 0xC0000022
            '0xC0000022' {
                Write-Host 'Wrong signature for this UEFI variable.' -ForegroundColor Red

                if ($SecureBoot -and $Variable -eq 'dbx') {
                    Write-Host "Try disabling Legacy CSM support and Secure Boot, before running the script."
                }
            }

            # Unexpected Result, status error: 0xC000000D
            '0xC000000D' {
                if ($Variable -eq 'KEK') {
                    Write-Host "UEFI doesn't allow appending to KEK variable.  Please try Setup Mode." -ForegroundColor Red
                }
                else {
                    Write-Host $_.Exception.Message -ForegroundColor Red
                }
            }

            default {
                $_.Exception.Message
            }
        }

        exit 1
    }

    'Successfully appended "{0}" to UEFI {1}.' -f (Split-Path $Filename -Leaf), $Variable.ToUpper()
    $script:UEFI_Updated = $true

    Suspend-Protection
    Remove-Item $SigFile,$ContentFile -Force
}

function Update-PK_Cert {
    # Pre-signed object for Windows OEM Devices PK

    $CertFile = 'WindowsOEMDevicesPK.der'
    $PreSignedObj_File = "$env:TEMP\$CertFile"

    if (-not (Test-Path -LiteralPath "$EFI_FolderPath\$CertFile")) {
        try {
            'Downloading "{0}" from GitHub.' -f $CertFile
            Invoke-WebRequest -UseBasicParsing -Uri $PK_DER_URL -OutFile $PreSignedObj_File
        }
        catch {
            $_.Exception.Message
            exit 1
        }

        if (-not (Test-Path -LiteralPath $EFI_FolderPath)) {
            $null = New-Item -Path $EFI_FolderPath -Type Directory -Force
        }

        'Copying "{0}" to EFI.' -f $CertFile
        Copy-Item -Path $PreSignedObj_File -Destination $EFI_FolderPath -Force

        Remove-Item $PreSignedObj_File -Force
    }

    $script:PK_README = $true
}

function Update-KEK_Cert {
    try {
        $JSON = (Invoke-WebRequest -UseBasicParsing -Uri $KEKUpdateMap_URL).Content | ConvertFrom-Json
    }
    catch {
        "`nERROR: Unable to parse Microsoft's KEK update map."
        Write-Host (($_.Exception.Message -split "`n") | select -First 1) -ForegroundColor Red
        exit 1
    }

    try {
        $PK_Thumbprint = (Get-UefiDatabaseSignatures -BytesIn (Get-SecureBootUEFI PK).Bytes).SignatureList.SignatureData.Thumbprint
    }
    catch {
        if ($_.Exception.Message -match '0xC0000100') {
            $PK_Thumbprint = $null
        }
        else {
            throw $_.Exception.Message
        }
    }

    if ($JSON.$PK_Thumbprint.KEKUpdate -ne $null) {
        # Post-signed object for KEK 2K CA 2023

        $array = @($JSON.$PK_Thumbprint.KEKUpdate -split '/')
        $Vendor = $array[0]
        $KEK_Update = $array[1]

        $KEK_BIN_URL = "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/KEK/$Vendor/$KEK_Update"
        $PostSignedObj_File = "$env:TEMP\$KEK_Update"

        try {
            'Downloading "{0}" from GitHub.' -f $KEK_Update
            Invoke-WebRequest -UseBasicParsing -Uri $KEK_BIN_URL -OutFile $PostSignedObj_File
        }
        catch {
            Write-Host $_.Exception.Message -ForegroundColor Red
            exit 1
        }

        Append-SecureBootSignedFile -Variable KEK -Filename $PostSignedObj_File

        Remove-Item $PostSignedObj_File -Force
    }
    else {
        # Pre-signed object for KEK 2K CA 2023

        $CertFile = 'Microsoft Corporation KEK 2K CA 2023.der'
        $PreSignedObj_File = "$env:TEMP\$CertFile"

        if (-not (Test-Path -LiteralPath "$EFI_FolderPath\$CertFile")) {
            try {
                'Downloading "{0}" from GitHub.' -f $CertFile
                Invoke-WebRequest -UseBasicParsing -Uri $KEK_DER_URL -OutFile $PreSignedObj_File
            }
            catch {
                Write-Host $_.Exception.Message -ForegroundColor Red
                exit 1
            }

            if (-not (Test-Path -LiteralPath $EFI_FolderPath)) {
                $null = New-Item -Path $EFI_FolderPath -Type Directory -Force
            }

            'Copying "{0}" to EFI.' -f $CertFile
            Copy-Item -Path $PreSignedObj_File -Destination $EFI_FolderPath -Force
            Copy-Item -Path $PreSignedObj_File -Destination "$EFI_FolderPath\$($CertFile -replace '\.der','.cer')" -Force
            Copy-Item -Path $PreSignedObj_File -Destination "$EFI_FolderPath\$($CertFile -replace '\.der','.crt')" -Force

            Suspend-Protection

            Remove-Item $PreSignedObj_File -Force
        }

        $script:KEK_README = $true
    }
}

function Update-EFI_BootManager {
    'Copying EFI boot files.'
    $EFI_DriveLetter = (& mountvol) -split "`n" | foreach { if ($_ -match '(.*mounted at )(.*)(\\)') { $Matches[2] } }

    if ($EFI_DriveLetter -eq $null) {
        $EFI_DriveLetter = ((68..89 | foreach { [char]$_ + ':' }) | where { (Get-CimInstance -ClassName Win32_LogicalDisk).DeviceID -notcontains $_ }) | select -First 1

        if ($EFI_DriveLetter -eq $null) {
            'ERROR: Unable to assign drive letter for EFI partition.'
            exit 1
        }

        try {
            Start-Process 'mountvol' -ArgumentList "$EFI_DriveLetter /s" -NoNewWindow -Wait
            Start-Process 'bcdboot' -ArgumentList "$env:SystemRoot /s $EFI_DriveLetter /f UEFI /bootex" -NoNewWindow -Wait
            Start-Process 'mountvol' -ArgumentList "$EFI_DriveLetter /d" -NoNewWindow -Wait
        }
        catch {
            $_.Exception.Message
            exit 1
        }
    }
    else {
        try {
            Start-Process 'bcdboot' -ArgumentList "$env:SystemRoot /s $EFI_DriveLetter /f UEFI /bootex" -NoNewWindow -Wait
        }
        catch {
            $_.Exception.Message
            exit 1
        }
    }

    $RE_info = reagentc /info

    if (($RE_info -match 'RE status:' -split ' ')[-1] -eq 'Enabled') {
        $WinRE = $true

        $WinRE_Path = ($RE_info -match 'RE location:' -split ' ')[-1]
        $WinRE_GUID = ($RE_info -match 'identifier:' -split ' ')[-1]
    }

    if ($WinRE) {
        try {
            Start-Process 'reagentc' -ArgumentList "/setreimage /path $WinRE_Path" -NoNewWindow -Wait
            Start-Process 'bcdedit' -ArgumentList "/set {default} recoverysequence {$WinRE_GUID}" -NoNewWindow -Wait
        }
        catch {
            $_.Exception.Message
            exit 1
        }

        $null = New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'Enable_WinRE' -Value 'conhost --headless C:\Windows\System32\reagentc.exe /enable' -Force
    }
}

function Update-USB_Drive {
    param (
        [Parameter(Mandatory)]
        [string]$DriveLetter
    )

    $Drive = $DriveLetter + ':'
    $Label = (Get-Volume -DriveLetter $DriveLetter).FileSystemLabel

    if (Test-Path "$Drive\ventoy") {
        'Skipping USB Drive {0} "{1}"' -f $Drive, $Label
        return
    }

    $EFI_Path = '{0}\EFI' -f $Drive

    $EFI_BootMgr_File = "$EFI_Path\Microsoft\Boot\bootmgfw.efi"
    $EFI_BootFile = "$EFI_Path\Boot\boot${EDK2_Arch}.efi"

    if (-not (Test-Path $EFI_BootMgr_File) -and -not (Test-Path $EFI_BootFile)) {
        continue
    }

    foreach ($Boot_File in @($EFI_BootMgr_File, $EFI_BootFile)) {
        if (Test-Path $Boot_File) {
            $EFI_BootStl_File = "$EFI_Path\Microsoft\Boot\boot.stl"
            $Invalid_BootStl = $false

            if ((Get-ChildItem -Path "$Drive\sources\install.*" -ErrorAction SilentlyContinue) | where { $_.Name -match 'wim|esd|swm' }) {
                if (Test-Path $EFI_BootStl_File) {
                    $EFI_BootStl_File_Hash = (Get-FileHash $EFI_BootStl_File).Hash

                    if ($EFI_BootStl_File_Hash -ne $BootStl_File_Hash) {
                        $Invalid_BootStl = $true
                    }
                }
                else {
                    $Invalid_BootStl = $true
                }
            }

            $FileVersion = Get-FileVersion $Boot_File

            if ($FileVersion -eq '0.0') {
                if ($Label -ne $null) {
                    'Skipping THIRD-PARTY boot file on USB Drive {0} "{1}"' -f $Drive, $Label
                }
                else {
                    'Skipping THIRD-PARTY boot file on USB Drive {0}' -f $Drive
                }

                if ($Invalid_BootStl) {
                    "Copying $EFI_BootStl_File"
                    Copy-Item $BootStl_File $EFI_BootStl_File -Force

                    $script:Media_Updated = $true
                }

                break
            }

            $BootFile_Hash = (Get-FileHash $Boot_File).Hash

            if ($Boot_File -eq $EFI_BootMgr_File) {
                if ($BootFile_Hash -ne $BootMgrEX_File_Hash) {
                    if ($Label -ne '') {
                        'Updating WinRE boot media on USB Drive {0} "{1}"' -f $Drive, $Label
                    }
                    else {
                        'Updating WinRE boot media on USB Drive {0}' -f $Drive
                    }

                    $BCD = "$EFI_Path\Microsoft\Boot\BCD"
                    $Backup_BCD = "$env:TEMP\BCD.BAK"

                    try {
                        Copy-Item $BCD $Backup_BCD -Force
                        Start-Process 'bcdboot' -ArgumentList "$env:SystemRoot /s $Drive /f UEFI /bootex" -NoNewWindow -Wait
                        Copy-Item $Backup_BCD $BCD -Force
                        Remove-Item $Backup_BCD -Force
                    }
                    catch {
                        $_.Exception.Message
                        exit 1
                    }

                    $script:Media_Updated = $true
                }
            }
            else {
                if ($BootFile_Hash -ne $BootMgr_File_Hash) {
                    if ($Label -ne '') {
                        'Updating WinPE boot media on USB Drive {0} "{1}"' -f $Drive, $Label
                    }
                    else {
                        'Updating WinPE boot media on USB Drive {0}' -f $Drive
                    }

                    try {
                        Copy-Item $BootMgrEX_File $EFI_BootFile -Force
                    }
                    catch {
                        $_.Exception.Message
                        exit 1
                    }

                    $script:Media_Updated = $true
                }
            }

            if ($Invalid_BootStl) {
                "Copying $EFI_BootStl_File"
                Copy-Item $BootStl_File $EFI_BootStl_File -Force

                $script:Media_Updated = $true
            }

            break
        }
    }
}

$ScriptBlock = {
    $CurrentVersion = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion'
    $Result = Confirm-MinimumUBR

    if ($Result -ne $true) {
        if ($Result -notmatch 'Cannot confirm') {
            "ERROR: $Result.`n"
            exit 1
        }
        else {
            "WARNING: $Result.`n"
        }
    }

    try {
        $SecureBoot = Confirm-SecureBootUEFI
    }
    catch {
        "ERROR: BIOS running in Legacy CSM mode.  Please enable UEFI mode.`n"
        exit 1
    }

    $VBS_Status = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus

    if ($VBS_Status -gt 0) {
        $VBS_Enabled = $true
    }

    $NGC_Credential_Provider = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}'

    try {
        $LogonCreds_Count = ((Get-ChildItem -Path $NGC_Credential_Provider) | where { (Get-ItemProperty $_.PSPath).LogonCredsAvailable -eq 1 }).Count
    }
    catch {
        $LogonCreds_Count = 0
    }

    if ($LogonCreds_Count) {
        $WindowsHello = $true
    }

    try {
        $PK_Cert = Get-UEFICert PK
        $KEK_Certs = Get-UEFICert KEK
        $db_Certs = Get-UEFICert db
        $dbx_Certs = Get-UEFICert dbx
    }
    catch {
        Write-Host 'ERROR: Failed to read UEFI Secure Boot settings.' -ForegroundColor Red
        exit 1
    }

    $Model = '{0} {1}' -f ($System.Manufacturer -split ',')[0], $System.Model

    if ($KEK_Certs -notcontains 'Microsoft Corporation KEK 2K CA 2023' -and $dbx_Certs -notcontains 'Microsoft Windows Production PCA 2011') {
        switch -Regex ($Model) {
            'LENOVO ThinkCentre M700' { $Unsafe_Model = $true }
            'SAMSUNG ELECTRONICS CO. 300E4C/300E5C/300E7C' { $Unsafe_Model = $true }

            default {
                try {
                    $ConfidenceLevel = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'ConfidenceLevel'
                }
                catch {
                }

                if ($ConfidenceLevel -match 'Temporarily Paused|Not Supported') {
                    $Unsafe_Model = $true
                }
            }
        }
    }

    if ($Unsafe_Model) {
        if ($Force) {
            Write-Host "WARNING: Updating $Model can lead to possible corruption or damage.`n" -ForegroundColor Red
            $Confirmation = Read-Host -Prompt 'Please confirm you want to force an update.  Enter "YES" to confirm'

            if ($Confirmation -ne "YES") {
                "User did not enter the correct confirmation. Exiting.`n"
                exit 0
            }

            "User entered the correct confirmation. Script will force an update.`n"
        }
        else {
            if ($ConfidenceLevel -match 'Temporarily Paused') {
                Write-Host "WARNING: $Model may be corrupted by updating Secure Boot certs.`n" -ForegroundColor Red
            }
            else {
                Write-Host "WARNING: $Model could be damaged by updating Secure Boot certs.`n" -ForegroundColor Red
            }

            "Registry: `"ConfidenceLevel`" = $ConfidenceLevel`n"
            exit 1
        }
    }

    foreach ($Variable in 'PK','KEK','db','dbx') {
        try {
            $Count = (Get-SecureBootUEFI $Variable).Bytes.Count
        }
        catch {
            if ($_.Exception.Message -match '0xC0000100') {
                $Count = 0
            }
        }

        New-Variable -Name "${Variable}_BytesCount" -Value $Count
    }

    try {
        $SetupMode_Bytes = Get-SecureBootUEFI SetupMode
    }
    catch {
        if ($_.Exception.Message -match '0xC0000100') {
            $SetupMode_Bytes = @{}
        }
        else {
            throw $_.Exception.Message
        }
    }

    if (($SetupMode_Bytes -join '') -eq 1) {
        if ($WindowsHello) {
            Write-Host "WARNING: Disable Windows Hello PIN before running script in Setup Mode." -ForegroundColor Red
            exit 1
        }

        $SetupMode = $true
    }

    $PK_Untrusted = Check-UntrustedPK

    if ($PK_Cert -eq 'Microsoft Corporation KEK 2K CA 2023') {
        'ERROR: KEK CA 2023 is not a valid Platform Key'
        exit 1
    }

    $EFI_Device = & bcdedit /enum '{bootmgr}' | Select-String 'device'

    switch -Regex ($EFI_Device) {
        'Harddisk' {
            $EFI_Path = '\\.\{0}\EFI' -f ($EFI_Device -split '\\')[-1]
        }

        '[A-Z]:' {
            $DriveLetter = ($EFI_Device -split '=')[-1]
            $VolumeID = (& mountvol $DriveLetter /l).TrimStart()

            if ((Get-Volume -UniqueId $VolumeID).FileSystemType -ne 'FAT32') {
                "ERROR: bcdedit {bootmgr} device $DriveLetter is not FAT32."
                exit 1
            }

            $null = $VolumeID -match '({.*})'
            $EFI_Path = '{0}\EFI' -f (Get-HarddiskVolume $Matches[0])
        }

        # Worse case fallback
        default {
            $SystemDisk = (Get-CimInstance -Namespace 'Root\CIMv2' -Query 'SELECT * FROM Win32_DiskPartition' | where { $_.Type -eq 'GPT: System' }).DiskIndex
            $GUID = (Get-Partition -DiskNumber $SystemDisk | Where-Object { $_.Type -eq 'System' }).Guid

            $EFI_Path = '{0}\EFI' -f (Get-HarddiskVolume $GUID)
        }
    }

    if (-not (Test-Path $EFI_Path)) {
        'ERROR: EFI folder "$EFI_Path" cannot be found.'
        exit 1
    }

    $EFI_FolderPath = "$EFI_Path\Certs"

    $BootMgrEX_File = "$env:SystemRoot\Boot\EFI_EX\bootmgfw_EX.efi"
    $SkuSiPolicy_File = "$UpdatesFolder\SkuSiPolicy.p7b"

    $BootMgr_File = "$EFI_Path\Microsoft\Boot\bootmgfw.efi"
    $EFI_SkuSiPolicy_File = "$EFI_Path\Microsoft\Boot\SkuSiPolicy.p7b"

    $PFXCert = Get-PFXCert $BootMgr_File
    $BootMgrSVN = Get-BootManagerSVN $BootMgr_File

    $CheckList = Audit-UEFI

    if ($Audit) {
        Print-Header -Bold "`nAUDIT REPORT"

        if ($CheckList -eq $null) {
            'No action is required.'
        }
        else {
            $CheckList.TrimEnd("`n")
        }

        return
    }

    if ($PK_BytesCount -eq 0 -and ($KEK_BytesCount -eq 0 -or $db_BytesCount -eq 0 -or $dbx_BytesCount -eq 0)) {
        $EDK2_Folder = "$env:TEMP\EDK2_bin"
        Download-EDK2bin

        if ($db_BytesCount -eq 0) {
            Set-SecureBootSignedFile -Variable db -Filename "$EDK2_Folder\Default3PDb.bin"
        }

        if ($dbx_BytesCount -eq 0) {
            Set-SecureBootSignedFile -Variable dbx -Filename "$EDK2_Folder\DefaultDbx.bin"
        }

        if ($KEK_BytesCount -eq 0) {
            Set-SecureBootSignedFile -Variable KEK -Filename "$EDK2_Folder\DefaultKek.bin"
        }

        if ($PK_BytesCount -eq 0) {
            Set-SecureBootSignedFile -Variable PK -Filename "$EDK2_Folder\DefaultPk.bin"
        }

        try {
            $PK_Cert = Get-UEFICert PK
            $KEK_Certs = Get-UEFICert KEK
            $db_Certs = Get-UEFICert db
            $dbx_Certs = Get-UEFICert dbx
        }
        catch {
            Write-Host 'ERROR: Failed to read UEFI Secure Boot settings.' -ForegroundColor Red
            exit 1
        }

        Remove-Item $EDK2_Folder -Recurse -Force
    }

    if ($PK_Untrusted) {
        Update-PK_Cert
    }

    if ('Microsoft Corporation KEK 2K CA 2023' -notin $KEK_Certs) {
        Update-KEK_Cert
    }

    if ('Windows UEFI CA 2023' -notin $db_Certs) {
        Append-SecureBootSignedFile -Variable db -Filename "$UpdatesFolder\dbupdate2024.bin"
    }

    if ('Microsoft UEFI CA 2023' -notin $db_Certs) {
        Append-SecureBootSignedFile -Variable db -Filename "$UpdatesFolder\DBUpdate3P2023.bin"
    }

    if ('Microsoft Option ROM UEFI CA 2023' -notin $db_Certs) {
        Append-SecureBootSignedFile -Variable db -Filename "$UpdatesFolder\DBUpdateOROM2023.bin"
    }

    if ($Revoke -or ('Microsoft Windows Production PCA 2011' -in $dbx_Certs)) {
        if ($SecureBoot -and ('Microsoft Corporation KEK 2K CA 2023' -notin (Get-UEFICert KEK))) {
            'WARNING: Disable Secure Boot, before attempting to use -Revoke option.  No [KEK 2K CA 2023] cert is currently enrolled.'
            '{0}System will fail to boot due to a security violation.' -f $Tab4
            exit 1
        }

        if ($Latest) {
            try {
                'Downloading "DBXUpdate.bin" from GitHub.'
                Invoke-WebRequest -UseBasicParsing -Uri $DBXUpdate_bin_URL -OutFile "$env:TEMP\DBXUpdate.bin"
                'Downloading "DBXUpdateSVN.bin" from GitHub.'
                Invoke-WebRequest -UseBasicParsing -Uri $DBXUpdateSVN_bin_URL -OutFile "$env:TEMP\DBXUpdateSVN.bin"
            }
            catch {
                $_.Exception.Message
                exit 1
            }

            $DBXUpdate_bin = "$env:TEMP\dbxupdate.bin"
            $DBXUpdateSVN_bin = "$env:TEMP\DBXUpdateSVN.bin"
        }
        else {
            $DBXUpdate_bin = "$UpdatesFolder\dbxupdate.bin"
            $DBXUpdateSVN_bin = "$UpdatesFolder\DBXUpdateSVN.bin"
        }

        try {
            $DBXSignatureData = (Get-SecureBootUEFI dbx | Get-UEFIDatabaseSignatures).SignatureList.SignatureData
        }
        catch {
            if ($_.Exception.Message -match '0xC0000100') {
                $DBXSignatureData = $false
            }
            else {
                throw $_.Exception.Message
            }
        }

        if (-not $(Match-DBXSignatureData $DBXUpdate_bin)) {
            Append-SecureBootSignedFile -Variable dbx -Filename $DBXUpdate_bin
        }
        elseif ($Latest) {
            '"dbxupdate.bin" is not a newer version.'
        }

        if ('Microsoft Windows Production PCA 2011' -notin (Get-UEFICert dbx)) {
            Append-SecureBootSignedFile -Variable dbx -Filename "$UpdatesFolder\DBXUpdate2024.bin"
        }

        if ('Microsoft Windows Production PCA 2011' -in (Get-UEFICert dbx)) {
            if (-not $(Match-DBXSignatureData $DBXUpdateSVN_bin)) {
                $Result = Append-SecureBootSignedFile -Variable dbx -Filename $DBXUpdateSVN_bin
                $SVN = Get-SecureBootUEFI_SVN $EFI_BOOTMGR_SVN_GUID

                $Result -replace ' to'," (SVN $SVN) to"
                $UEFI_Updated = $true
            }
            elseif ($Latest) {
                '"DBXUpdateSVN.bin" is not a newer version.'
            }
        }
    }

    $AvailableUpdates = 0

    if ($SkuSiPolicy -or (Test-Path -LiteralPath $EFI_SkuSiPolicy_File)) {
        try {
            $CodeIntegrity = Get-ItemPropertyValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard' -Name 'HypervisorEnforcedCodeIntegrity' -ErrorAction Stop

            if ($CodeIntegrity -eq 1) {
                $UEFI_Lock = $true
            }
        }
        catch {
        }

        $SkuSiPolicyFile_Version = Get-SkuSiPolicyVersion $SkuSiPolicy_File

        if ((Test-Path -LiteralPath $EFI_SkuSiPolicy_File)) {
            $SkuSiPolicyFile_Hash = (Get-FileHash $SkuSiPolicy_File).Hash
            $EFI_SkuSiPolicyFile_Hash = (Get-FileHash -LiteralPath $EFI_SkuSiPolicy_File).Hash

            $EFI_SkuSiPolicyFile_Version = Get-SkuSiPolicyVersion $EFI_SkuSiPolicy_File

            if (($EFI_SkuSiPolicyFile_Hash -ne $SkuSiPolicyFile_Hash) -and ([Version]$SkuSiPolicyFile_Version -gt [Version]$EFI_SkuSiPolicyFile_Version)) {
                Copy-Item $SkuSiPolicy_File "$EFI_SkuSiPolicy_File" -Force

                if ($UEFI_Lock) {
                    $AvailableUpdates = $AvailableUpdates -bor 0x10
                }

                'Deployed SkuSiPolicy.p7b, Version: {0}' -f [string]$SkuSiPolicyFile_Version
                $UEFI_Updated = $true
            }
        }
        else {
            Copy-Item $SkuSiPolicy_File "$EFI_SkuSiPolicy_File" -Force

            if ($UEFI_Lock) {
                $AvailableUpdates = $AvailableUpdates -bor 0x10
            }

            'Deployed SkuSiPolicy.p7b, Version: {0}' -f [string]$SkuSiPolicyFile_Version
            $UEFI_Updated = $true
        }
    }

    if ($SecureBoot -and -not (Get-SbatLevel)) {
        $AvailableUpdates = $AvailableUpdates -bor 0x400

        'Applying SBAT update for Linux.'
        $UEFI_Updated = $true
    }

    if ($AvailableUpdates -gt 0) {
        $null = Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates' -Value $AvailableUpdates

        switch ($SecureBoot_TaskState) {
            'DISABLED' {
                "WARNING: `"Secure-Boot-Update`" scheduled task is DISABLED.  Unable to apply `"AvailableUpdates`" = 0x{0:x}`n" -f $AvailableUpdates
            }
            'REMOVED' {
                "WARNING: `"Secure-Boot-Update`" scheduled task was REMOVED.  Unable to apply `"AvailableUpdates`" = 0x{0:x}`n" -f $AvailableUpdates
            }
            default {
                Start-ScheduledTask -TaskName '\Microsoft\Windows\PI\Secure-Boot-Update'
            }
        }
    }

    if ($Latest) {
        Remove-Item $DBXUpdate_bin,$DBXUpdateSVN_bin -Force
    }

    if ('Windows UEFI CA 2023' -in (Get-UEFICert db)) {
        $BootMgrEX_File_Hash = (Get-FileHash $BootMgrEX_File).Hash
        $BootMgr_File_Hash = (Get-FileHash -LiteralPath $BootMgr_File).Hash

        if (($PFXCert -notmatch 'Windows UEFI CA 2023') -or ($BootMgrSVN -lt $UEFI_SVN) -or ($BootMgrSVN -eq $UEFI_SVN -and $BootMgr_File_Hash -ne $BootMgrEX_File_Hash)) {
            Update-EFI_BootManager
            $UEFI_Updated = $true
        }

        if ($BootMedia) {
            $RemovableDrives = @(Get-CimInstance -ClassName Win32_LogicalDisk | where { $_.Description -match 'Removable' -and $_.FileSystem -and $_.DeviceID -match '[A-Z]' } | foreach { $_.DeviceID.SubString(0,1) })

            if ($RemovableDrives.Count -eq 0) {
                "No USB removable media found.`n"
            }
            else {
                $BootStl_File = "$env:SystemRoot\Boot\EFI\boot.stl"
                $BootStl_File_Hash = (Get-FileHash $BootStl_File).Hash

                foreach ($Drive in $RemovableDrives) {
                    Update-USB_Drive $Drive
                }

                if ($Media_Updated) { '' }
            }
        }
    }

    if ($UEFI_Updated -or $PK_README -or $KEK_README) {
        if ($UEFI_Updated -or $Latest) {
            Write-Output ''
        }

        Print-Header 'REQUIRED ACTION'

        if ($PK_README -or $KEK_README) {
            if ($PK_README -or $KEK_README) {
                if ($PK_README -and $KEK_README) {
                    $CertName = 'PK and [KEK CA 2023] certs'
                }
                elseif ($PK_README) {
                    $CertName = 'PK cert'
                }
                else {
                    $CertName = '[KEK CA 2023] cert'
                }

                "Please follow the README_UEFI.TXT instructions, for installing the {0} from BIOS.`n" -f $CertName
            }
        }

        'Restart Windows, for UEFI updates to take effect.'
    }
    else {
        if ($Latest) {
            Write-Output ''
        }

       'SUCCESS: NO UPDATES ARE REQUIRED.'
    }
}

if ($Force -or $Log) {
    $LogFile = '{0}\{1} {2} Update-UEFI.log' -f $PSScriptRoot, (Get-Date -Format 'yyyy-MM-dd'), ($System.Model.ToUpper().Split([IO.Path]::GetInvalidFileNameChars()) -join '_')

    & $ScriptBlock | Tee-Object $LogFile
    "`nLog file saved as `"{0}`"`n" -f $LogFile
}
else {
    & $ScriptBlock
    Write-Output ''
}

<#PSScriptInfo

.VERSION 2026.08.03

.GUID ab687543-1a54-4da4-9870-8e8523ea806f

.AUTHOR garlin

.COPYRIGHT

.TAGS UEFI, Secure Boot, CA 2023, KEK, DB, DBX, SVN, Windows Boot Manager

.RELEASENOTES

#>

<#
.SYNOPSIS
    Script to identify Secure Boot certificates installed in the UEFI variables, and signing certs for Windows boot files.

.DESCRIPTION
    Run this script to check Windows compliance with Secure Boot CA 2023 updates, and CA 2011 revocation.

.PARAMETER Version
    Print the script's version number and exit.

.PARAMETER Verbose
    Identify extra details including the Windows build version.  Windows Boot Manager SVN will be reported, if present in DBX.

.PARAMETER Audit
    If Secure Boot is currently disabled, report will simulate conditions where Secure Boot is enabled.

.PARAMETER NoSkip
    When checking Windows install files on removable media, examine every image in the install WIM/ESD file.
    By default, -BootMedia parameter stops checking after the first image in the install file to improve script reporting time.

.PARAMETER Log
    Save script output to a file named "YYYY-MM-DD [Model] Check UEFI.log"

.EXAMPLE
    Check_BootMedia.ps1
.EXAMPLE
    Check_BootMedia.ps1 -Verbose
    Check_BootMedia.ps1 -Verbose -Audit -Log
#>

[CmdletBinding(DefaultParameterSetName='Default')]
param (
    [Parameter(Mandatory=$false,ParameterSetName='Version')]
    [switch]$Version,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Audit,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$NoSkip,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Log
)

$ScriptVersion = '2026.08.03'

# https://github.com/microsoft/secureboot_objects/blob/main/Archived/dbx_info_msft_4_09_24_svns.csv
$EFI_BOOTMGR_SVN_GUID = '01612B139DD5598843AB1C185C3CB2EB92'
$EFI_CDBOOT_SVN_GUID =  '019D2EF8E827E15841A4884C18ABE2F284'
$EFI_WDSMGR_SVN_GUID =  '01C2CA99C9FE7F6F4981279E2A8A535976'

$CN_Regex = '(CN=)([^,]+)'

$Tab4 = ' ' * 4
$Tab8 = ' ' * 8
$Tab12 = ' ' * 12

$TEMP_DIR = "$env:TEMP"

$wimlib_URL = 'https://wimlib.net/downloads/wimlib-1.14.5-windows-x86_64-bin.zip'

$wimlib_imagex = "$TEMP_DIR\wimlib-imagex.exe"
$wimlib_dll = "$TEMP_DIR\libwim-15.dll"

$7z_exe_URL = 'https://gitlab.com/stdout12/bat-util/-/raw/28560e775cd2623b8360d42a4c4d1f822b13e7df/uup-converter-wimlib/bin/7z.exe'
$7z_dll_URL = 'https://gitlab.com/stdout12/bat-util/-/raw/28560e775cd2623b8360d42a4c4d1f822b13e7df/uup-converter-wimlib/bin/7z.dll'

$7z_exe = "$TEMP_DIR\7z.exe"
$7z_dll = "$TEMP_DIR\7z.dll"

$offlinereg_URL = 'http://erwan.labalec.fr/offlinereg/offlinereg.zip'

$offlinereg = "$env:TEMP\offlinereg-win32.exe"
$offlinereg_dll = "$env:TEMP\offreg.dll"

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

    $args = ($MyInvocation.BoundParameters.Keys.GetEnumerator() | where { $_ -notmatch 'ignored' } | foreach { '-{0}' -f $_ }) -join ' '

    Start-Process $PS -ArgumentList "-nop -ep bypass -NoLogo -NoExit -f `"$($MyInvocation.MyCommand.Path)`" $args" -Verb RunAs
    exit 0
}

if ($PSBoundParameters['Verbose']) {
    $Verbose = $true
    $VerbosePreference = 'SilentlyContinue'
}

if ([Environment]::Is64BitProcess) {
    $UpdatesFolder = "$env:SystemRoot\System32\SecureBootUpdates"
}
else {
    $UpdatesFolder = "$env:SystemRoot\SysNative\SecureBootUpdates"
}

switch ($env:PROCESSOR_ARCHITECTURE) {
    'amd64' { $Arch = 'x64' }
    'x86'   { $Arch = 'x86' }
    'arm64' { $Arch = 'aa64' }
    'arm'   { $Arch = 'aa32' }
}

$System = Get-CimInstance -ClassName Win32_ComputerSystem
$SystemDrive = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

function Install-Tools {
    $objShell = New-Object -ComObject 'Shell.Application'
    $objFolder = $objShell.NameSpace($env:TEMP)

    if (-not (Test-Path $wimlib_imagex -PathType Leaf) -or -not (Test-Path $wimlib_dll -PathType Leaf)) {
        try {
            $ZIP_File = '{0}\{1}' -f $env:TEMP, ($wimlib_URL -split '/')[-1]

            Invoke-WebRequest -UseBasicParsing -Uri $wimlib_URL -OutFile $ZIP_File

            $objFolder.CopyHere("$($ZIP_File)\wimlib-imagex.exe", 0x14)
            $objFolder.CopyHere("$($ZIP_File)\libwim-15.dll", 0x14)
            $objFolder.CopyHere("$($ZIP_File)\COPYING.txt", 0x14)
            $objFolder.CopyHere("$($ZIP_File)\COPYING.GPLv3.txt", 0x14)
            $objFolder.CopyHere("$($ZIP_File)\COPYING.LGPL.txt", 0x14)
            $objFolder.CopyHere("$($ZIP_File)\COPYING.libdivsufsort-lite.txt", 0x14)

            Remove-Item $ZIP_File -Force
        }
        catch {
            $_.Exception.Message
        }
    }

if (-not (Test-Path $7z_exe) -or -not (Test-Path $7z_dll)) {
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $7z_exe_URL -OutFile $7z_exe
        Invoke-WebRequest -UseBasicParsing -Uri $7z_dll_URL -OutFile $7z_dll
    }
    catch {
        $_.Exception.Message
    }
}

    if (-not (Test-Path $offlinereg -PathType Leaf) -or -not (Test-Path $offlinereg_dll -PathType Leaf)) {
        try {
            $ZIP_File = '{0}\{1}' -f $env:TEMP, ($offlinereg_URL -split '/')[-1]

            Invoke-WebRequest -UseBasicParsing -Uri $offlinereg_URL -OutFile $ZIP_File

            $objFolder.CopyHere("$($ZIP_File)\offlinereg-win32.exe", 0x14)
            $objFolder.CopyHere("$($ZIP_File)\offreg.dll", 0x14)
            $objFolder.CopyHere("$($ZIP_File)\license.txt", 0x14)

            Remove-Item $ZIP_File -Force
        }
        catch {
            $_.Exception.Message
        }
    }
}

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

    return ("`n{0}`n{1}" -f $Header, ($Header -replace "`n" -replace '(.)',$Separator))
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
        [ValidateSet('KEK','db','dbx')]
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
    $Certs = $Subject | where { $_ -match 'Microsoft' } | foreach { $null = $_ -match $CN_Regex; $Matches[2] }

    return $Certs
}

function Print-UEFICerts {
    param (
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ref]$CertArray
    )

    Print-Header "UEFI $Name Certs"

    if (($CertArray.Value).Count) {
        $SortedArray = @(foreach ($item in $CertArray.Value) {
            [PSCustomObject] @{
                Date = ($item -split ' ')[-1]
                Name = $item
            }
        }) | sort Date, Name | select -ExpandProperty Name

        $SortedArray | foreach { '{0}{1}' -f $Tab4, $_ }
    }
    else {
        '{0}(NONE)' -f $Tab4
    }
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

function Validate-PFXCert {
    param (
        [Parameter(Mandatory)]
        [string]$CertName
    )

    if ($SecureBoot -eq $false) {
        return 'ALLOWED'
    }

    switch -Regex ($CertName) {
        '2011' {
            if ($KEK_Certs -contains 'Microsoft Corporation KEK CA 2011' -and $db_Certs -contains $CertName) {
                if ($dbx_Certs -contains $CertName) {
                    return 'BANNED'
                }
                else {
                    return 'ALLOWED'
                }
            }
        }

        '2023' {
            if ($KEK_Certs -contains 'Microsoft Corporation KEK 2K CA 2023' -and $db_Certs -contains $CertName) {
                if ($dbx_Certs -contains $CertName) {
                    return 'BANNED'
                }
                else {
                    return 'ALLOWED'
                }
            }
        }
    }

    return 'UNTRUSTED'
}

function Get-SignatureDataSVN {
    param (
        [Parameter(Mandatory)]
        [string]$SignatureData
    )

    if ($SignatureData) {
        # https://github.com/microsoft/secureboot_objects/blob/main/scripts/utility_functions.py
        [version]$SVN = '{0}.{1}' -f [System.Convert]::ToUInt16($SignatureData.Substring(40,2) + $SignatureData.Substring(38,2), 16), [System.Convert]::ToUInt16($SignatureData.Substring(36,2) + $SignatureData.Substring(34,2), 16)
    }
    else {
        $SVN = $null
    }

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

function Get-UEFI_DeviceGuard {
    $LastBootUpTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $Events = Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-Kernel-Boot'; Id=153; StartTime=$LastBootUpTime} -ErrorAction SilentlyContinue | where { $_.Message -match 'VBS locked' }

    if ($Events.Count) {
        return $true
    }
    else {
        return $false
    }
}

Add-Type -AssemblyName System.Security

function ConvertTo-SkuSiPolicy {
<#
    .SYNOPSIS

    Converts a binary file that contains a Code Integrity Boot Policy into XML format.
    https://gist.github.com/HarmJ0y/c5cf17def719d3b6406a89504ec518c4

    Original Author: Matthew Graeber (@mattifestation)
    Contributors: James Forshaw (@tiraniddo) - thanks for the major bug fixes!
    Modified by @garlin-cant-code

    License: BSD 3-Clause

    Modified to add proper PKCS#7 support and the new DG policy header version.

    .DESCRIPTION

    ConvertTo-SkuSiPolicy converts a binary file that contains a Code Integrity Boot Policy into XML format. This function is used to audit deployed Code Integrity policies for which the original XML is not present. It can also be used to compare deployed rules against a reference XML file.

    Note: the process of converting an XML file to a binary policy is lossy. ID, Name, and FriendlyName attributes are all lost in the process. ConvertTo-SkuSiPolicy auto-generates ID and Name properties when necessary.

    ConvertTo-SkuSiPolicy supports both signed and unsigned policies.

    .PARAMETER BinaryFilePath

    Specifies the path of the binary policy file that this cmdlet converts. Deployed binary policy files are located in \EFI\Microsoft\Boot\SKUSiPolicy.p7b

    .EXAMPLE

    ConvertTo-SkuSiPolicy -BinaryFilePath C:\Windows\System32\SecureBootUpdates\SKUSiPolicy.p7b

    .OUTPUTS

    System.Xml.XmlDocument

    Outputs a recovered Code Integrity policy XML document only containing the FileRules.
#>

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Position = 0, Mandatory)]
        [String]
        $BinaryFilePath
    )

    $CorruptPolicyErr = 'The CI policy may be corrupt.'

    $HeaderLengthMax = 0x44
    $GuidLength = 0x10

    # Generated code that enables CI policy XML serialization.
    $TypeDef = @'
    using System.Xml.Serialization;

    namespace CodeIntegrity {
        // The following code was generated with: xsd.exe C:\Windows\schemas\CodeIntegrity\cipolicy.xsd /classes /namespace:CodeIntegrity

        /// <remarks/>
        [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.8.3698.0")]
        [System.SerializableAttribute()]
        [System.Diagnostics.DebuggerStepThroughAttribute()]
        [System.ComponentModel.DesignerCategoryAttribute("code")]
        [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="urn:schemas-microsoft-com:sipolicy")]
        [System.Xml.Serialization.XmlRootAttribute(Namespace="urn:schemas-microsoft-com:sipolicy", IsNullable=false)]
        public partial class FileRules {
            private object[] itemsField;

            /// <remarks/>
            [System.Xml.Serialization.XmlElementAttribute("Allow", typeof(Allow))]
            [System.Xml.Serialization.XmlElementAttribute("Deny", typeof(Deny))]
            [System.Xml.Serialization.XmlElementAttribute("FileAttrib", typeof(FileAttrib))]
            public object[] Items {
                get {
                    return this.itemsField;
                }
                set {
                    this.itemsField = value;
                }
            }
        }

        /// <remarks/>
        [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.8.3698.0")]
        [System.SerializableAttribute()]
        [System.Diagnostics.DebuggerStepThroughAttribute()]
        [System.ComponentModel.DesignerCategoryAttribute("code")]
        [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="urn:schemas-microsoft-com:sipolicy")]
        [System.Xml.Serialization.XmlRootAttribute(Namespace="urn:schemas-microsoft-com:sipolicy", IsNullable=false)]
        public partial class Allow {
            private string idField;
            private string fileNameField;
            private string minimumFileVersionField;
            private string maximumFileVersionField;

            /// <remarks/>
            [System.Xml.Serialization.XmlAttributeAttribute()]
            public string ID {
                get {
                    return this.idField;
                }
                set {
                    this.idField = value;
                }
            }

            /// <remarks/>
            [System.Xml.Serialization.XmlAttributeAttribute()]
            public string FileName {
                get {
                    return this.fileNameField;
                }
                set {
                    this.fileNameField = value;
                }
            }

            /// <remarks/>
            [System.Xml.Serialization.XmlAttributeAttribute()]
            public string MinimumFileVersion {
                get {
                    return this.minimumFileVersionField;
                }
                set {
                    this.minimumFileVersionField = value;
                }
            }

            /// <remarks/>
            [System.Xml.Serialization.XmlAttributeAttribute()]
            public string MaximumFileVersion {
                get {
                    return this.maximumFileVersionField;
                }
                set {
                    this.maximumFileVersionField = value;
                }
            }
        }

        /// <remarks/>
        [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.8.3698.0")]
        [System.SerializableAttribute()]
        [System.Diagnostics.DebuggerStepThroughAttribute()]
        [System.ComponentModel.DesignerCategoryAttribute("code")]
        [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="urn:schemas-microsoft-com:sipolicy")]
        [System.Xml.Serialization.XmlRootAttribute(Namespace="urn:schemas-microsoft-com:sipolicy", IsNullable=false)]
        public partial class Deny {
            private string idField;
            private string fileNameField;
            private string minimumFileVersionField;
            private string maximumFileVersionField;

            /// <remarks/>
            [System.Xml.Serialization.XmlAttributeAttribute()]
            public string ID {
                get {
                    return this.idField;
                }
                set {
                    this.idField = value;
                }
            }

            /// <remarks/>
            [System.Xml.Serialization.XmlAttributeAttribute()]
            public string FileName {
                get {
                    return this.fileNameField;
                }
                set {
                    this.fileNameField = value;
                }
            }

            /// <remarks/>
            [System.Xml.Serialization.XmlAttributeAttribute()]
            public string MinimumFileVersion {
                get {
                    return this.minimumFileVersionField;
                }
                set {
                    this.minimumFileVersionField = value;
                }
            }

            /// <remarks/>
            [System.Xml.Serialization.XmlAttributeAttribute()]
            public string MaximumFileVersion {
                get {
                    return this.maximumFileVersionField;
                }
                set {
                    this.maximumFileVersionField = value;
                }
            }
        }

        /// <remarks/>
        [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.8.3698.0")]
        [System.SerializableAttribute()]
        [System.Diagnostics.DebuggerStepThroughAttribute()]
        [System.ComponentModel.DesignerCategoryAttribute("code")]
        [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="urn:schemas-microsoft-com:sipolicy")]
        [System.Xml.Serialization.XmlRootAttribute(Namespace="urn:schemas-microsoft-com:sipolicy", IsNullable=false)]
        public partial class FileAttrib {
            private string idField;
            private string fileNameField;
            private string minimumFileVersionField;
            private string maximumFileVersionField;

            /// <remarks/>
            [System.Xml.Serialization.XmlAttributeAttribute()]
            public string ID {
                get {
                    return this.idField;
                }
                set {
                    this.idField = value;
                }
            }

            /// <remarks/>
            [System.Xml.Serialization.XmlAttributeAttribute()]
            public string FileName {
                get {
                    return this.fileNameField;
                }
                set {
                    this.fileNameField = value;
                }
            }

            /// <remarks/>
            [System.Xml.Serialization.XmlAttributeAttribute()]
            public string MinimumFileVersion {
                get {
                    return this.minimumFileVersionField;
                }
                set {
                    this.minimumFileVersionField = value;
                }
            }

            /// <remarks/>
            [System.Xml.Serialization.XmlAttributeAttribute()]
            public string MaximumFileVersion {
                get {
                    return this.maximumFileVersionField;
                }
                set {
                    this.maximumFileVersionField = value;
                }
            }
        }

        /// <remarks/>
        [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.8.3698.0")]
        [System.SerializableAttribute()]
        [System.Diagnostics.DebuggerStepThroughAttribute()]
        [System.ComponentModel.DesignerCategoryAttribute("code")]
        [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="urn:schemas-microsoft-com:sipolicy")]
        [System.Xml.Serialization.XmlRootAttribute(Namespace="urn:schemas-microsoft-com:sipolicy", IsNullable=false)]
        public partial class SiPolicy {
            private string versionExField;
            private object[] fileRulesField;

            /// <remarks/>
            public string VersionEx {
                get {
                    return this.versionExField;
                }
                set {
                    this.versionExField = value;
                }
            }

            /// <remarks/>
            [System.Xml.Serialization.XmlArrayItemAttribute("Allow", typeof(Allow), IsNullable=false)]
            [System.Xml.Serialization.XmlArrayItemAttribute("Deny", typeof(Deny), IsNullable=false)]
            [System.Xml.Serialization.XmlArrayItemAttribute("FileAttrib", typeof(FileAttrib), IsNullable=false)]
            public object[] FileRules {
                get {
                    return this.fileRulesField;
                }
                set {
                    this.fileRulesField = value;
                }
            }
        }
    }
'@

    if (-not ('CodeIntegrity.SIPolicy' -as [Type])) {
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            Add-Type -TypeDefinition $TypeDef
        }
        else {
            Add-Type -TypeDefinition $TypeDef -ReferencedAssemblies System.Xml
        }
    }

    # Helper function to read strings from the binary
    function Get-BinaryString {
        [OutputType('String')]
        param (
            [Parameter(Mandatory)]
            [IO.BinaryReader]
            [ValidateNotNullOrEmpty()]
            $BinaryReader
        )

        $StringLength = $BinaryReader.ReadUInt32()

        if ($StringLength) {
            $PaddingBytes = 4 - $StringLength % 4 -band 3

            $StringBytes = $BinaryReader.ReadBytes($StringLength)
            $null = $BinaryReader.ReadBytes($PaddingBytes)

            [Text.Encoding]::Unicode.GetString($StringBytes)
        }

        $null = $BinaryReader.ReadInt32()
    }

    try {
        $CIPolicyBytes = [IO.File]::ReadAllBytes($BinaryFilePath)

        try {
            $ContentType = $null

            try {
                $ContentType = [Security.Cryptography.Pkcs.ContentInfo]::GetContentType($CIPolicyBytes)
            } catch { }

            # Check for PKCS#7 ASN.1 SignedData type
            if ($ContentType -and $ContentType.Value -eq '1.2.840.113549.1.7.2') {
                $Cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
                $Cms.Decode($CIPolicyBytes)
                $CIPolicyBytes = $Cms.ContentInfo.Content

                if ($CIPolicyBytes[0] -eq 4) {
                    # Policy is stored as an OCTET STRING
                    $PolicySize = $CIPolicyBytes[1]
                    $BaseIndex = 2

                    if (($PolicySize -band 0x80) -eq 0x80) {
                        $SizeCount = $PolicySize -band 0x7F
                        $BaseIndex += $SizeCount
                        $PolicySize = 0

                        for ($i = 0; $i -lt $SizeCount; $i++) {
                            $PolicySize = $PolicySize -shl 8
                            $PolicySize = $PolicySize -bor $CIPolicyBytes[2 + $i]
                        }
                    }

                    $CIPolicyBytes = $CIPolicyBytes[$BaseIndex..($BaseIndex + $PolicySize - 1)]
                }
            }
        } catch {
            Write-Output $_
        }

        $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$CIPolicyBytes)
        $BinaryReader = New-Object -TypeName System.IO.BinaryReader -ArgumentList $MemoryStream, ([Text.Encoding]::Unicode)
    } catch {
        throw $_
        return
    }

    $SIPolicy = New-Object -TypeName CodeIntegrity.SIPolicy

    try {
        # Validate binary CI policy header
        # This header value indicates likely indicates the schema version that was used.
        # This script will only support whatever the latest schema version was at the time of last update, in this case, 7.
        $CIPolicyFormatVersion = $BinaryReader.ReadInt32()

        # My inference is that the binary format will terminate with a UInt32 value that is $CIPolicyFormatVersion + 1.
        # For example, if $CIPolicyFormatVersion is 7, the binary policy is expected to be terminated with 0x00000008.
        # This way, should the following warning be presented, should a format version of 8 be introduced, I will know that
        # there will be binary data in need of parsing beyond 0x00000008.

        # Hush, little baby, don't say a word, Mama's gonna buy you a mockingbird.

        if ($CIPolicyFormatVersion -gt 7) {
            #Write-Warning "$BinaryFilePath has an invalid or unsupported binary CI policy format version value: 0x$($CIPolicyFormatVersion.ToString('X8')). If you are sure that you are dealing with a binary code integrity policy, there is a high likelihood that Microsoft updated the binary file format to support new schema elements and that this code will likely need to be updated."
        }

        $PolicyTypeID = [Guid][Byte[]] $BinaryReader.ReadBytes($GuidLength)

        [Byte[]] $PlatformIDBytes = $BinaryReader.ReadBytes($GuidLength)

        $OptionFlags = $BinaryReader.ReadInt32()

        # Validate that the high bit is set - i.e. mask it off with 0x80000000
        if ($OptionFlags -band ([Int32]::MinValue) -ne [Int32]::MinValue) {
            throw "Invalid policy options flag. $CorruptPolicyErr"
            return
        }

        if (($OptionFlags -band 0x40000000) -eq 0x40000000) {
            Write-Warning 'Policy option flags indicate that the code integrity policy was built from supplmental policies.'
        }

        $EKURuleEntryCount = $BinaryReader.ReadInt32()

        $FileRuleEntryCount = $BinaryReader.ReadInt32()

        $SignerRuleEntryCount = $BinaryReader.ReadInt32()

        $SignerScenarioEntryCount = $BinaryReader.ReadInt32()

        $Revision = $BinaryReader.ReadUInt16()
        $Build = $BinaryReader.ReadUInt16()
        $Minor = $BinaryReader.ReadUInt16()
        $Major = $BinaryReader.ReadUInt16()

        $SIPolicy.VersionEx = New-Object -TypeName Version -ArgumentList $Major, $Minor, $Build, $Revision

        # Validate that the fixed header length was written to the end of the header
        $HeaderLength = $BinaryReader.ReadInt32()

        if ($HeaderLength -ne ($HeaderLengthMax - 4)) {
            Write-Warning "$BinaryFilePath has an invalid header footer: 0x$($HeaderLength.ToString('X8')). $CorruptPolicyErr"
        }

        if ($EKURuleEntryCount) {
            for ($i = 0; $i -lt $EKURuleEntryCount; $i++) {
                # Length of the encoded EKU OID value
                $EkuValueLen = $BinaryReader.ReadUInt32()

                # Length of the encoded EKU OID value padded out to 4 bytes
                $PaddingBytes = 4 - $EkuValueLen % 4 -band 3

                $EKUValueBytes = $BinaryReader.ReadBytes($EkuValueLen)
                $null = $BinaryReader.ReadBytes($PaddingBytes)
            }
        }

        if ($FileRuleEntryCount) {
            # The XMl serializer won't validate unless
            # I use a generic collection vs. a System.Object[].
            $Script:FileRulesArray = New-Object -TypeName 'System.Collections.Generic.List[Object]'

            for ($i = 0; $i -lt $FileRuleEntryCount; $i++) {
                $FileRuleTypeValue = $BinaryReader.ReadInt32()

                switch ($FileRuleTypeValue) {
                    0 {
                        $TypeName = 'CodeIntegrity.Deny'
                        $ID = "ID_DENY_D_$(($i + 1).ToString('X4'))"
                    }

                    1 {
                        $TypeName = 'CodeIntegrity.Allow'
                        $ID = "ID_ALLOW_A_$(($i + 1).ToString('X4'))"
                    }

                    2 {
                        $TypeName = 'CodeIntegrity.FileAttrib'
                        $ID = "ID_FILEATTRIB_F_$(($i + 1).ToString('X4'))"
                    }

                    default { throw "Invalid file rule type: 0x$($FileRuleTypeValue.ToString('X8'))" }
                }

                $FileRule = New-Object -TypeName $TypeName -Property @{ ID = $ID }

                $FileName = Get-BinaryString -BinaryReader $BinaryReader

                if ($FileName) {
                    $FileRule.FileName = $FileName
                }

                $Revision = $BinaryReader.ReadUInt16()
                $Build = $BinaryReader.ReadUInt16()
                $Minor = $BinaryReader.ReadUInt16()
                $Major = $BinaryReader.ReadUInt16()

                $MinimumVersion = New-Object -TypeName Version -ArgumentList $Major, $Minor, $Build, $Revision

                # If it's a deny rule and MaximumFileVersion is null, the version will be set to 65535.65535.65535.65535
                # Otherwise, if MinimumFileVersion is non-zero, then a MinimumFileVersion was specified.
                if (!(($FileRuleTypeValue -eq 0) -and ($MinimumVersion -eq '65535.65535.65535.65535')) -and ($MinimumVersion -ne '0.0.0.0')) {
                    $FileRule.MinimumFileVersion = $MinimumVersion
                }

                $HashLen = $BinaryReader.ReadUInt32()

                if ($HashLen) {
                    $PaddingBytes = 4 - $HashLen % 4 -band 3

                    $HashBytes = $BinaryReader.ReadBytes($HashLen)
                    $null = $BinaryReader.ReadBytes($PaddingBytes)
                }

                $Script:FileRulesArray.Add($FileRule)
            }

            $SIPolicy.FileRules = $Script:FileRulesArray
        }

        if ($SignerRuleEntryCount) {
            for ($i = 0; $i -lt $SignerRuleEntryCount; $i++) {
                $CertRootTypeValue = $BinaryReader.ReadInt32()

                switch ($CertRootTypeValue) {
                    0 { $CertRootType = 'TBS' } # TBS - To Be Signed
                    1 { $CertRootType = 'WellKnown' }
                    default { throw "Invalid certificate root type: 0x$($CertRooTypeValue.ToString('X8'))" }
                }

                if ($CertRootType -eq 'TBS') {
                    $CertRootLength = $BinaryReader.ReadUInt32()

                    if ($CertRootLength) {
                        $PaddingBytes = 4 - $CertRootLength % 4 -band 3

                        # This is a hash of the ToBeSigned data blob.
                        # The hashing algorithm used is dictated by the algorithm specified in the certificate.
                        [Byte[]] $CertRootBytes = $BinaryReader.ReadBytes($CertRootLength)

                        $null = $BinaryReader.ReadBytes($PaddingBytes)
                    }
                } else {
                    # WellKnown type

                    # I'd like to know what these map to. I assume there's a mapped list of common
                    # Microsoft root certificates.
                    # It doesn't appear as though the ConfigCI cmdlets can generate a well known root type.
                    [Byte[]] $CertRootBytes = @(($BinaryReader.ReadUInt32() -band 0xFF))
                }

                $CertEKULength = $BinaryReader.ReadUInt32()

                if ($CertEKULength) {
                    for ($j = 0; $j -lt $CertEKULength; $j++) {
                        $EKUIndex = $BinaryReader.ReadUInt32()
                    }
                }

                $CertIssuer = Get-BinaryString -BinaryReader $BinaryReader

                $CertPublisher = Get-BinaryString -BinaryReader $BinaryReader

                $CertOemID = Get-BinaryString -BinaryReader $BinaryReader

                $FileAttribRefLength = $BinaryReader.ReadUInt32()

                if ($FileAttribRefLength) {
                    for ($j = 0; $j -lt $FileAttribRefLength; $j++) {
                        $FileAttribRefIndex = $BinaryReader.ReadUInt32()
                    }
                }
            }
        }

        $UpdatePolicySignersLength = $BinaryReader.ReadUInt32()

        if ($UpdatePolicySignersLength) {
            for ($i = 0; $i -lt $UpdatePolicySignersLength; $i++) {
                $UpdatePolicySignersIndex = $BinaryReader.ReadUInt32()
            }
        }

        $CISignersLength = $BinaryReader.ReadUInt32()

        if ($CISignersLength) {
            for ($i = 0; $i -lt $CISignersLength; $i++) {
                $CISignersIndex = $BinaryReader.ReadUInt32()
            }
        }

        if ($SignerScenarioEntryCount) {
            for ($i = 0; $i -lt $SignerScenarioEntryCount; $i++) {
                [Byte] $SigningScenarioValue = $BinaryReader.ReadUInt32() -band 0xFF

                # The ability to inherit from another signing scenario is not formally documented
                # other than in the SIPolicy schema.
                $InheritedScenarioLength = $BinaryReader.ReadUInt32()

                if ($InheritedScenarioLength) {
                    $InheritedScenarios = New-Object UInt32[]($InheritedScenarioLength)

                    for ($j = 0; $j -lt $InheritedScenarioLength; $j++) {
                        $InheritedScenarios[$j] = $BinaryReader.ReadUInt32()
                    }
                }

                [UInt16] $MinimumHashValueValue = $BinaryReader.ReadUInt32() -band [UInt16]::MaxValue

                # Loop over product signers, test signers, and test signing signers
                1..3 | ForEach-Object {
                    $AllowedSignersCount = $BinaryReader.ReadUInt32()

                    if ($AllowedSignersCount) {
                        for ($j = 0; $j -lt $AllowedSignersCount; $j++) {
                            $AllowedSignerIndex = $BinaryReader.ReadUInt32()

                            $ExceptDenyRuleLength = $BinaryReader.ReadUInt32()
                        }
                    }

                    $DeniedSignersCount = $BinaryReader.ReadUInt32()

                    if ($DeniedSignersCount) {
                        for ($j = 0; $j -lt $DeniedSignersCount; $j++) {
                            $DeniedSignerIndex = $BinaryReader.ReadUInt32()

                            $ExceptAllowRuleLength = $BinaryReader.ReadUInt32()
                        }
                    }

                    $FileRulesRefCount = $BinaryReader.ReadUInt32()

                    if ($FileRulesRefCount) {
                        for ($j = 0; $j -lt $FileRulesRefCount; $j++) {
                            $FileRulesRefIndex = $BinaryReader.ReadUInt32()
                        }
                    }
                }
            }
        }

        $HVCIOptions = $BinaryReader.ReadUInt32()

        $SecureSettingsLength = $BinaryReader.ReadUInt32()

        if ($SecureSettingsLength) {
            for ($i = 0; $i -lt $SecureSettingsLength; $i++) {
                $Provider = Get-BinaryString -BinaryReader $BinaryReader
                $Key = Get-BinaryString -BinaryReader $BinaryReader
                $ValueName = Get-BinaryString -BinaryReader $BinaryReader

                $ValueType = $BinaryReader.ReadUInt32()

                switch ($ValueType) {
                    0 { # Boolean type
                        [Bool] $Value = $BinaryReader.ReadUInt32()
                    }

                    1 { # Unsigned int type
                        [UInt32] $Value = $BinaryReader.ReadUInt32()
                    }

                    2 { # Byte array type
                        # Length of the byte array
                        $ByteArrayLen = $BinaryReader.ReadUInt32()

                        # Length of the byte array padded out to 4 bytes
                        $PaddingBytes = 4 - $ByteArrayLen % 4 -band 3

                        $ValueBytes = $BinaryReader.ReadBytes($ByteArrayLen)
                        $null = $BinaryReader.ReadBytes($PaddingBytes)
                    }

                    3 { # String type
                        [String] $Value = Get-BinaryString -BinaryReader $BinaryReader
                    }
                }
            }
        }

        $V3RuleSupport = $BinaryReader.ReadUInt32()

        if ($V3RuleSupport -eq 3 -and $CIPolicyFormatVersion -ge 3) {
            if ($FileRuleEntryCount) {
                for ($i = 0; $i -lt $FileRuleEntryCount; $i++) {
                    $Revision = $BinaryReader.ReadUInt16()
                    $Build = $BinaryReader.ReadUInt16()
                    $Minor = $BinaryReader.ReadUInt16()
                    $Major = $BinaryReader.ReadUInt16()

                    $MaximumVersion = New-Object -TypeName Version -ArgumentList $Major, $Minor, $Build, $Revision

                    if ($MaximumVersion -ne ([Version] '0.0.0.0')) {
                        $Script:FileRulesArray[$i].MaximumFileVersion = $MaximumVersion
                    }

                    $MacroStringCount = $BinaryReader.ReadUInt32()

                    # Note: macro names are not stored in a binary policy (only values) so no effort will be made to infer macro names.
                    if ($MacroStringCount) {
                        if ($MacroStringCount -eq 1) {
                            $MacroString = Get-BinaryString -BinaryReader $BinaryReader
                        } else {
                            $MacroStrings = (1..$MacroStringCount | ForEach-Object { Get-BinaryString -BinaryReader $BinaryReader }) -join ''
                        }
                    }
                }
            }

            if ($SignerRuleEntryCount) {
                for ($i = 0; $i -lt $SignerRuleEntryCount; $i++) {
                    $SignTimeAfterValue = $BinaryReader.ReadInt64()
                }
            }

            $V4RuleSupport = $BinaryReader.ReadUInt32()

            if ($V4RuleSupport -eq 4 -and $CIPolicyFormatVersion -ge 4) {
                if ($FileRuleEntryCount) {
                    for ($i = 0; $i -lt $FileRuleEntryCount; $i++) {
                        $InternalName = Get-BinaryString -BinaryReader $BinaryReader
                        $FileDescription = Get-BinaryString -BinaryReader $BinaryReader
                        $ProductName = Get-BinaryString -BinaryReader $BinaryReader
                    }
                }

                $V5RuleSupport = $BinaryReader.ReadUInt32()

                if ($V5RuleSupport -eq 5 -and $CIPolicyFormatVersion -ge 5) {
                    if ($FileRuleEntryCount) {
                        for ($i = 0; $i -lt $FileRuleEntryCount; $i++) {
                            $PackageFamilyName = Get-BinaryString -BinaryReader $BinaryReader

                            $Revision = $BinaryReader.ReadUInt16()
                            $Build = $BinaryReader.ReadUInt16()
                            $Minor = $BinaryReader.ReadUInt16()
                            $Major = $BinaryReader.ReadUInt16()
                        }
                    }

                    $V6RuleSupport = $BinaryReader.ReadUInt32()

                    if ($V6RuleSupport -eq 6 -and $CIPolicyFormatVersion -ge 6) {
                        # The CI policy has the new BasePolicyID and PolicyID elements versus the older PolicyTypeID element.

                        $PolicyID = [Guid][Byte[]] $BinaryReader.ReadBytes($GuidLength)

                        $BasePolicyID = [Guid][Byte[]] $BinaryReader.ReadBytes($GuidLength)

                        $SupplementalSignerRuleEntryCount = $BinaryReader.ReadUInt32()

                        if ($SupplementalSignerRuleEntryCount) {
                            for ($i = 0; $i -lt $SupplementalSignerRuleEntryCount; $i++) {
                                $SupplemetalSignersIndex = $BinaryReader.ReadUInt32()
                            }
                        }

                        $V7RuleSupport = $BinaryReader.ReadUInt32()

                        if ($V7RuleSupport -eq 7 -and $CIPolicyFormatVersion -ge 7) {
                            if ($FileRuleEntryCount) {
                                for ($i = 0; $i -lt $FileRuleEntryCount; $i++) {
                                    $FilePath = Get-BinaryString -BinaryReader $BinaryReader
                                }
                            }

                            $V8RuleSupport = $BinaryReader.ReadUInt32()

                            # To-do: What follows will need to be updated when a new CI policy schema is released.
                            if ($V8RuleSupport -ne 8) {
                                Write-Warning 'A parsing error may have occurred. The CI policy should end with 0x00000008.'
                            }
                        }
                    }
                }
            }

            if ($FileRuleEntryCount) { $SIPolicy.FileRules = $Script:FileRulesArray }
        }
    } catch {
        $BinaryReader.Close()
        $MemoryStream.Close()

        throw $_
        return
    }

    $BinaryReader.Close()
    $MemoryStream.Close()

    return $SIPolicy
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

function Validate-BootMgrFile
{
    param (
        [Parameter(Mandatory)]
        [string]$BootMgr_File,

        [Parameter(Mandatory)]
        [string]$Label,

        [Parameter(Mandatory=$false)]
        [string]$ShowAsFile,

        [Parameter(Mandatory)]
        [string]$Indent,

        [Parameter(Mandatory=$false)]
        [switch]$SkipNewLine
    )

    $PFXCert = Get-PFXCert $BootMgr_File
    $BootMgrSVN = Get-BootManagerSVN $BootMgr_File

    switch -Regex (Validate-PFXCert $PFXCert) {
        'BANNED|UNTRUSTED' {
            '{0}{1} [{2}] {3} {4}.' -f $Indent, $Label, ($PFXCert -replace 'Microsoft Windows '), $SecureBoot_Verb, $_
        }

        'ALLOWED' {
            if (-not $SecureBoot -or $BootMgrSVN -ge $UEFI_SVN) {
                '{0}{1} [{2}] {3} ALLOWED.' -f $Indent, $Label, ($PFXCert -replace 'Microsoft Windows '), $SecureBoot_Verb
            }
            else {
                '{0}{1} [{2}] {3} BANNED.' -f $Indent, $Label, ($PFXCert -replace 'Microsoft Windows '), $SecureBoot_Verb
            }
        }
    }

    if ($Verbose) {
        $Version = Get-FileVersion $BootMgr_File
        $Indent += $Tab4

        if ($ShowAsFile) {
            $BootMgr_File = $ShowAsFile
        }

        if ($SkipNewLine) {
            $NewLine = $null
        }
        else {
            $NewLine = "`n"
        }

        if ($Version -ne '0.0') {
            if ($BootMgrSVN -ne $null) {
                "{0}{1}`n{2}File Version: {3}, SVN {4}{5}" -f $Indent, $BootMgr_File, $Indent, $Version, $BootMgrSVN, $NewLine
            }
            else {
                "{0}{1}`n{2}File Version: {3}{4}" -f $Indent, $BootMgr_File, $Indent, $Version, $NewLine
            }
        }
        else {
            "{0}{1}`n{2}[THIRD-PARTY] EFI File{3}" -f $Indent, $BootMgr_File, $Indent, $NewLine
        }
    }
    else {
        if (-not $SkipNewLine) {
            Write-Output ''
        }
    }
}

function Validate-WinloadEFI_File
{
    param (
        [Parameter(Mandatory)]
        [string]$WinloadEFI_File
    )

    $Status = 'ALLOWED'

    if (-not $VBS_Enabled) {
        return $Status
    }

    $File = Get-Item $WinloadEFI_File
    $FileVersion = [version]$File.VersionInfo.FileVersionRaw

    foreach ($Rule in $FileRules) {
        if ($FileVersion -ge $Rule.MinimumFileVersion -and $FileVersion -le $Rule.MaximumFileVersion) {
            $Status = 'BANNED'

            return $Status
        }
    }

    return $Status
}

function Validate-BootStl {
    param (
        [Parameter(Mandatory)]
        [string]$BootStl_File
    )

    $EFI_BootStl_File = "$env:SystemRoot\Boot\EFI\boot.stl"

    if (-not (Test-Path $BootStl_File)) {
        '{0}{1} is MISSING.' -f $Tab8, $BootStl_File
    }
    else {
        $EFI_BootStl_File_Hash = (Get-FileHash $EFI_BootStl_File).Hash
        $BootStl_File_Hash = (Get-FileHash $BootStl_File).Hash

        try {
            $Update = ' [{0}]' -f ((& certutil -dump $BootStl_File | Select-String 'ThisUpdate') -replace ' ThisUpdate: ')
        }
        catch {
            $Update = $null
        }

        if (-not $Verbose) {
            $BootStl_File = 'boot.stl'
            $Update = $null
        }

        if ($EFI_BootStl_File_Hash -ne $BootStl_File_Hash) {
            '{0}{1}{2} is WRONG VERSION.' -f $Tab4, $BootStl_File, $Update
        }
        else {
            '{0}{1}{2} is CURRENT.' -f $Tab4, $BootStl_File, $Update
        }
    }
}

function Check-CacheFolders {
    try {
        $InstallDir = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Macrium\RescuePE' -Name 'InstallDir' -ErrorAction Stop
    }
    catch {
        $InstallDir = "$env:SystemDrive\boot"
    }

    $Macrium_WinRE_BootMgr_File = "$InstallDir\macrium\WinREFiles\media\EFI\Microsoft\Boot\bootmgfw.efi"
    $Macrium_WinPE_BootFile = "$InstallDir\macrium\\WA11KFiles\media\EFI\Boot\bootx64.efi"

    if ((Test-Path $Macrium_WinRE_BootMgr_File) -or (Test-Path $Macrium_WinPE_BootFile)) {
        try {
            $Version = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | where { $_.DisplayName -match 'Macrium Reflect' } | select -First 1).DisplayVersion
            Print-Header "Macrium $Version"
        }
        catch {
            Print-Header 'Macrium Folders'
        }
    }

    if (Test-Path $Macrium_WinRE_BootMgr_File) {
        if ($Verbose -and (Test-Path $Macrium_WinPE_BootFile)) {
            Validate-BootMgrFile -BootMgr_File $Macrium_WinRE_BootMgr_File -Label 'WinRE Boot Manager' -Indent $Tab4
        }
        else {
            Validate-BootMgrFile -BootMgr_File $Macrium_WinRE_BootMgr_File -Label 'WinRE Boot Manager' -Indent $Tab4 -SkipNewLine
        }
    }

    if (Test-Path $Macrium_WinPE_BootFile) {
        Validate-BootMgrFile -BootMgr_File $Macrium_WinPE_BootFile -Label 'WinPE Boot File' -Indent $Tab4 -SkipNewLine
    }

    try {
        $DisplayVersion = [Version](Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | where { $_.DisplayName -match 'Hasleo Backup Suite' }).DisplayVersion
        $Version = $DisplayVersion
    }
    catch {
        $Version = '0.0.0.0'
    }

    if ([version]$Version -lt [Version]'5.8.2.2') {
        $Hasleo_StagedBootMgr_File = "$env:ProgramFiles\Hasleo\Hasleo Backup Suite\bin\WADK\Boot\EFI_EX\bootmgfw.efi"

        if (Test-Path $Hasleo_StagedBootMgr_File) {
            Print-Header "Hasleo $DisplayVersion"
            Validate-BootMgrFile -BootMgr_File $Hasleo_StagedBootMgr_File -Label 'WinPE Boot Manager' -Indent $Tab4 -SkipNewLine
        }
    }
}

function Check-WIM_File {
    param (
        [Parameter(Mandatory)]
        [string]$WIM_File,

        [Parameter(Mandatory)]
        [int]$Index,

        [Parameter(Mandatory=$false)]
        [switch]$ShowPath
    )

    $Extract_Files = '/Windows/Boot/EFI/bootmgfw.efi /Windows/Boot/EFI_EX/bootmgfw_EX.efi /Windows/System32/config/SOFTWARE /Windows/System32/winload.efi'

    if ($WIM_file -match '.swm$') {
        $SWM_Path = Split-Path $WIM_File
        $Temp_WIM = "$TEMP_DIR\install.wim"

        "{0}Please wait while install SWM is analyzed.`n" -f $Tab4

        try {
            $null = Export-WindowsImage -SourceImagePath $WIM_File -SplitImageFilePattern "$SWM_Path\install*.swm" -SourceIndex 1 -DestinationImagePath $Temp_WIM
        }
        catch {
            $_.Exception.Message
            exit 1
        }

        Start-Sleep 2

        $Extract_Files = $Extract_Files -replace '/Windows','Windows' -replace '/','\'
        Start-Process $7z_exe -ArgumentList "e $Temp_WIM -aoa $Extract_Files -o`"$TEMP_DIR`"" -RedirectStandardOut NUL -RedirectStandardError '\\.\NUL' -NoNewWindow -Wait
        Remove-Item $Temp_WIM -Force
    }
    else {
        $ArgumentList = "extract $WIM_File $Index $Extract_Files --quiet --nullglob --no-acls --dest-dir=`"$env:TEMP`""
    }

    try {
        Start-Process $wimlib_imagex -ArgumentList $ArgumentList -NoNewWindow -RedirectStandardOut NUL -RedirectStandardError '\\.\NUL' -Wait

        if ($WIM_File -match 'boot.wim') {
            if ((& $wimlib_imagex dir $WIM_File $Index -path=/Windows/System32) -match 'MXEAgent.dll') {
                $WIM_Type = 'WinRE'
            }
            else {
                $WIM_Type = 'WinPE'
            }
        }
    }
    catch {
        "ERROR: wimlib unable to open $WIM_File"
        return
    }

    $Hive = "$env:TEMP\SOFTWARE"
    $CurrentVersion = & $offlinereg $Hive 'Microsoft\Windows NT\CurrentVersion' enumallvalues

    $Build = [int](($CurrentVersion | Select-String '"CurrentBuild"') -split '"')[3]
    $UBR = (($CurrentVersion | Select-String 'UBR') -split ':')[-1]
    $DisplayVersion = (($CurrentVersion | Select-String '"DisplayVersion"') -split '"')[3]

    switch ($Build) {
        { $_ -ge 19041 -and $_ -le 19045 } {
            $Release = "W10 $DisplayVersion"
        }

        { $_ -ge 22000 } {
            $Release = "W11 $DisplayVersion"
        }

        default {
            $Release = "Windows $DisplayVersion"
        }
    }

    $Temp_BootMgrEX_File = "$env:TEMP\bootmgfw_EX.efi"
    $Temp_BootMgr_File = "$env:TEMP\bootmgfw.efi"

    if ($ShowPath) {
        $Filename = $WIM_File
    }
    else {
        $Filename = Split-Path $WIM_File -Leaf
    }

    if ($WIM_Type -match 'Win') {
        '{0}{1}:{2} ({3} {4}.{5}) ' -f $Tab4, $Filename, $Index, $WIM_Type, $Build, $UBR
    }
    else {
        '{0}{1}:{2} ({3} {4}.{5}) ' -f $Tab4, $Filename, $Index, $Release, $Build, $UBR
    }

    if (Test-Path $Temp_BootMgrEX_File) {
        Validate-BootMgrFile -BootMgr_File $Temp_BootMgrEX_File -Label 'Boot Manager' -ShowAsFile '\Windows\Boot\EFI_EX\bootmgfw_EX.efi' -Indent $Tab8 -SkipNewLine
    }
    elseif (Test-Path $Temp_BootMgr_File) {
        Validate-BootMgrFile -BootMgr_File $Temp_BootMgr_File -Label 'Boot Manager' -ShowAsFile '\Windows\Boot\EFI\bootmgfw.efi' -Indent $Tab8 -SkipNewLine
    }
    else {
        '{0}ERROR: No boot manager found in WIM.' -f $Tab8
    }

    $WinloadEFI_File = "$env:TEMP\winload.efi"

    if (Test-Path $WinloadEFI_File) {
        $File = Get-Item $WinloadEFI_File
        $FileVersion = [version]$File.VersionInfo.FileVersionRaw

        $Status = Validate-WinloadEFI_File $WinloadEFI_File

        if ($Verbose) {
            "`n{0}\Windows\System32\winload.efi {1} {2}.`n{3}File Version: {4}" -f $Tab8, $VBS_Verb, $Status, $Tab12, $FileVersion
        }
        else {
            "{0}winload.efi {1} {2}.`n" -f $Tab8, $VBS_Verb, $Status
        }
    }
    else {
        "ERROR: $WinloadEFI_File not found."
    }

    foreach ($File in @($Hive, $Temp_BootMgrEX_File, $Temp_BootMgr_File, $WinloadEFI_File)) {
        Remove-Item $File -Force -ErrorAction SilentlyContinue
    }
}

function Check-DriveVolume {
    param (
        [Parameter(Mandatory)]
        [ref]$Volume,

        [Parameter(Mandatory=$false)]
        [switch]$ShowPath
    )

    $DriveLetter = $Volume.Value.DriveLetter + ':'

    $EFI_BootMgr_File = "$DriveLetter\EFI\Microsoft\Boot\bootmgfw.efi"
    $EFI_BootFile = "$DriveLetter\EFI\Boot\boot${Arch}.efi"

    $Boot_WIM = "$DriveLetter\sources\boot.wim"
    $WIM_Formats = @('wim','esd','swm')

    $Label = $Volume.Value.FileSystemLabel

    if ($ShowPath) {
        $ImagePath = (Get-Volume -DriveLetter $Volume.Value.DriveLetter | Get-DiskImage).ImagePath

        if ($Label -ne '') {
            "`n{0} `"{1}`"" -f $ImagePath, $Label
        }
        else {
            "`n{0}" -f $ImagePath
        }
    }
    else {
        if ($Volume.Value.DriveType -eq 'Removable') {
            $DriveType = 'USB'
        }
        else {
            $DriveType = 'DVD'
        }

        if ($Label -ne '') {
            "`n{0} Drive {1} `"{2}`"" -f $DriveType, $DriveLetter, $Label
        }
        else {
            "`n{0} Drive {1}" -f $DriveType, $DriveLetter
        }
    }

    if (Test-Path $EFI_BootMgr_File) {
        Validate-BootMgrFile -BootMgr_File $EFI_BootMgr_File -Label 'Windows Boot Manager' -Indent $Tab4
    }
    elseif (Test-Path $EFI_BootFile) {
        Validate-BootMgrFile -BootMgr_File $EFI_BootFile -Label 'Boot File' -Indent $Tab4
    }

    if (Test-Path $Boot_WIM) {
        try {
            $Index = (Get-WindowsImage -ImagePath $Boot_WIM -Name *Setup*).ImageIndex
        }
        catch {
            try {
                $Index = (Get-WindowsImage -ImagePath $Boot_WIM -Name *Recovery*).ImageIndex
            }
            catch {
                $ErrorMessage = $_.Exception.Message

                if ($ErrorMessage -notmatch 'There is no matching image.') {
                    $ErrorMessage
                    continue
                }

                $Index = (Get-WindowsImage -ImagePath $Boot_WIM).Count
            }
        }

        Check-WIM_File -WIM_File $Boot_WIM -Index $Index
        if ($Verbose) { '' }
    }

    $LineBreak = $true

    foreach ($Format in $WIM_Formats) {
        $ImageFile = "$DriveLetter\sources\install.$Format"

        if (Test-Path $ImageFile) {
            $ImageCount = (Get-WindowsImage -ImagePath $ImageFile).Count

            if ($NoSkip) {
                $Count = $ImageCount
            }
            else {
                $Count = 1
            }

            try {
                for ($i = 1; $i -le $Count; $i++) {
                    Check-WIM_File -WIM_File $ImageFile -Index $i
                }
            }
            catch {
                $ErrorMessage = $_.Exception.Message

                if ($ErrorMessage -ne 'There is no matching image.') {
                    $ErrorMessage
                }
            }

            if ($ImageCount -gt 1 -and -not $NoSkip) {
                if ($Verbose) {
                    "`n{0}Skipping over the next {1} images." -f $Tab8, --$ImageCount
                }
                else {
                    '{0}Skipping over the next {1} images.' -f $Tab8, --$ImageCount
                }
            }

            Write-Output ''
            $LineBreak = $false
        }
    }

    if ($DriveType -eq 'USB') {
        Validate-BootStl "$DriveLetter\EFI\Microsoft\Boot\boot.stl"
    }

    if ($LineBreak) {
        Write-Output ''
    }
}

$ScriptBlock = {
    if (-not (Test-Path $wimlib_imagex) -or -not (Test-Path $offlinereg)) {
        Install-Tools
    }

    $CurrentVersion = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion'

    if ($Verbose) {
        $CurrentBuild = $CurrentVersion.CurrentBuildNumber
        "Windows {0} {1} ({2}.{3})`n" -f $(if ($CurrentBuild -lt 22000) { '10' } else { '11' }), $CurrentVersion.DisplayVersion, $CurrentBuild, $CurrentVersion.UBR
    }

    $Result = Confirm-MinimumUBR

    if ($Result -ne $true) {
        $Result
    }

    try {
        $SecureBoot = Confirm-SecureBootUEFI
        $SecureBoot_Verb = 'is'
    }
    catch {
        "ERROR: BIOS running in Legacy CSM mode.  Please enable UEFI mode.`n"
        exit 1
    }

    if ($SecureBoot) {
        'Secure Boot: ON'
    }
    else {
        if ($Audit) {
            'Secure Boot: OFF (Audit Report runs as ON)'
            $SecureBoot = $true
            $SecureBoot_Verb = 'will be'
        }
        else {
            'Secure Boot: OFF'
        }
    }

    $VBS_Status = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus
    $VBS_Verb = 'is'

    if ($VBS_Status -gt 0) {
        'Virtualization Based Security: ON'
        $VBS_Enabled = $true
    }
    else {
        if ($Audit) {
            'Virtualization Based Security: OFF (Audit Report runs as ON)'
            $VBS_Enabled = $true
            $VBS_Verb = 'will be'
        }
        else {
            'Virtualization Based Security: OFF'
        }
    }

    if (Get-UEFI_DeviceGuard) {
        'DeviceGuard (UEFI): ON'
    }

    $EFI_Device = & bcdedit /enum '{bootmgr}' | Select-String 'device'
    try {
        $KEK_Certs = Get-UEFICert KEK
        $db_Certs = Get-UEFICert db
        $dbx_Certs = Get-UEFICert dbx
    }
    catch {
        Write-Host 'ERROR: Failed to read UEFI Secure Boot settings.' -ForegroundColor Red
        $_.Exception.Message
        exit 1
    }

    $Model = '{0} {1}' -f ($System.Manufacturer -split ',')[0], $System.Model

    foreach ($Variable in 'PK','KEK','db','dbx') {
        try {
            $Count = (Get-SecureBootUEFI $Variable).Bytes.Count
        }
        catch {
            if ($_.Exception.Message -match '0xC0000100') {
                $Count = 0
            }
            else {
                throw $_.Exception.Message
            }
        }

        New-Variable -Name "${Variable}_BytesCount" -Value $Count
    }

    Print-UEFICerts -Name 'KEK' -CertArray ([ref]$KEK_Certs)
    Print-UEFICerts -Name 'DB' -CertArray ([ref]$db_Certs)
    Print-UEFICerts -Name 'DBX' -CertArray ([ref]$dbx_Certs)

    $UEFI_SVN = Get-SecureBootUEFI_SVN $EFI_BOOTMGR_SVN_GUID

    if ($UEFI_SVN) {
        '{0}Windows BootMgr SVN {1}' -f $Tab4, $UEFI_SVN
    }
    elseif ($Verbose) {
        '{0}Windows BootMgr SVN is MISSING.' -f $Tab4
    }

    $EFI_Device = & bcdedit /enum '{bootmgr}' | Select-String 'device'

    switch -Regex (, $EFI_Device) {
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

    $BootMgrEX_File = "$env:SystemRoot\Boot\EFI_EX\bootmgfw_EX.efi"
    $SkuSiPolicy_File = "$UpdatesFolder\SkuSiPolicy.p7b"

    $BootMgr_File = "$EFI_Path\Microsoft\Boot\bootmgfw.efi"
    $EFI_SkuSiPolicy_File = "$EFI_Path\Microsoft\Boot\SkuSiPolicy.p7b"

    $PFXCert = Get-PFXCert $BootMgr_File
    $BootMgrSVN = Get-BootManagerSVN $BootMgr_File

    if ($VBS_Enabled) {
        Print-Header 'EFI Files'

        if ((Test-Path -LiteralPath $EFI_SkuSiPolicy_File)) {
            $SkuSiPolicyFile_Hash = (Get-FileHash $SkuSiPolicy_File).Hash
            $EFI_SkuSiPolicyFile_Hash = (Get-FileHash -LiteralPath $EFI_SkuSiPolicy_File).Hash

            $EFI_SkuSiPolicyVersion = [string](Get-SkuSiPolicyVersion $EFI_SkuSiPolicy_File)

            if ($EFI_SkuSiPolicyFile_Hash -eq $SkuSiPolicyFile_Hash) {
                if ($Verbose) {
                    '{0}SkuSiPolicy.p7b is CURRENT.' -f $Tab4
                    "{0}{1}`n{2}Version: {3}" -f $Tab8, $EFI_SkuSiPolicy_File, $Tab8, $EFI_SkuSiPolicyVersion
                }
                else {
                    '{0}SkuSiPolicy.p7b is CURRENT.' -f $Tab4
                }
            }
            else {
                if ($Verbose) {
                    '{0}SkuSiPolicy.p7b Version: {1} is WRONG VERSION.' -f $Tab4, $EFI_SkuSiPolicyVersion
                    "{0}{1}`n{2}Version: {3}" -f $Tab8, $EFI_SkuSiPolicy_File, $Tab8, $EFI_SkuSiPolicyVersion
                }
                else {
                }
                    '{0}SkuSiPolicy.p7b is WRONG VERSION.' -f $Tab4
            }

            try {
                $XML = ConvertTo-SkuSiPolicy -BinaryFilePath $EFI_SkuSiPolicy_File

                $FileRules = @($XML.FileRules | where { $_.FileName -eq 'osloader.exe' } | foreach {
                    [PSCustomObject]@{
                        FileRule = $_.ID
                        MinimumFileVersion = [version]$(if ($_.MinimumFileVersion -eq $null) { '0.0.0.0' } else { $_.MinimumFileVersion })
                        MaximumFileVersion = [version]$_.MaximumFileVersion
                    }
                }) | sort MinimumFileVersion

                if ($Verbose) {
                    ($FileRules | Out-String) -replace "`r`n$" -split "`r`n" | foreach { '{0}{1}' -f $Tab4, $_ }
                }
            }
            catch {
                "ERROR: ConvertTo-SkuSiPolicy $EFI_SkuSiPolicy_File"
            }
        }
        else {
            '{0}[OPTIONAL] SkuSiPolicy.p7b (for VBS) is MISSING.' -f $Tab4
        }

        if ([Environment]::Is64BitProcess) {
            if ((& bcdedit | Select-String 'winload.efi').Count -gt 1) {
                '{0}NOT RECOMMENDED for dual-boot setups.' -f $Tab4
            }
        }
        else {
            if ((& "$env:SystemRoot\SysNative\bcdedit" | Select-String 'winload.efi').Count -gt 1) {
                '{0}NOT RECOMMENDED for dual-boot setups.' -f $Tab4
            }
        }
    }

    Check-CacheFolders

    $RemovableDrives = Get-Volume | where { $_.DriveType -in 'CD-ROM','Removable' -and $_.DriveLetter -ne $null -and $_.OperationalStatus -eq 'OK' } | sort DriveLetter

    if ($RemovableDrives.Count) {
        Print-Header 'Bootable Media'

        foreach ($Volume in $RemovableDrives) {
            Check-DriveVolume -Volume ([ref]$Volume)
        }
    }
}

if ($Log) {
    $LogFile = '{0}\{1} {2} Check-UEFI.log' -f $PSScriptRoot, (Get-Date -Format 'yyyy-MM-dd'), ($System.Model.ToUpper().Split([IO.Path]::GetInvalidFileNameChars()) -join '_')

    & $ScriptBlock | Tee-Object $LogFile
    "`nLog file saved as `"{0}`"`n" -f $LogFile
}
else {
    & $ScriptBlock
    Write-Output ''
}

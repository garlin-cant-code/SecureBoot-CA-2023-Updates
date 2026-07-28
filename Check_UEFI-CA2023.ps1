<#PSScriptInfo

.VERSION 2026.07.28

.GUID 240507af-7454-491f-8e42-acb2a40ae3ef

.AUTHOR garlin

.COPYRIGHT

.TAGS UEFI, Secure Boot, CA 2023, PK, KEK, DB, DBX, SVN, Windows Boot Manager

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
    Identify extra details including the Windows build version, BIOS version details, UEFI Platform Key, and Factory Defaults for PK, KEK, DB and DBX variables.
    Download "kek_update_map.json" from Microsoft's Secure Boot Objects GitHub, and check if vendor signed KEK CA 2023 update is available.
    Windows Boot Manager SVN will be reported, if present in DBX.

.PARAMETER Audit
    Perform an audit report of the UEFI variables and Windows Boot Manager version.  Identify any missing UEFI certs, and validate if current boot file is
    allowed by enabling Secure Boot mode.

    Identify all required actions to bring system into compliance for upcoming Windows CA 2023 changes.

    If Secure Boot is currently disabled, audit report will simulate conditions where Secure Boot is enabled.

.PARAMETER BootMedia
    Search all mounted removable media (DVD & USB drives), for Windows boot files and install images.  Validate if boot file and install image are allowed by
    current Secure Boot settings.

.PARAMETER NoSkip
    When checking Windows install files on removable media, examine every image in the install WIM/ESD file.
    By default, -BootMedia parameter stops checking after the first image in the install file to improve script reporting time.

.PARAMETER Log
    Save script output to a file named "YYYY-MM-DD [Model] Check UEFI.log"

.EXAMPLE
    Check_UEFI-CA2023.ps1
.EXAMPLE
    Check_UEFI-CA2023.ps1 -Audit
.EXAMPLE
    Check_UEFI-CA2023.ps1 -Verbose -Audit -BootMedia -Log
#>

[CmdletBinding(DefaultParameterSetName='Default')]
param (
    [Parameter(Mandatory=$false,ParameterSetName='Version')]
    [switch]$Version,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Audit,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$BootMedia,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$NoSkip,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Log,

    [Parameter(Mandatory=$false,ParameterSetName='Default',DontShow,ValueFromRemainingArguments=$true)]
    [string[]]$ignored
)

$ScriptVersion = '2026.07.28'

# https://github.com/microsoft/secureboot_objects/blob/main/Archived/dbx_info_msft_4_09_24_svns.csv
$EFI_BOOTMGR_SVN_GUID = '01612B139DD5598843AB1C185C3CB2EB92'
$EFI_CDBOOT_SVN_GUID =  '019D2EF8E827E15841A4884C18ABE2F284'
$EFI_WDSMGR_SVN_GUID =  '01C2CA99C9FE7F6F4981279E2A8A535976'

$VMWARE_GUID = 'a3d5e95b-0a8f-4753-8735-445afb708f62'

$CN_Regex = '(CN=)([^,]+)'

$Tab4 = ' ' * 4
$Tab8 = ' ' * 8
$Tab12 = ' ' * 12

$KEKUpdateMap_URL = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/KEK/kek_update_map.json'

if ([Environment]::Is64BitProcess) {
    $UpdatesFolder = "$env:SystemRoot\System32\SecureBootUpdates"
}
else {
    $UpdatesFolder = "$env:SystemRoot\SysNative\SecureBootUpdates"
}

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

function Print-UEFICerts {
    param (
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ref]$CertArray
    )

    if ($Name -match 'Default') {
        $Header = '{0} Cert{1}' -f ($Name -replace 'Default','Factory Default UEFI'), $(if ($Name -notmatch 'PK') { 's' })
    }
    else {
        $Header = 'UEFI {0} Cert{1}' -f $Name, $(if ($Name -notmatch 'PK') { 's' })
    }

    Print-Header $Header

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

    if ($PKSignatureList -eq $null) {
        return $null
    }

    if ($PKSignatureList.SignatureData.Subject -match 'DO NOT |Example') {
        return $true
    }
    else {
        return $false
    }
}

function Check-KEKUpdateMap {
    try {
        $JSON = (Invoke-WebRequest -UseBasicParsing -Uri $KEKUpdateMap_URL).Content | ConvertFrom-Json
    }
    catch {
        return (($_.Exception.Message -split "`n") | select -First 1)
    }

    try {
        $PK_Thumbprint = (Get-UefiDatabaseSignatures -BytesIn (Get-SecureBootUEFI PK).Bytes).SignatureList.SignatureData.Thumbprint
    }
    catch {
        if ($_.Exception.Message -match '0xC0000100') {
            return $null
        }
        else {
            throw $_.Exception.Message
        }
    }

    if ($JSON.$PK_Thumbprint.KEKUpdate -ne $null) {
        $script:SignedKEK = $true
        return $JSON.$PK_Thumbprint.KEKUpdate
    }
    else {
        return $null
    }
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

function Get-UEFI_CredentialGuard {
    $LastBootUpTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $Events = Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-Wininit'; Id=12; StartTime=$LastBootUpTime} -ErrorAction SilentlyContinue | where { $_.Message -match 'LSASS.exe was started as a protected process with level: 4.' }

    if ($Events.Count) {
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

function Audit-UEFI {
    $CheckList = $null
    $index = 1
    $script:UpdateFlags = $script:RevokeFlags = 0

    $Result = Confirm-MinimumUBR

    if ($Result -ne $true) {
        $CheckList += "{0,-3} {1}`n" -f ('{0}.' -f $index++), $Result
        $NotMinimumUBR = $true
    }

    if (-not $SetupMode -and -not (Confirm-SecureBootUEFI)) {
        $CheckList += "{0,-3} Secure Boot is DISABLED`n" -f ('{0}.' -f $index++)
    }

    if ($SetupMode) {
        $CheckList += "{0,-3} UEFI is in Setup Mode`n" -f ('{0}.' -f $index++)

        if ($WindowsHello) {
            $CheckList += "{0,-3} Windows Hello must be disabled when in UEFI Setup Mode`n" -f ('{0}.' -f $index++)
        }
    }

    if ($PK_Untrusted) {
        $CheckList += "{0,-3} [{1}] is UNTRUSTED`n" -f ('{0}.' -f $index++), $PK_Cert
    }

    # https://support.microsoft.com/en-us/topic/secure-boot-certificate-updates-guidance-for-it-professionals-and-organizations-e2b43f9f-b424-42df-bc6a-8476db65ab2f#bkmk_troubleshooting

    if ('Microsoft Corporation KEK 2K CA 2023' -notin $KEK_Certs) {
        $CheckList += "{0,-3} [Microsoft Corporation KEK 2K CA 2023] is missing from UEFI KEK`n" -f ('{0}.' -f $index++)
        $script:UpdateFlags = $script:UpdateFlags -bor 0x4
    }

    if ('Windows UEFI CA 2023' -notin $db_Certs) {
        $CheckList += "{0,-3} [Windows UEFI CA 2023] is missing from UEFI DB`n" -f ('{0}.' -f $index++)
        $script:UpdateFlags = $script:UpdateFlags -bor 0x40
    }

    if ('Microsoft UEFI CA 2023' -notin $db_Certs) {
        $CheckList += "{0,-3} [Microsoft UEFI CA 2023] is missing from UEFI DB`n" -f ('{0}.' -f $index++)
        $script:UpdateFlags = $script:UpdateFlags -bor 0x4000 -bor 0x1000
    }

    if ('Microsoft Option ROM UEFI CA 2023' -notin $db_Certs) {
        $CheckList += "{0,-3} [Microsoft Option ROM UEFI CA 2023] is missing from UEFI DB`n" -f ('{0}.' -f $index++)
        $script:UpdateFlags = $script:UpdateFlags -bor 0x4000 -bor 0x800
    }

    if ('Microsoft Windows Production PCA 2011' -notin $dbx_Certs) {
        $CheckList += "{0,-3} [Production PCA 2011] is missing from UEFI DBX`n" -f ('{0}.' -f $index++)
        $script:RevokeFlags = $script:RevokeFlags -bor 0x80
    }

    if (($dbx_BytesCount -eq 0) -or -not (Match-DBXSignatureData "$UpdatesFolder\dbxupdate.bin")) {
        $CheckList += "{0,-3} DBX Updates are missing from UEFI DBX`n" -f ('{0}.' -f $index++)
        $script:RevokeFlags = $script:RevokeFlags -bor 0x2
    }

    if ($UEFI_SVN -eq $null) {
        $CheckList += "{0,-3} Windows BootMgr SVN is missing from UEFI DBX`n" -f ('{0}.' -f $index++)
        $script:RevokeFlags = $script:RevokeFlags -bor 0x200
    }
    elseif ((Get-DBXUpdateSVN) -gt $UEFI_SVN) {
        $CheckList += "{0,-3} SecureBootUpdates SVN is higher than UEFI DBX`n" -f ('{0}.' -f $index++)
        $script:RevokeFlags = $script:RevokeFlags -bor 0x200
    }

    $BootMgrEX_File_Hash = (Get-FileHash $BootMgrEX_File).Hash
    $BootMgr_File_Hash = (Get-FileHash -LiteralPath $BootMgr_File).Hash

    if (($PFXCert -notmatch 'Windows UEFI CA 2023') -or ($BootMgrSVN -lt $UEFI_SVN) -or (($BootMgrSVN -eq $UEFI_SVN) -and ($BootMgr_File_Hash -ne $BootMgrEX_File_Hash))) {
        $CheckList += "{0,-3} Windows Boot Manager [{1}] is wrong version`n" -f ('{0}.' -f $index++), ($PFXCert -replace 'Microsoft Windows ')
        $script:UpdateFlags = $script:UpdateFlags -bor 0x100
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

function Run-FiniteStateMachine {
    if ($UpdateFlags -band 0x100) {
        $BootMgr_Required = $true
    }

    if ($UpdateFlags -band 0x4 -or $UpdateFlags -band 0x40 -or $UpdateFlags -band 0x800 -or $UpdateFlags -band 0x1000) {
        $CA2023_Required = $true
        $BootMgr_Required = $false
    }

    if ($CA2023_Required) {
        $script:UpdateMessage = 'To install [UEFI CA 2023] certs'
    }
    elseif ($BootMgr_Required) {
        if ((Get-DBXUpdateSVN) -gt $UEFI_SVN) {
            $script:UpdateMessage = 'To update Windows Boot Manager [UEFI CA 2023]'
        }
        else {
            $script:UpdateMessage = 'To install Windows Boot Manager [UEFI CA 2023]'
        }
    }

    if ($RevokeFlags -band 0x2) {
        $DBXUpdate_Required = $true
    }

    if ($RevokeFlags -band 0x200) {
        $SVN_Required = $true
    }

    if ($RevokeFlags -band 0x80) {
        $Revoke_PCA2011_Required = $true
        $DBXUpdate_Required = $false
        $SVN_Required = $false
    }

    if ($Revoke_PCA2011_Required) {
        if ($UpdateFlags) {
            $script:RevokeMessage = $script:UpdateMessage + ' and REVOKE the [PCA 2011] cert'
        }
        else {
            $script:RevokeMessage = 'To REVOKE the [PCA 2011] cert'
        }
    }
    elseif ($DBXUpdate_Required -and $SVN_Required) {
        if ($UpdateFlags) {
            $script:RevokeMessage = $script:UpdateMessage + ' and apply other DBX updates'
        }
        else {
            $script:RevokeMessage = 'To apply other DBX updates'
        }
    }
    elseif ($DBXUpdate_Required) {
        if ($UpdateFlags) {
            $script:RevokeMessage = $script:UpdateMessage + ' and update DBX signatures'
        }
        else {
            $script:RevokeMessage = 'To update DBXUpdate signatures'
        }
    }
    elseif ($SVN_Required) {
        if ($UpdateFlags) {
            $script:RevokeMessage = $script:UpdateMessage + ' and update the DBX SVN'
        }
        else {
            $script:RevokeMessage = 'To update the DBX SVN'
        }
    }
}

function Validate-BootMgrFile
{
    param (
        [Parameter(Mandatory)]
        [string]$BootMgr_File,

        [Parameter(Mandatory)]
        [string]$Label,

        [Parameter(Mandatory)]
        [string]$Indent,

        [Parameter(Mandatory=$false)]
        [switch]$SkipNewLine
    )

    $PFXCert = Get-PFXCert $BootMgr_File
    $BootMgrSVN = Get-BootManagerSVN $BootMgr_File

    switch -Regex (Validate-PFXCert $PFXCert) {
        'BANNED|UNTRUSTED' {
            '{0}{1} [{2}] {3} {4}.' -f $Indent, $Label, ($PFXCert -replace 'Microsoft Windows '), $Verb, $_
        }

        'ALLOWED' {
            if (-not $SecureBoot -or $BootMgrSVN -ge $UEFI_SVN) {
                '{0}{1} [{2}] {3} ALLOWED.' -f $Indent, $Label, ($PFXCert -replace 'Microsoft Windows '), $Verb
            }
            else {
                '{0}{1} [{2}] {3} BANNED.' -f $Indent, $Label, ($PFXCert -replace 'Microsoft Windows '), $Verb
            }
        }
    }

    if ($Verbose) {
        $Version = Get-FileVersion $BootMgr_File
        $Indent += $Tab4

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

function Check-BootStl {
    param (
        [Parameter(Mandatory)]
        [string]$BootStl_File
    )

    $EFI_BootStl_File = "$env:SystemRoot\Boot\EFI\boot.stl"

    if (-not (Test-Path $BootStl_File)) {
        "{0}{1} is MISSING.`n" -f $Tab8, $BootStl_File
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
            "{0}{1}{2} is WRONG VERSION.`n" -f $Tab8, $BootStl_File, $Update
        }
        else {
            "{0}{1}{2} is CURRENT.`n" -f $Tab8, $BootStl_File, $Update
        }
    }
}

function Check-WIM_BootManager {
    param (
        [Parameter(Mandatory)]
        [string]$WIM_File,

        [Parameter(Mandatory)]
        [int]$Index
    )

    $WIM_Image = '{0}:{1}' -f (Split-Path $WIM_File -Leaf), $Index

    if (((& dism /list-image /imagefile:$WIM_File /index:$Index) -match '\\bootmgfw_EX.efi').Count) {
        '{0}{1,-13} Boot Manager [Windows UEFI CA 2023] is PRESENT.' -f $Tab8, $WIM_Image
    }
    else {
        if ($SecureBoot -and $dbx_Certs -contains 'Microsoft Windows Production PCA 2011') {
            '{0}{1,-13} Boot Manager [Production PCA 2011] {2} BANNED.' -f $Tab8, $WIM_Image, $Verb
        }
        else {
            '{0}{1,-13} Boot Manager [Production PCA 2011] {2} ALLOWED.' -f $Tab8, $WIM_Image, $Verb
        }
    }
}

function Check-BootMedia {
    $RemovableDrives = Get-Volume | where { $_.DriveType -in 'CD-ROM','Removable' -and $_.DriveLetter -ne $null -and $_.OperationalStatus -eq 'OK' } | sort DriveLetter

    if ($RemovableDrives.Count -eq 0) {
        return
    }

    Print-Header 'Bootable Media'
    foreach ($Volume in $RemovableDrives) {
        $DriveLetter = $Volume.DriveLetter

        $EFI_BootMgr_File = "${DriveLetter}:\EFI\Microsoft\Boot\bootmgfw.efi"
        $EFI_BootFile = "${DriveLetter}:\EFI\Boot\boot${Arch}.efi"

        $Boot_WIM = "${DriveLetter}:\sources\boot.wim"
        $WIM_Formats = @('wim','esd','swm')

        if ($Volume.DriveType -eq 'Removable') {
            $DriveType = 'USB'
        }
        else {
            $DriveType = 'DVD'
        }

        $Label = $Volume.FileSystemLabel

        if ($Label -ne '') {
            '{0}{1} Drive {2}: "{3}"' -f $Tab4, $DriveType, $DriveLetter, $Label
        }
        else {
            '{0}{1} Drive {2}:' -f $Tab4, $DriveType, $DriveLetter
        }

        if (Test-Path $EFI_BootMgr_File) {
            Validate-BootMgrFile -BootMgr_File $EFI_BootMgr_File -Label 'Windows Boot Manager' -Indent $Tab8
        }
        elseif (Test-Path $EFI_BootFile) {
            Validate-BootMgrFile -BootMgr_File $EFI_BootFile -Label 'Boot File' -Indent $Tab8
        }

        if ($DriveType -eq 'USB') {
            Check-BootStl "${DriveLetter}:\EFI\Microsoft\Boot\boot.stl"
        }

        if (Test-Path $Boot_WIM) {
            try {
                $Index = (Get-WindowsImage -ImagePath $Boot_WIM -Name *Setup*).ImageIndex

                if ($Index -eq $null) {
                    $Index = (Get-WindowsImage -ImagePath $Boot_WIM).Count
                }

                Check-WIM_BootManager -WIM_File $Boot_WIM -Index $Index
            }
            catch {
                $ErrorMessage = $_.Exception.Message

                if ($ErrorMessage -ne 'There is no matching image.') {
                    $ErrorMessage
                }
            }
        }

        $LineBreak = $true

        foreach ($Format in $WIM_Formats) {
            $ImageFile = "${DriveLetter}:\sources\install.$Format"

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
                        Check-WIM_BootManager -WIM_File $ImageFile -Index $i
                    }
                }
                catch {
                    $ErrorMessage = $_.Exception.Message

                    if ($ErrorMessage -ne 'There is no matching image.') {
                        $ErrorMessage
                    }
                }

                if ($ImageCount -gt 1 -and -not $NoSkip) {
                    '{0}Skipping checks on next {1} install.{2} images.' -f $Tab12, --$ImageCount, $Format
                }

                Write-Output ''
                $LineBreak = $false
            }
        }

        if ($LineBreak) {
            Write-Output ''
        }
    }
}

$ScriptBlock = {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'amd64' { $Arch = 'x64' }
        'x86'   { $Arch = 'x86' }
        'arm64' { $Arch = 'aa64' }
        'arm'   { $Arch = 'aa32' }
    }

    $System = Get-CimInstance -ClassName Win32_ComputerSystem
    $BIOS = Get-CimInstance -ClassName Win32_BIOS

    $CurrentVersion = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion'

    $SystemDrive = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive

    # Force a refresh of reg key 'WindowsUEFICA2023Capable'
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"

    if ($Verbose) {
        $CurrentBuild = $CurrentVersion.CurrentBuildNumber
        "Windows {0} {1} ({2}.{3})`n" -f $(if ($CurrentBuild -lt 22000) { '10' } else { '11' }), $CurrentVersion.DisplayVersion, $CurrentBuild, $CurrentVersion.UBR
    }

    try {
        $SecureBoot = Confirm-SecureBootUEFI
        $Verb = 'is'
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
            $Verb = 'will be'
        }
        else {
            'Secure Boot: OFF'
        }
    }

    $VBS_Status = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus

    if ($VBS_Status -gt 0) {
        'Virtualization Based Security: ON'
        $VBS_Enabled = $true
    }
    else {
        'Virtualization Based Security: OFF'
    }

    try {
        $ProtectionStatus = ([string](Get-BitLockerVolume -MountPoint $SystemDrive).ProtectionStatus).ToUpper()
        $ManageBDECount = (Get-CimInstance -Namespace 'ROOT/CIMV2/Security/MicrosoftVolumeEncryption' -Class Win32_EncryptableVolume -Filter "DriveLetter=`"$SystemDrive`"" | Invoke-CimMethod -MethodName 'GetSuspendCount').SuspendCount

        if ($ManageBDECount) {
            "`nBitLocker on ({0}) {1}`n{2}SUSPENDED for {3} reboot{4}." -f $SystemDrive, $ProtectionStatus, $Tab4, $ManageBDECount, $(if ($ManageBDECount -gt 1) { 's' })
        }
        else {
            'BitLocker on ({0}) {1}' -f $SystemDrive, $ProtectionStatus

            if ($ProtectionStatus -eq 'On') {
                $BitLocker_Enabled = $true
            }
       }

    }
    catch {
        $_.Exception.Message
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
        $PKDefault_Cert = Get-UEFICert PKDefault
        $KEKDefault_Certs = Get-UEFICert KEKDefault
        $dbDefault_Certs = Get-UEFICert dbDefault
        $dbxDefault_Certs = Get-UEFICert dbxDefault

        $PK_Cert = Get-UEFICert PK
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
    $BIOS_Version = $BIOS.SMBIOSBIOSVersion

    if ($BIOS.ReleaseDate -ne $null) {
        $BIOS_Date = $BIOS.ReleaseDate.ToString('yyyy-MM-dd')
    }
    else {
        $BIOS_Date = $null
    }

    if ($KEK_Certs -notcontains 'Microsoft Corporation KEK 2K CA 2023' -and $dbx_Certs -notcontains 'Microsoft Windows Production PCA 2011') {
        # https://support.hp.com/ie-en/document/ish_13070353-13070429-16
        if ($BIOS_Version -match '^HP(?!\S)|Hewlett' -and $BIOS_Version -notmatch 'SBKPFV3') {
            $HP_NotSupported = $true
        }

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

    if ($Verbose -or $HP_NotSupported -or $Unsafe_Model) {
        Print-Header 'BIOS Firmware'
        '{0}{1}' -f $Tab4, $Model
        '{0}Version: {1}' -f $Tab4, $BIOS_Version
        '{0}Date: {1}' -f $Tab4, $BIOS_Date

        if ($HP_NotSupported) {
            "{0}This version of HP BIOS doesn't support automatic updates." -f $Tab8
        }
        elseif ($Unsafe_Model) {
            if ($ConfidenceLevel -match 'Temporarily Paused') {
                '{0}This BIOS may be corrupted by updating Secure Boot certs.' -f $Tab8
            }
            else {
                '{0}This BIOS could be damaged by updating Secure Boot certs.' -f $Tab8
            }
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
            else {
                throw $_.Exception.Message
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

    if ((($SetupMode_Bytes -join '') -eq 1) -or ($PK_BytesCount -eq 0 -and $KEK_BytesCount -eq 0 -and $db_BytesCount -eq 0 -and $dbx_BytesCount -eq 0)) {
        if (-not $Verbose) {
            "`nUEFI is in Setup Mode (NO CERTS)"
        }

        $SetupMode = $true
    }

    $PK_Untrusted = Check-UntrustedPK

    if ($Verbose) {
        Print-UEFICerts -Name 'Default PK' -CertArray ([ref]$PKDefault_Cert)
    }

    if ($Verbose -or $PK_Untrusted) {
        Print-UEFICerts -Name 'PK' -CertArray ([ref]$PK_Cert)

        if ($PK_Untrusted) {
            '{0}Platform Key is UNTRUSTED.' -f $Tab8
        }

        if ($PK_Cert -eq 'Microsoft Corporation KEK 2K CA 2023') {
            '{0}KEK CA 2023 is not a valid Platform Key' -f $Tab8
        }
    }

    $KEKUpdate = Check-KEKUpdateMap

    if ($Verbose -and 'Microsoft Corporation KEK 2K CA 2023' -notin $KEK_Certs) {
        switch ($KEKUpdate) {
            { $_ -match '\.bin' } {
                if ($Verbose) {
                    $Vendor = ($_ -split '/')[0]

                    if ($Vendor -ne 'Microsoft') {
                        '{0}[KEK CA 2023] Update is available from {1} or Microsoft.' -f $Tab8, $Vendor
                    }
                    else {
                        '{0}[KEK CA 2023] Update is available from Microsoft.' -f $Tab8
                    }
                }
            }

            $null {
                if (-not $SetupMode) {
                    '{0}Manual update of [KEK CA 2023] is REQUIRED.' -f $Tab8
                }
            }

            default {
                "`nERROR: Unable to parse Microsoft's KEK update map."
                Write-Host $_ -ForegroundColor Red
            }
        }
    }

    if ($Verbose) {
        Print-UEFICerts -Name 'Default KEK' -CertArray ([ref]$KEKDefault_Certs)
    }

    if (-not $SetupMode -or $Verbose) {
        Print-UEFICerts -Name 'KEK' -CertArray ([ref]$KEK_Certs)
    }

    if ($Verbose) {
        Print-UEFICerts -Name 'Default DB' -CertArray ([ref]$dbDefault_Certs)
    }

    if (-not $SetupMode -or $Verbose) {
        Print-UEFICerts -Name 'DB' -CertArray ([ref]$db_Certs)
    }

    if ($Verbose) {
        try {
            $Count = (Get-SecureBootUEFI dbxDefault | Get-UEFIDatabaseSignatures | where { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' }).SignatureList.Count
        }
        catch {
            if ($_.Exception.Message -match '0xC0000100') {
                $Count = 0
            }
            else {
                throw $_.Exception.Message
            }
        }

        Print-UEFICerts -Name 'Default DBX' -CertArray ([ref]$dbxDefault_Certs)
        '{0}EFI_CERT_SHA256_GUID Signatures: {1}' -f $Tab4, $Count
    }

    if (-not $SetupMode -or $Verbose) {
        Print-UEFICerts -Name 'DBX' -CertArray ([ref]$dbx_Certs)
    }

    $UEFI_SVN = Get-SecureBootUEFI_SVN $EFI_BOOTMGR_SVN_GUID

    if ($UEFI_SVN) {
        '{0}Windows BootMgr SVN {1}' -f $Tab4, $UEFI_SVN
    }
    elseif ($Verbose) {
        '{0}Windows BootMgr SVN is MISSING.' -f $Tab4
    }

    if ($Verbose) {
        if ($dbx_BytesCount -ne 0) {
            '{0}EFI_CERT_SHA256_GUID Signatures: {1}' -f $Tab4, (Get-SecureBootUEFI -Name dbx | Get-UEFIDatabaseSignatures | where { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' }).SignatureList.Count
        }
        else {
            '{0}EFI_CERT_SHA256_GUID Signatures: 0' -f $Tab4
        }
    }

    $UEFI_DeviceGuard = Get-UEFI_DeviceGuard
    $UEFI_CredentialGuard = Get-UEFI_CredentialGuard
    $SbatLevel = Get-SbatLevel

    if ($Verbose -and ($UEFI_DeviceGuard -or $UEFI_CredentialGuard -or ($SbatLevel -ne $null))) {
        Print-Header 'UEFI Variables'

        if ($UEFI_DeviceGuard) {
            '{0}DeviceGuard (VBS): ON' -f $Tab4
        }

        if ($UEFI_CredentialGuard) {
            '{0}Credential Guard: ON' -f $Tab4
        }

        if ($SbatLevel -ne $null) {
            '{0}SBAT (Linux only): {1}' -f $Tab4, ($SbatLevel -replace "`n",' / ')
        }
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

    Print-Header 'EFI Files'
    Validate-BootMgrFile -BootMgr_File $BootMgr_File -Label 'Windows Boot Manager' -Indent $Tab4

    try {
        $WindowsUEFICA2023Capable = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'WindowsUEFICA2023Capable'

        '{0}Registry: "WindowsUEFICA2023Capable" = {1}' -f $Tab4, $WindowsUEFICA2023Capable

        switch ($WindowsUEFICA2023Capable) {
            0  { '{0}[Windows UEFI CA 2023] not in UEFI DB.' -f $Tab8 }
            1  { '{0}[Windows UEFI CA 2023] in UEFI DB.' -f $Tab8 }
            2  { '{0}[Windows UEFI CA 2023] in UEFI DB, and Windows starting from CA 2023 Boot Manager.' -f $Tab8 }
            default { '{0}Unknown status.' -f $Tab8 }
        }
    }
    catch {
    }

    if ($VBS_Enabled) {
        if ((Test-Path -LiteralPath $EFI_SkuSiPolicy_File)) {
            $SkuSiPolicyFile_Hash = (Get-FileHash $SkuSiPolicy_File).Hash
            $EFI_SkuSiPolicyFile_Hash = (Get-FileHash -LiteralPath $EFI_SkuSiPolicy_File).Hash

            $EFI_SkuSiPolicyVersion = [string](Get-SkuSiPolicyVersion $EFI_SkuSiPolicy_File)

            if ($EFI_SkuSiPolicyFile_Hash -eq $SkuSiPolicyFile_Hash) {
                if ($Verbose) {
                    "`n{0}SkuSiPolicy.p7b is CURRENT." -f $Tab4
                    "{0}{1}`n{2}Version: {3}" -f $Tab8, $EFI_SkuSiPolicy_File, $Tab8, $EFI_SkuSiPolicyVersion
                }
                else {
                    "`n{0}SkuSiPolicy.p7b is CURRENT." -f $Tab4
                }
            }
            else {
                if ($Verbose) {
                    "`n{0}SkuSiPolicy.p7b Version: {1} is WRONG VERSION." -f $Tab4, $EFI_SkuSiPolicyVersion
                    "{0}{1}`n{2}Version: {3}" -f $Tab8, $EFI_SkuSiPolicy_File, $Tab8, $EFI_SkuSiPolicyVersion
                }
                else {
                }
                    "`n{0}SkuSiPolicy.p7b is WRONG VERSION." -f $Tab4
            }
        }
        else {
            "`n{0}[OPTIONAL] SkuSiPolicy.p7b (for VBS) is MISSING." -f $Tab4
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

    if ($BootMedia) {
        try {
            $InstallDir = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Macrium\RescuePE' -Name 'InstallDir' -ErrorAction Stop
        }
        catch {
            $InstallDir = "$env:SystemDrive\boot"
        }

        $Macrium_WinRE_BootMgr_File = "$InstallDir\macrium\WinREFiles\media\EFI\Microsoft\Boot\bootmgfw.efi"
        $Macrium_WinPE_BootFile = "$InstallDir\macrium\\WA11KFiles\media\EFI\Boot\bootx64.efi"

        if ((Test-Path $Macrium_WinRE_BootMgr_File) -or (Test-Path $Macrium_WinPE_BootFile)) {
            Print-Header 'Macrium Folders'
        }

        if (Test-Path $Macrium_WinRE_BootMgr_File) {
            if ($Verbose -and (Test-Path $Macrium_WinPE_BootFile)) {
                Validate-BootMgrFile -BootMgr_File $Macrium_WinRE_BootMgr_File -Label 'Windows Boot Manager' -Indent $Tab4
            }
            else {
                Validate-BootMgrFile -BootMgr_File $Macrium_WinRE_BootMgr_File -Label 'Windows Boot Manager' -Indent $Tab4 -SkipNewLine
            }
        }

        if (Test-Path $Macrium_WinPE_BootFile) {
            Validate-BootMgrFile -BootMgr_File $Macrium_WinPE_BootFile -Label 'Boot File' -Indent $Tab4 -SkipNewLine
        }

        try {
            $HasleoVersion = [Version](Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | where { $_.DisplayName -match 'Hasleo Backup Suite' }).DisplayVersion
        }
        catch {
            $HasleoVersion = [Version]'0.0.0.0'
        }

        if ($HasleoVersion -lt [Version]'5.8.2.2') {
            $Hasleo_StagedBootMgr_File = "$env:ProgramFiles\Hasleo\Hasleo Backup Suite\bin\WADK\Boot\EFI_EX\bootmgfw.efi"

            if (Test-Path $Hasleo_StagedBootMgr_File) {
                Print-Header 'Hasleo Folder'
                Validate-BootMgrFile -BootMgr_File $Hasleo_StagedBootMgr_File -Label 'Windows Boot Manager' -Indent $Tab4 -SkipNewLine
            }
        }

        Check-BootMedia
    }

    $CheckList = Audit-UEFI

    if ($Audit) {
        if (-not $BootMedia) { '' }
        Print-Header -Bold 'AUDIT REPORT'

        if ($CheckList -ne $null) {
            $CheckList.TrimEnd("`n")
        }
        else {
            '{0}PASSED ALL CHECKS.' -f $Tab4
        }
    }

    if ($Unsafe_Model -and ($UpdateFlags -band 0x4)) {
        if (-not $BootMedia) { '' }
        Print-Header 'STATUS REPORT'

        try {
            $UEFICA2023Status = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'UEFICA2023Status'
            '{0}Registry: "UEFICA2023Status" = {1}' -f $Tab4, $UEFICA2023Status
        }
        catch {
        }

        if ($ConfidenceLevel) {
            '{0}Registry: "ConfidenceLevel" = {1}' -f $Tab4, $ConfidenceLevel
        }

        switch ($ConfidenceLevel) {
            'Temporarily Paused' {
                "`n{0}This device is affected by a known issue. This may require a firmware update." -f $Tab4
            }
            'Not Supported' {
                "`n{0}This device may have a hardware or firmware limitation blocking updates." -f $Tab4
                '{0}Please do not attempt to manually enroll Secure Boot keys.' -f $Tab4
            }
        }
    }
    elseif ($UpdateFlags -or $RevokeFlags -or $UpdateSkuSiPolicy) {
        if ($BitLocker_Enabled -and $UpdateFlags -ne 0x100) {
            $DeviceGuard_Running = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning

            if ($DeviceGuard_Running -eq 1) {
                $ManageBDE = "manage-bde -Protectors -Disable $SystemDrive -RebootCount 3"
            }
            else {
                $ManageBDE = "manage-bde -Protectors -Disable $SystemDrive -RebootCount 1"
            }
        }

        Run-FiniteStateMachine

        if (-not $BootMedia) { '' }
        Print-Header -Bold 'REQUIRED ACTION'

        if (('Microsoft Corporation KEK 2K CA 2023' -notin $KEK_Certs) -and ('Windows UEFI CA 2023' -in $db_Certs)) {
            "`nRun the command:`n{0}Update_UEFI-CA2023.ps1{1}`n" -f $Tab4, $(if ($RevokeFlags) { ' -Revoke' })

            if ($PK_Untrusted) {
                "Finish the UEFI steps to manually add the Platform Key (PK) cert, if the script provided instructions.`n"
            }

            "Finish the UEFI steps to manually add the [KEK CA 2023] cert, if the script provided instructions.`n"
            break
        }

        if (-not $PK_Untrusted -and (('Microsoft Corporation KEK 2K CA 2023' -in $KEK_Certs) -or $SignedKEK)) {
            $MergedFlags = $UpdateFlags -bor $RevokeFlags

            if ($UpdateFlags -and $RevokeFlags) {
                "`nOPTION 1:  DO NOTHING AND WAIT.  Windows will apply the UEFI updates (PC has supported BIOS)."

                if ($RevokeFlags -band 0x80) {
                    "`nOPTION 2:  {0} WITHOUT REVOKING the [PCA 2011] cert, run the commands:`n" -f $UpdateMessage
                }
                else {
                    "`nOPTION 2:  {0}, run the commands:`n" -f $UpdateMessage
                }

                if ($ManageBDE -ne $null) { '{0}{1}' -f $Tab4, $ManageBDE }

                '{0}reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x{1:x} /f' -f $Tab4, $UpdateFlags
                '{0}powershell Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"' -f $Tab4

                "`n`nOPTION 3:  {0}, run the commands:`n" -f $RevokeMessage

                if ($ManageBDE -ne $null) { '{0}{1}' -f $Tab4, $ManageBDE }

                if ($UpdateFlags) {
                    '{0}reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x{1:x} /f' -f $Tab4, $MergedFlags
                }
                else {
                    '{0}reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x{1:x} /f' -f $Tab4, $RevokeFlags
                }

                '{0}powershell Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"' -f $Tab4
            }
            elseif ($UpdateFlags) {
                "{0}, run the commands:`n" -f $UpdateMessage

                if ($ManageBDE -ne $null) { '{0}{1}' -f $Tab4, $ManageBDE }

                '{0}reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x{1:x} /f' -f $Tab4, $UpdateFlags
                '{0}powershell Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"' -f $Tab4
            }
            elseif ($RevokeFlags) {
                "{0}, run the commands:`n" -f $RevokeMessage

                if ($ManageBDE -ne $null) { '{0}{1}' -f $Tab4, $ManageBDE }

                '{0}reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x{1:x} /f' -f $Tab4, $RevokeFlags
                '{0}powershell Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"' -f $Tab4
            }

            if ($UpdateSkuSiPolicy) {
                "`n[OPTIONAL] To update SkuSiPolicy.p7b, run the command:"
                '{0}Update_UEFI-CA2023.ps1 -SkuSiPolicy' -f $Tab4
            }
        }
        else {
            if (-not $SetupMode) {
                "`nMANUAL UPDATE of the BIOS is required.`n"

                "Enter the BIOS menu, and search for User or Custom Mode option of updating the UEFI PK or KEK keys."
                "If your BIOS doesn't support this feature, select Setup Mode to clear all certs."

                if ($WindowsHello) {
                    "`nIMPORTANT: Disable Windows Hello PIN before clearing certs."
                }
            }

            "`nOPTION 1:  {0}`n" -f $UpdateMessage
            '{0}Update_UEFI-CA2023.ps1' -f $Tab8

            "`n`nOPTION 2:  {0}`n" -f $RevokeMessage
            '{0}Update_UEFI-CA2023.ps1 -Revoke' -f $Tab8
        }
    }
    else {
        if (-not $BootMedia) { '' }
        Print-Header 'STATUS REPORT'

        try {
            $UEFICA2023Status = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'UEFICA2023Status'
            "{0}Registry: `"UEFICA2023Status`" = {1}`n" -f $Tab4, $UEFICA2023Status
        }
        catch {
        }

        "{0}SUCCESS: UPDATES ARE FINISHED.`n{1}UEFI CA 2023 certs are present, PCA 2011 cert is revoked." -f $Tab4, $Tab4
    }
}

if ($Log) {
    $System = Get-CimInstance -ClassName Win32_ComputerSystem
    $LogFile = '{0}\{1} {2} Check-UEFI.log' -f $PSScriptRoot, (Get-Date -Format 'yyyy-MM-dd'), ($System.Model.ToUpper().Split([IO.Path]::GetInvalidFileNameChars()) -join '_')

    & $ScriptBlock | Tee-Object $LogFile
    "`nLog file saved as `"{0}`"`n" -f $LogFile
}
else {
    & $ScriptBlock
    Write-Output ''
}

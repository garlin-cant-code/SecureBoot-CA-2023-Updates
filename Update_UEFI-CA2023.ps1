<#PSScriptInfo

.VERSION 2026.01.18

.GUID 7c7848ed-3952-4726-8f23-8644881c2c91

.AUTHOR garlin, ungentilgarcon (@garlin-cant-code) (@ungentilgarcon)

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
    Perform an audit report of the UEFI variables and Windows Boot Manager version.  Identify any missing UEFI certs, and validate if current boot files are
    allowed by enabling Secure Boot mode.

    Identify all required actions to bring system into compliance for upcoming CA 2023 changes.

    If Secure Boot is currently disabled, audit report will simulate conditions where Secure Boot is enabled

.PARAMETER Revoke
    Revoke [Microsoft Windows Production PCA 2011] certificate by adding the cert to the UEFI DBX.
    To allow dual-booting of [Production PCA 2011] & [UEFI CA 2023] media, do not use the -Revoke option.

.PARAMETER Latest
    Download latest version of DBXUpdate.bin and DBXUpdateSVN.bin, from Microsoft's Secure Boot Objects GitHub before proceeding.

.PARAMETER SkuSiPolicy
    Deploy \Windows\System32\SecureBootUpdates\SkuSiPolicy.p7b to EFI partition.

.PARAMETER SBAT
    Apply optional Secure Boot Advanced Targeting (SBAT) update, when sharing UEFI with Linux OS'es.

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
    [string]$UpdatesFolder = "$env:SystemRoot\System32\SecureBootUpdates",

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Audit,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Latest,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Revoke,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$SkuSiPolicy,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$SBAT,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$BootMedia,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Log,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [string]$LocalRepo = "${PSScriptRoot}\Certs",

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Offline,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$DownloadContent,

    [Parameter(Mandatory=$false,ParameterSetName='Default',DontShow,ValueFromRemainingArguments=$true)]
    [string[]]$ignored
)

$ScriptVersion = '2026.01.18'

# https://github.com/microsoft/secureboot_objects/blob/main/Archived/dbx_info_msft_4_09_24_svns.csv
$EFI_BOOTMGR_DBXSVN_GUID = '01612B139DD5598843AB1C185C3CB2EB92'
$EFI_CDBOOT_DBXSVN_GUID =  '019D2EF8E827E15841A4884C18ABE2F284'
$EFI_WDSMGR_DBXSVN_GUID =  '01C2CA99C9FE7F6F4981279E2A8A535976'

$VMWARE_GUID = 'a3d5e95b-0a8f-4753-8735-445afb708f62'

$CN_Regex = '(CN=)([^,]+)'

$Arch = $env:PROCESSOR_ARCHITECTURE.ToLower()

switch ($Arch) {
    'amd64' { $EDK2_Arch = 'x64' }
    'x86'   { $EDK2_Arch = 'ia32' }
    'arm64' { $EDK2_Arch = 'aarch64' }
    'arm'   { $EDK2_Arch = 'arm' }
}

$EDK2bin_URL = "https://github.com/microsoft/secureboot_objects/releases/download/v1.6.2/edk2-${EDK2_Arch}-secureboot-binaries.zip"
$PK_DER_URL = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der'

$KEKUpdateMap_URL = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/KEK/kek_update_map.json'
$KEK_DER_URL = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/KEK/Certificates/microsoft%20corporation%20kek%202k%20ca%202023.der'

$DBXUpdate_bin_URL = "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/DBX/$Arch/DBXUpdate.bin"
$DBXUpdateSVN_bin_URL = "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/Optional/DBX/$Arch/DBXUpdateSVN.bin"

$Tab4 = ' ' * 4
$UpdatedMarkerFile = Join-Path $env:TEMP 'SecureBoot-CA2023-UPDATED.txt'
$UpdatedMarkerStatePath = 'HKLM:\SOFTWARE\SecureBoot-CA2023-Updates'
$UpdatedMarkerCountName = 'UpdatedRebootCount'
$UpdatedMarkerLastBootName = 'UpdatedLastBootId'

function Reset-UpdatedMarkerState {
    try {
        if (-not (Test-Path -LiteralPath $UpdatedMarkerStatePath)) {
            $null = New-Item -Path $UpdatedMarkerStatePath -Force
        }

        $null = New-ItemProperty -Path $UpdatedMarkerStatePath -Name $UpdatedMarkerCountName -PropertyType DWord -Value 0 -Force
        Remove-ItemProperty -Path $UpdatedMarkerStatePath -Name $UpdatedMarkerLastBootName -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $UpdatedMarkerFile -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning ('Unable to reset completion marker state: {0}' -f $_.Exception.Message)
    }
}

function Write-UpdatedMarkerAfterTwoReboots {
    try {
        if (-not (Test-Path -LiteralPath $UpdatedMarkerStatePath)) {
            $null = New-Item -Path $UpdatedMarkerStatePath -Force
        }

        $CurrentBootId = ([Management.ManagementDateTimeConverter]::ToDateTime((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)).ToString('o')
        $PreviousBootId = Get-ItemPropertyValue -Path $UpdatedMarkerStatePath -Name $UpdatedMarkerLastBootName -ErrorAction SilentlyContinue
        $RebootCount = [int](Get-ItemPropertyValue -Path $UpdatedMarkerStatePath -Name $UpdatedMarkerCountName -ErrorAction SilentlyContinue)

        if ($null -eq $PreviousBootId -or $PreviousBootId -ne $CurrentBootId) {
            $RebootCount++
            $null = New-ItemProperty -Path $UpdatedMarkerStatePath -Name $UpdatedMarkerCountName -PropertyType DWord -Value $RebootCount -Force
            $null = New-ItemProperty -Path $UpdatedMarkerStatePath -Name $UpdatedMarkerLastBootName -PropertyType String -Value $CurrentBootId -Force
        }

        if ($RebootCount -ge 2) {
            Set-Content -LiteralPath $UpdatedMarkerFile -Value 'UPDATED:"true"' -Encoding Ascii -Force
            'Wrote completion marker to "{0}" after {1} reboot(s).' -f $UpdatedMarkerFile, $RebootCount
        }
        else {
            'Completion marker deferred: {0}/2 reboot(s) observed.' -f $RebootCount
        }
    }
    catch {
        Write-Warning ('Unable to process completion marker state: {0}' -f $_.Exception.Message)
    }
}

if ($Version) {
    '{0} version ({1}){2}' -f $MyInvocation.MyCommand.Name, $ScriptVersion, $(if ($MyInvocation.Line -ne '') { "`n" })
    exit 0
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($PSVersionTable.PSVersion.Major -gt 5) {
        $PS = 'pwsh'
    }
    else {
        $PS = 'powershell'
    }

    $args = ($MyInvocation.BoundParameters.Keys.GetEnumerator() | where { $_ -notmatch 'UpdatesFolder|DBXupdate|ignored' } | foreach { '-{0}' -f $_ }) -join ' '

    if ($MyInvocation.BoundParameters.'UpdatesFolder' -ne $null) {
        $args += ' -UpdatesFolder "{0}"' -f (Get-Item $MyInvocation.BoundParameters.'UpdatesFolder' -ErrorAction SilentlyContinue).FullName
    }

    Start-Process $PS -ArgumentList "-nop -ep bypass -NoLogo -NoExit -f $($MyInvocation.MyCommand.Path) $args" -Verb RunAs
    exit 0
}

function Confirm-MinimumUBR {
    $Build = $CurrentVersion.CurrentBuildNumber
    $UBR = $CurrentVersion.UBR
    $Release = $CurrentVersion.DisplayVersion

    switch ($Build) {
        { $_ -in 19044,19045 } {
            if ($UBR -lt 6456) {
                return "Update W10 $Release to KB5066791 (Oct 2025) or later"
            }
        }

        22000 {
            if ($UBR -lt 3260) {
                return "Update W11 21H2 to KB5044280 (Oct 2025) or later"
            }
        }

        { $_ -in 22621,22631 } {
            if ($UBR -lt 6060) {
                return "Update W11 $Release to KB5066793 (Oct 2025) or later"
            }
        }

        { $_ -in 26100,26200 } {
            if ($UBR -lt 6899) {
                return "Update W11 $Release to KB5066835 (Oct 2025) or later"
            }
        }

        default {
            return ('Build {0}.{1} is unsupported' -f $Build, $UBR)
        }
    }

    return $true
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
            $Bytes = Get-Content -Encoding Byte $Filename  -ErrorAction Stop
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
    if (($Bytes[40] -eq 0x30) -and ($Bytes[41] -eq 0x82 ))
    {
        Write-Debug "Removing signature."

        # Signature is known to be ASN size plus header of 4 bytes
        $sig_length = $Bytes[42] * 256 + $Bytes[43] + 4
        if ($sig_length -gt ($Bytes.Length + 40)) {
            Write-Error "Signature longer than file size!" -ErrorAction Stop
        }

        ## Unsigned db store
        [System.Byte[]]$Bytes = @($Bytes[($sig_length+40)..($Bytes.Length - 1)].Clone())
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
        if ($_.Exception.Message -eq 'Variable is currently undefined: 0xC0000100') {
            return @()
        }
        else {
            throw $_.Exception.Message
        }
    }

    $Subject = $SignatureList.SignatureData.Subject

    if ($Verbose) {
        $Certs = $Subject | where { $_ -match '\s' } | foreach { $null = $_ -match $CN_Regex; $Matches[2] }
    }
    else {
        $Certs = $Subject | where { $_ -match 'Microsoft|Mosby' } | foreach { $null = $_ -match $CN_Regex; $Matches[2] }
    }

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

function Check-TrustedPK {
    try {
        $PKSignatureList = (Get-SecureBootUEFI PK | Get-UefiDatabaseSignatures).SignatureList
    }
    catch {
        if ($_.Exception.Message -eq 'Variable is currently undefined: 0xC0000100') {
            return $false
        }
        else {
            throw $_.Exception.Message
        }
    }

    if ($PKSignatureList.SignatureData.Subject -notmatch 'DO NOT |Example') {
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
    $SVN = '{0}.{1}' -f [int]::Parse($SignatureData.Substring(36,4), [System.Globalization.NumberStyles]::HexNumber), [int]::Parse($SignatureData.Substring(40,4), [System.Globalization.NumberStyles]::HexNumber)

    return $SVN
}

function Get-SecureBootUEFI_DBXSVN {
    param (
        [Parameter(Mandatory)]
        [string]$DBXSVN
    )

    try {
        $SignatureData = (Get-SecureBootUEFI dbx | Get-UEFIDatabaseSignatures).SignatureList.SignatureData
    }
    catch {
        if ($_.Exception.Message -eq 'Variable is currently undefined: 0xC0000100') {
            return $null
        }
        else {
            throw $_.Exception.Message
        }
    }

    $LastSig = $SignatureData -match "^$DBXSVN" | sort | select -Last 1

    if ($LastSig.Count) {
        $SVN = Get-SignatureDataSVN $LastSig
    }
    else {
        $SVN = $null
    }

    return $SVN
}

function Get-WindowsUpdate_DBXSVN {
    $DBXSVN_File = "$env:SystemRoot\System32\SecureBootUpdates\DBXUpdateSVN.bin"

    try {
        $Signatures = Get-UEFIDatabaseSignatures -BytesIn ([IO.File]::ReadAllBytes($DBXSVN_File)) | where { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' }
    }
    catch {
        $_.Exception.Message
        exit 1
    }

    $SignatureData = $Signatures.SignatureList.SignatureData -match "^$EFI_BOOTMGR_DBXSVN_GUID"
    $Count = $SignatureData.Count

    if ($Count -eq 0) {
        return $null
    }

    return (Get-SignatureDataSVN $($SignatureData))
}

function Audit-UEFI {
    $CheckList = $null
    $index = 1

    if ($SetupMode) {
        $CheckList += "{0,-3} UEFI is in Setup Mode`n" -f ('{0}.' -f $index++)
    }

    if ($PK_Cert.Count -and -not $PK_Trusted) {
        $CheckList += "{0,-3} [{1}] is UNTRUSTED`n" -f ('{0}.' -f $index++), $PK_Cert
    }

    if ('Microsoft Corporation KEK 2K CA 2023' -notin $KEK_Certs) {
        $CheckList += "{0,-3} [Microsoft Corporation KEK 2K CA 2023] missing from UEFI KEK`n" -f ('{0}.' -f $index++)
    }

    if ('Windows UEFI CA 2023' -notin $db_Certs) {
        $CheckList += "{0,-3} [Windows UEFI CA 2023] missing from UEFI DB (dbupdate2024.bin)`n" -f ('{0}.' -f $index++)
    }

    if ('Microsoft UEFI CA 2023' -notin $db_Certs) {
        $CheckList += "{0,-3} [Microsoft UEFI CA 2023] missing from UEFI DB (DBUpdate3P2023.bin)`n" -f ('{0}.' -f $index++)
    }

    if ('Microsoft Option ROM UEFI CA 2023' -notin $db_Certs) {
        $CheckList += "{0,-3} [Microsoft Option ROM UEFI CA 2023] missing from UEFI DB (DBUpdateOROM2023.bin)`n" -f ('{0}.' -f $index++)
    }

    if ('Microsoft Windows Production PCA 2011' -notin $dbx_Certs) {
        $CheckList += "{0,-3} [Production PCA 2011] missing from UEFI DBX (DBXUpdate2024.bin)`n" -f ('{0}.' -f $index++)
    }

    if (($dbx_BytesCount -eq 0) -or -not (Match-DBXSignatureData "$env:SystemRoot\System32\SecureBootUpdates\dbxupdate.bin")) {
        $CheckList += "{0,-3} DBX Updates are missing from UEFI DBX (dbxupdate.bin)`n" -f ('{0}.' -f $index++)
    }

    $UEFI_DBXSVN = Get-SecureBootUEFI_DBXSVN $EFI_BOOTMGR_DBXSVN_GUID

    if ($UEFI_DBXSVN -eq $null) {
        $CheckList += "{0,-3} Windows BootMgr SVN is missing from UEFI DBX (DBXUpdateSVN.bin)`n" -f ('{0}.' -f $index++)
    }
    elseif ((Get-WindowsUpdate_DBXSVN) -gt $UEFI_DBXSVN) {
        $CheckList += "{0,-3} SecureBootUpdates SVN is higher than UEFI DBX`n" -f ('{0}.' -f $index++)
    }

    $null = (Get-PfxCertificate -LiteralPath $BootMgr_File).Issuer -match $CN_Regex
    $PFXCert = $Matches[2]

    $BootMgr_File_Hash = (Get-FileHash -LiteralPath $BootMgr_File).Hash
    $BootMgrEX_File_Hash = (Get-FileHash $BootMgrEX_File).Hash

    if (($PFXCert -notmatch 'Windows UEFI CA 2023') -or ((Get-WindowsUpdate_DBXSVN) -gt $UEFI_DBXSVN) -and ($BootMgr_File_Hash -ne $BootMgrEX_File_Hash)) {
        $CheckList += "{0,-3} Windows Boot Manager [{1}] is wrong version`n" -f ('{0}.' -f $index++), ($PFXCert -replace 'Microsoft Windows ')
    }

    if ($VBS_Enabled) {
        if ((Test-Path -LiteralPath $EFI_SkuSiPolicy_File)) {
            $SkuSiPolicy_File_Hash = (Get-FileHash $SkuSiPolicy_File).Hash
            $EFI_SkuSiPolicy_File_Hash = (Get-FileHash -LiteralPath $EFI_SkuSiPolicy_File).Hash

            if ($EFI_SkuSiPolicy_File_Hash -ne $SkuSiPolicy_File_Hash) {
                $CheckList += "{0,-3} SkuSiPolicy.p7b (for VBS) is not updated`n" -f ('{0}.' -f $index++)
                $script:UpdateSkuSiPolicy = $true
            }
        }
        else {
            $CheckList += "{0,-3} SkuSiPolicy.p7b (for VBS) is missing`n" -f ('{0}.' -f $index++)
            $script:UpdateSkuSiPolicy = $true
        }
    }

    return $CheckList
}

function Download-EDK2bin {
    $ZIP_File = "$EDK2_Folder\edk2-secureboot-binaries.zip"

    if (-not (Test-Path $EDK2_Folder)) {
        $null = New-Item -Path $EDK2_Folder -Type Directory -Force
    }

    # Prefer a local copy of the edk2 zip when available (offline support)
    $LocalEDK2Zip = $null
    $EDK2ZipName = ($EDK2bin_URL -split '/')[-1]
    if ($LocalRepo) { $LocalEDK2Zip = Join-Path $LocalRepo $EDK2ZipName }
    if (-not $LocalEDK2Zip -and $PSScriptRoot) { $LocalEDK2Zip = Join-Path $PSScriptRoot $EDK2ZipName }

    if ($LocalEDK2Zip -and (Test-Path $LocalEDK2Zip)) {
        'Using local "{0}".' -f $EDK2ZipName
        Copy-Item -Path $LocalEDK2Zip -Destination $ZIP_File -Force
    }
    else {
        try {
            'Downloading "{0}" from GitHub.' -f $EDK2ZipName
            Invoke-WebRequest -UseBasicParsing -Uri $EDK2bin_URL -OutFile $ZIP_File
        }
        catch {
            $_.Exception.Message
            exit 1
        }
    }

    $DefaultBin_Files = @('Default3PDb.bin', 'DefaultDbx.bin', 'DefaultKek.bin', 'DefaultPk.bin')

    $objShell = New-Object -ComObject 'Shell.Application'
    $objFolder = $objShell.NameSpace($EDK2_Folder)

    foreach ($File in $DefaultBin_Files) {
        $objFolder.CopyHere("$ZIP_File\LegacyFirmwareDefaults\Firmware\$File", 0x14)
    }
}

function Suspend-Bitlocker {
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
            $null = Suspend-Bitlocker -MountPoint $SystemDrive -RebootCount $RebootCount
        }
        catch {
            $_.Exception.Message
            exit 1
        }
    }
}

function Set-SecureBootSignedFile {
    param (
        [Parameter(Mandatory)]
        [ValidateSet('PKDefault','KEKDefault','dbDefault','dbxDefault','PK','KEK','db','dbx')]
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
        Write-Host $ErrorMessage -Foreground Red

        if ($_.Exception.Message -match 'Incorrect authentication') {
            Write-Host 'Wrong signature for this UEFI variable.' -Foreground Red
        }
        else {
            $_.Exception.Message
        }

        exit 1
    }

    'Successfully wrote "{0}" to UEFI {1}.' -f (Split-Path $Filename -Leaf), $Variable
    $script:UEFI_Updated = $true

    Suspend-Bitlocker
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
        [ValidateSet('PKDefault','KEKDefault','dbDefault','dbxDefault','PK','KEK','db','dbx')]
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
        $Bytes = Get-Content -AsByteStream $Filename
    }
    else {
        $Bytes = Get-Content -Encoding Byte $Filename
    }

    # Identify file signature
    if (($Bytes[40] -ne 0x30) -or ($Bytes[41] -ne 0x82 )) {
        Write-Error "Cannot find signature!" -ErrorAction Stop
    }

    # Signature is known to be ASN size plus header of 4 bytes
    $sig_length = $Bytes[42] * 256 + $Bytes[43] + 4

    if ($sig_length -gt ($Bytes.Length + 40)) {
        Write-Error "Signature longer than file size!" -ErrorAction Stop
    }

    $SigFile = '{0}\{1}.signature.p7' -f $env:TEMP, $CertName
    $ContentFile = '{0}\{1}.content.bin' -f $env:TEMP, $CertName

    # Build and write signature output file
    if ($PSVersion -ge 6) {
        Set-Content -AsByteStream -Path $SigFile -Value ([Byte[]] $Bytes[40..($sig_length + 40 - 1)]) -ErrorAction Stop
    }
    else {
        Set-Content -Encoding Byte -Path $SigFile -Value ([Byte[]] $Bytes[40..($sig_length + 40 - 1)]) -ErrorAction Stop
    }

    # Build and write variable content output file
    if ($PSVersion -ge 6) {
        Set-Content -AsByteStream -Path $ContentFile -Value ([Byte[]] $Bytes[($sig_length + 40)..($Bytes.Length - 1)]) -ErrorAction Stop
    }
    else {
        Set-Content -Encoding Byte -Path $ContentFile -Value ([Byte[]] $Bytes[($sig_length + 40)..($Bytes.Length - 1)]) -ErrorAction Stop
    }

    try {
        # https://github.com/microsoft/secureboot_objects/discussions/158
        $null = Set-SecureBootUEFI -Name $Variable -ContentFilePath $ContentFile -SignedFilePath $SigFile -Time '2010-03-06T19:17:21Z' -AppendWrite
    }
    catch {
        $ErrorMessage = 'ERROR: Failed to append "{0}.bin" to UEFI {1}.' -f $CertName, $Variable.ToUpper()
        Write-Host $ErrorMessage -Foreground Red

        if ($_.Exception.Message -match 'Incorrect authentication') {
            Write-Host 'Wrong signature for this UEFI variable.' -Foreground Red
        }
        else {
            $_.Exception.Message
        }

        exit 1
    }

    'Successfully appended "{0}" to UEFI {1}.' -f (Split-Path $Filename -Leaf), $Variable.ToUpper()
    $script:UEFI_Updated = $true

    Suspend-Bitlocker
    Remove-Item $SigFile,$ContentFile -Force
}

function Match-DBXSignatureData {
    <#
        .SYNOPSIS
        Parses EFI signatures from a DBX Update .bin file and compares the entire list against the current UEFI DBX.

        .DESCRIPTION
        From https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0#file-check-dbx-ps1
        Modified by github.com/cjee21
        Modified by github.com/garlin-cant-code

        .PARAMETER DBXUpdateFile
        Specifies a filename containing signed DBX Update signatures

        .OUTPUTS
        $true or $false
    #>

    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DBXUpdateFile
    )

    if (-not (Test-Path $DBXUpdateFile)) {
        Write-Host "DBX update file `"$DBXUpdateFile`" not found." -Foreground Red
        exit 1
    }

    try {
        $RequiredSignatures = Get-UEFIDatabaseSignatures -BytesIn ([IO.File]::ReadAllBytes($DBXUpdateFile)) | where { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' }
    }
    catch {
        Write-Host "No EFI_CERT_SHA256 signatures in $DBXUpdateFile" -Foreground Red
        return $true
    }

    try {
        $DBXSignatureData = (Get-SecureBootUEFI dbx | Get-UEFIDatabaseSignatures).SignatureList.SignatureData
    }
    catch {
        if ($_.Exception.Message -eq 'Variable is currently undefined: 0xC0000100') {
            return $false
        }
        else {
            throw $_.Exception.Message
        }
    }

    $RequiredSignatureData = $RequiredSignatures.SignatureList.SignatureData
    $RequiredCount = $RequiredSignatureData.Count

    if ($RequiredCount -eq 0) {
        Write-Host "No DBX signatures in $DBXUpdateFile" -Foreground Red
        return $true
    }

    $Matched = 0

    foreach ($RequiredSig in $RequiredSignatureData) {
        if ($DBXSignatureData -contains $RequiredSig) {
            $Matched++
        }
        else {
            $RequiredSVN = Get-SignatureDataSVN $RequiredSig

            switch ($RequiredSig) {
                { $_ -match "^$EFI_BOOTMGR_DBXSVN_GUID" } {
                    $CurrentSVN = Get-SecureBootUEFI_DBXSVN $EFI_BOOTMGR_DBXSVN_GUID

                    if ($CurrentSVN -ge $RequiredSVN) {
                        $Matched++
                    }
                }

                { $_ -match "^$EFI_CDBOOT_DBXSVN_GUID" } {
                    $CurrentSVN = Get-SecureBootUEFI_DBXSVN $EFI_CDBOOT_DBXSVN_GUID

                    if ($CurrentSVN -ge $RequiredSVN) {
                        $Matched++
                    }
                }

                { $_ -match "^$EFI_WDSMGR_DBXSVN_GUID" } {
                    $CurrentSVN = Get-SecureBootUEFI_DBXSVN $EFI_WDSMGR_DBXSVN_GUID

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

function Resolve-LocalCertPath {
    param (
        [Parameter(Mandatory)]
        [string]$CertFile
    )

    $Candidates = @()

    if ($PSScriptRoot) {
        $Candidates += (Join-Path $PSScriptRoot $CertFile)
        $Candidates += (Join-Path $PSScriptRoot 'certs' $CertFile)
        $Candidates += (Join-Path $PSScriptRoot 'Certs' $CertFile)
    }

    if ($UpdatesFolder) {
        $Candidates += (Join-Path $UpdatesFolder $CertFile)
    }

    if ($LocalRepo) {
        $Candidates += (Join-Path $LocalRepo $CertFile)
        $Candidates += (Join-Path $LocalRepo 'certs' $CertFile)
        $Candidates += (Join-Path $LocalRepo 'Certs' $CertFile)
    }

    foreach ($Path in $Candidates) {
        if (Test-Path -LiteralPath $Path) {
            return $Path
        }
    }

    return $null
}

function Invoke-FileStageAsSystem {
    param (
        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$DestinationPath,

        [Parameter(Mandatory=$false)]
        [switch]$CopyChildren,

        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 300
    )

    if (-not (Test-Path -LiteralPath $SourcePath)) {
        throw "Source path not found: $SourcePath"
    }

    $TaskId = [guid]::NewGuid().Guid.Substring(0,8)
    $TaskName = "SBStage-$TaskId"

    $StageWorkRoot = Join-Path $env:ProgramData 'SBStage'
    if (-not (Test-Path -LiteralPath $StageWorkRoot)) {
        $null = New-Item -Path $StageWorkRoot -ItemType Directory -Force
    }

    $ScriptFile = Join-Path $StageWorkRoot "$TaskName.ps1"
    $DoneFile = Join-Path $StageWorkRoot "$TaskName.done"
    $ErrorFile = Join-Path $StageWorkRoot "$TaskName.error"
    $StageSourceRoot = Join-Path $StageWorkRoot "$TaskName-src"
    $StageSourcePath = Join-Path $StageSourceRoot (Split-Path -Path $SourcePath -Leaf)
    $EscScriptFile = $ScriptFile.Replace("'","''")

    $EscSource = $SourcePath.Replace("'","''")
    $EscStageSource = $StageSourcePath.Replace("'","''")
    $EscDestination = $DestinationPath.Replace("'","''")
    $EscDone = $DoneFile.Replace("'","''")
    $EscError = $ErrorFile.Replace("'","''")

    if ($CopyChildren) {
        $RobocopyDestination = $DestinationPath
    }
    else {
        $RobocopyDestination = Join-Path $DestinationPath (Split-Path -Path $SourcePath -Leaf)
    }

    $EscRoboDest = $RobocopyDestination.Replace("'","''")

    if (Test-Path -LiteralPath $StageSourceRoot) {
        Remove-Item -LiteralPath $StageSourceRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    $null = New-Item -Path $StageSourceRoot -ItemType Directory -Force
    Copy-Item -Path $SourcePath -Destination $StageSourceRoot -Recurse -Force

    $CopyCommand = @"
if (-not (Test-Path -LiteralPath '$EscRoboDest')) {
    `$null = New-Item -Path '$EscRoboDest' -ItemType Directory -Force -ErrorAction SilentlyContinue
}

`$null = & robocopy '$EscStageSource' '$EscRoboDest' * /E /B /COPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS /NP
`$rc = `$LASTEXITCODE
if (`$rc -ge 8) {
    throw "Robocopy failed with exit code `$rc (source '$EscStageSource' -> destination '$EscRoboDest')."
}
"@

    $SystemScript = @"
`$ErrorActionPreference = 'Stop'
try {
    if (-not (Test-Path -LiteralPath '$EscDestination')) {
        `$null = New-Item -Path '$EscDestination' -ItemType Directory -Force
    }

    $CopyCommand

    'OK' | Set-Content -LiteralPath '$EscDone' -Encoding Ascii -Force
}
catch {
    (`$_ | Out-String) | Set-Content -LiteralPath '$EscError' -Encoding Ascii -Force
    exit 1
}
"@

    Set-Content -LiteralPath $ScriptFile -Value $SystemScript -Encoding Ascii -Force

    "[SYSTEM-STAGE] Source: $SourcePath"
    "[SYSTEM-STAGE] StagedSource: $StageSourcePath"
    "[SYSTEM-STAGE] Destination: $DestinationPath"
    "[SYSTEM-STAGE] RobocopyDestination: $RobocopyDestination"
    "[SYSTEM-STAGE] Script: $ScriptFile"
    "[SYSTEM-STAGE] Markers: $DoneFile ; $ErrorFile"

    try {
        $ScheduleSvc = Get-Service -Name Schedule -ErrorAction SilentlyContinue
        if ($null -eq $ScheduleSvc) {
            throw 'Task Scheduler service (Schedule) was not found.'
        }

        if ($ScheduleSvc.Status -ne 'Running') {
            Start-Service -Name Schedule -ErrorAction Stop
        }

        $StartTime = (Get-Date).AddMinutes(5).ToString('HH:mm')
        $RunCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptFile"

        $null = & schtasks.exe /Create /TN $TaskName /SC ONCE /ST $StartTime /RL HIGHEST /RU SYSTEM /TR $RunCmd /F
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create SYSTEM staging task '$TaskName' (exit code $LASTEXITCODE)."
        }

        $null = & schtasks.exe /Run /TN $TaskName
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to run SYSTEM staging task '$TaskName' (exit code $LASTEXITCODE)."
        }

        $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $NextWaitPrint = (Get-Date).AddSeconds(15)
        $NoMarkerDeadline = (Get-Date).AddSeconds([Math]::Min(120, [Math]::Max(45, [int]($TimeoutSeconds / 2))))

        while ((Get-Date) -lt $Deadline) {
            if (Test-Path -LiteralPath $DoneFile) {
                return $true
            }

            if (Test-Path -LiteralPath $ErrorFile) {
                throw (Get-Content -LiteralPath $ErrorFile -Raw)
            }

            if ((Get-Date) -ge $NextWaitPrint) {
                "[SYSTEM-STAGE] Waiting for completion markers..."
                $NextWaitPrint = (Get-Date).AddSeconds(15)
            }

            if ((Get-Date) -ge $NoMarkerDeadline) {
                $TaskQuery = (& schtasks.exe /Query /TN $TaskName /V /FO LIST 2>$null) -join "`n"
                throw "SYSTEM staging produced no completion markers after extended wait. Task may be blocked from launching PowerShell payload.`n$TaskQuery"
            }

            Start-Sleep -Milliseconds 500
        }

        $TaskQuery = (& schtasks.exe /Query /TN $TaskName /V /FO LIST) -join "`n"
        if (Test-Path -LiteralPath $ErrorFile) {
            throw (Get-Content -LiteralPath $ErrorFile -Raw)
        }

        throw "SYSTEM staging timed out after $TimeoutSeconds seconds.`n$TaskQuery"
    }
    finally {
        $null = & schtasks.exe /Delete /TN $TaskName /F 2>$null
        Remove-Item -LiteralPath $ScriptFile,$DoneFile,$ErrorFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $StageSourceRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-PreReqStaging {
    param (
        [Parameter(Mandatory)]
        [string]$Reason
    )

    $LocalRepoPath = $LocalRepo
    if (-not $LocalRepoPath -and $PSScriptRoot) {
        $LocalRepoPath = Join-Path $PSScriptRoot 'Certs'
    }

    $SourceRoots = @()
    if ($PSScriptRoot) {
        $SourceRoots += (Join-Path $PSScriptRoot 'Certs')
        $SourceRoots += $PSScriptRoot
    }
    if ($LocalRepoPath) {
        $SourceRoots += $LocalRepoPath
    }
    if ($UpdatesFolder) {
        $SourceRoots += $UpdatesFolder
    }

    $SourceRoots = $SourceRoots | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

    '[SYSTEM-STAGE] Candidate source roots:'
    $SourceRoots | ForEach-Object { "[SYSTEM-STAGE] - $_" }

    $EFIEX_SourceCandidates = @()
    $SecureBootUpdates_SourceCandidates = @()

    foreach ($Root in $SourceRoots) {
        $EFIEX_SourceCandidates += (Join-Path $Root 'EFI_EX')
        $EFIEX_SourceCandidates += (Join-Path $Root 'Certs\EFI_EX')

        $SecureBootUpdates_SourceCandidates += (Join-Path $Root 'SecureBootUpdates')
        $SecureBootUpdates_SourceCandidates += (Join-Path $Root 'Certs\SecureBootUpdates')
    }

    $EFIEX_Source = $EFIEX_SourceCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $SecureBootUpdates_Source = $SecureBootUpdates_SourceCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    if (-not $EFIEX_Source -and $PSScriptRoot) {
        try {
            $Found = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Certs') -Directory -Filter 'EFI_EX' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($Found) { $EFIEX_Source = $Found.FullName }
        }
        catch {}
    }

    if (-not $SecureBootUpdates_Source -and $PSScriptRoot) {
        try {
            $Found = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Certs') -Directory -Filter 'SecureBootUpdates' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($Found) { $SecureBootUpdates_Source = $Found.FullName }
        }
        catch {}
    }

    "[SYSTEM-STAGE] Resolved EFI_EX source: $EFIEX_Source"
    "[SYSTEM-STAGE] Resolved SecureBootUpdates source: $SecureBootUpdates_Source"

    if ($EFIEX_Source) {
        Invoke-FileStageAsSystem -SourcePath $EFIEX_Source -DestinationPath "$env:SystemRoot\Boot"
        'Staged EFI_EX into "{0}" from "{1}".' -f "$env:SystemRoot\Boot", $EFIEX_Source
    }
    else {
        Write-Warning 'Unable to find local EFI_EX folder to stage.'
    }

    $SecureBootUpdates_Dest = "$env:SystemRoot\System32\SecureBootUpdates"

    if (-not (Test-Path -LiteralPath $SecureBootUpdates_Dest)) {
        $null = New-Item -Path $SecureBootUpdates_Dest -ItemType Directory -Force
    }

    if ($SecureBootUpdates_Source) {
        Invoke-FileStageAsSystem -SourcePath $SecureBootUpdates_Source -DestinationPath $SecureBootUpdates_Dest -CopyChildren
        'Staged SecureBootUpdates into "{0}" from "{1}".' -f $SecureBootUpdates_Dest, $SecureBootUpdates_Source
    }
    else {
        Write-Warning 'Unable to find local SecureBootUpdates folder to stage.'
    }

    $SecureBootReg = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
    $null = New-Item -Path $SecureBootReg -Force
    $null = New-ItemProperty -Path $SecureBootReg -Name 'AvailableUpdates' -PropertyType DWord -Value 0x5900 -Force

    'Set registry: HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates = 0x5900.'
    "Minimum UBR prerequisite not met: $Reason"
    'After OS upgrade/KB compliance, use AvailableUpdates=0x5944 and run \\Microsoft\\Windows\\PI\\Secure-Boot-Update per KB5068202.'
}


function Populate-LocalRepo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$LocalRepoPath
    )

    if (-not (Test-Path -LiteralPath $LocalRepoPath)) {
        New-Item -Path $LocalRepoPath -ItemType Directory -Force | Out-Null
    }

    $ToFetch = @()

    $ToFetch += @{ url = $KEKUpdateMap_URL; name = (Split-Path $KEKUpdateMap_URL -Leaf) }
    $ToFetch += @{ url = $KEK_DER_URL; name = (Split-Path $KEK_DER_URL -Leaf) }
    $ToFetch += @{ url = $PK_DER_URL; name = (Split-Path $PK_DER_URL -Leaf) }
    $ToFetch += @{ url = $EDK2bin_URL; name = (Split-Path $EDK2bin_URL -Leaf) }
    $ToFetch += @{ url = $DBXUpdate_bin_URL; name = (Split-Path $DBXUpdate_bin_URL -Leaf) }
    $ToFetch += @{ url = $DBXUpdateSVN_bin_URL; name = (Split-Path $DBXUpdateSVN_bin_URL -Leaf) }

    foreach ($item in $ToFetch) {
        $name = $item.name -replace '%20',' '
        $dest = Join-Path $LocalRepoPath $name

        if (Test-Path -LiteralPath $dest) { continue }

        try {
            'Downloading "{0}" to "{1}".' -f $name, $LocalRepoPath
            Invoke-WebRequest -UseBasicParsing -Uri $item.url -OutFile $dest
        }
        catch {
            Write-Warning ("Warning: failed to download {0}: {1}" -f $item.url, $_.Exception.Message)
        }
    }

    # If we have a kek_update_map.json locally, attempt to download any referenced KEK update files
    $MapName = (Split-Path $KEKUpdateMap_URL -Leaf)
    $MapPath = Join-Path $LocalRepoPath $MapName
    if (Test-Path $MapPath) {
        try {
            $mapJson = Get-Content -Raw -Path $MapPath | ConvertFrom-Json
            $kekFiles = @()

            foreach ($prop in $mapJson.PSObject.Properties) {
                $val = $prop.Value
                if ($null -ne $val -and $val.PSObject.Properties.Name -contains 'KEKUpdate') {
                    $update = $val.KEKUpdate
                    if ($update) { $kekFiles += $update }
                }
            }

            $kekFiles = $kekFiles | Where-Object { $_ } | Sort-Object -Unique

            foreach ($entry in $kekFiles) {
                try {
                    $parts = $entry -split '/'
                    if ($parts.Count -eq 2) {
                        $vendor = $parts[0]
                        $file = $parts[1]
                        $kekDestFolder = Join-Path $LocalRepoPath 'KEK'
                        $kekVendorFolder = Join-Path $kekDestFolder $vendor
                        if (-not (Test-Path $kekVendorFolder)) { New-Item -Path $kekVendorFolder -ItemType Directory -Force | Out-Null }

                        $localPath1 = Join-Path $LocalRepoPath $file
                        $localPath2 = Join-Path $kekDestFolder $file
                        $localPath3 = Join-Path $kekVendorFolder $file

                        if ((Test-Path $localPath1) -or (Test-Path $localPath2) -or (Test-Path $localPath3)) { continue }

                        $remote = "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/KEK/$entry"
                        'Downloading KEK update "{0}"' -f $entry
                        Invoke-WebRequest -UseBasicParsing -Uri $remote -OutFile $localPath3 -ErrorAction Stop
                        # copy to top-level local repo for convenience
                        Copy-Item -Path $localPath3 -Destination $localPath1 -Force
                    }
                }
                catch {
                    Write-Warning ("Failed to fetch KEK entry {0}: {1}" -f $entry, $_.Exception.Message)
                }
            }
        }
        catch {
            Write-Warning ("Failed to parse KEK map for additional downloads: {0}" -f $_.Exception.Message)
        }
    }
}

function Update-PK_Cert {
    # Pre-signed object for Windows OEM Devices PK

    $CertFile = 'WindowsOEMDevicesPK.der'
    $PreSignedObj_File = "$env:TEMP\$CertFile"

    if (-not (Test-Path -LiteralPath "$EFI_FolderPath\$CertFile")) {
        try {
            $LocalCertPath = Resolve-LocalCertPath -CertFile $CertFile

            if ($LocalCertPath) {
                'Using local "{0}" from "{1}".' -f $CertFile, $LocalCertPath
                Copy-Item -Path $LocalCertPath -Destination $PreSignedObj_File -Force
            }
            else {
                'Downloading "{0}" from GitHub.' -f $CertFile
                Invoke-WebRequest -UseBasicParsing -Uri $PK_DER_URL -OutFile $PreSignedObj_File
            }
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
    # Attempt to load kek_update_map.json from a local repo when provided (offline support)
    $MapLocalPath = $null
    $MapFileName = (Split-Path $KEKUpdateMap_URL -Leaf)
    if ($LocalRepo) { $MapLocalPath = Join-Path $LocalRepo $MapFileName }
    if (-not $MapLocalPath -and $PSScriptRoot) { $MapLocalPath = Join-Path $PSScriptRoot $MapFileName }
    if (-not $MapLocalPath -and $UpdatesFolder) { $MapLocalPath = Join-Path $UpdatesFolder $MapFileName }

    if ($MapLocalPath -and (Test-Path $MapLocalPath)) {
        try {
            $JSON = Get-Content -Raw -Path $MapLocalPath | ConvertFrom-Json
        }
        catch {
            "`nERROR: Unable to parse local KEK update map: $MapLocalPath"
            Write-Host (($_.Exception.Message -split "`n") | select -First 1) -Foreground Red
            exit 1
        }
    }
    else {
        try {
            $JSON = (Invoke-WebRequest -UseBasicParsing -Uri $KEKUpdateMap_URL).Content | ConvertFrom-Json
        }
        catch {
            "`nERROR: Unable to parse Microsoft's KEK update map."
            Write-Host (($_.Exception.Message -split "`n") | select -First 1) -Foreground Red
            exit 1
        }
    }

    try {
        $PK_Thumbprint = (Get-UefiDatabaseSignatures -BytesIn (Get-SecureBootUEFI PK).Bytes).SignatureList.SignatureData.Thumbprint
    }
    catch {
        if ($_.Exception.Message -eq 'Variable is currently undefined: 0xC0000100') {
            return $null
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

        # Decode URL-encoded filename for local filesystem checks (e.g., %20 -> space)
        $KEK_Update_Local = $KEK_Update -replace '%20',' '

        $KEK_BIN_URL = "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/KEK/$Vendor/$KEK_Update"
        $PostSignedObj_File = "$env:TEMP\$KEK_Update_Local"

        # Prefer a local copy of the post-signed KEK update when available (check KEK subfolders)
        $LocalKEKBinCandidates = @()
        if ($LocalRepo) {
            $LocalKEKBinCandidates += Join-Path $LocalRepo $KEK_Update_Local
            $LocalKEKBinCandidates += Join-Path $LocalRepo ("KEK\\$KEK_Update_Local")
        }
        if ($PSScriptRoot) {
            $LocalKEKBinCandidates += Join-Path $PSScriptRoot $KEK_Update_Local
            $LocalKEKBinCandidates += Join-Path $PSScriptRoot ("KEK\\$KEK_Update_Local")
        }
        if ($UpdatesFolder) {
            $LocalKEKBinCandidates += Join-Path $UpdatesFolder $KEK_Update_Local
            $LocalKEKBinCandidates += Join-Path $UpdatesFolder ("KEK\\$KEK_Update_Local")
        }

        $LocalKEKBin = $LocalKEKBinCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

        # If not found in the candidate paths, try a recursive search under common local roots
        if (-not $LocalKEKBin) {
            $searchRoots = @()
            if ($LocalRepo) { $searchRoots += $LocalRepo }
            if ($PSScriptRoot) { $searchRoots += $PSScriptRoot }
            if ($UpdatesFolder) { $searchRoots += $UpdatesFolder }

            foreach ($root in $searchRoots) {
                if ($LocalKEKBin) { break }
                if (Test-Path -LiteralPath $root) {
                    try {
                        $found = Get-ChildItem -Path $root -Filter $KEK_Update_Local -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($found) {
                            $LocalKEKBin = $found.FullName
                            'Found local KEK via recursive search: {0}' -f $LocalKEKBin
                            break
                        }
                    }
                    catch {
                        # ignore and continue
                    }
                }
            }
        }

        if ($LocalKEKBin) {
            'Using local "{0}".' -f (Split-Path $LocalKEKBin -Leaf)
            Copy-Item -Path $LocalKEKBin -Destination $PostSignedObj_File -Force
        }
        else {
            # Diagnostic: list candidate local paths and whether they exist
            'Local KEK candidates (path -> exists):'
            foreach ($c in $LocalKEKBinCandidates) {
                Write-Host ("{0} -> {1}" -f $c, (Test-Path -LiteralPath $c))
            }

            try {
                'Downloading "{0}" from GitHub.' -f $KEK_Update
                Invoke-WebRequest -UseBasicParsing -Uri $KEK_BIN_URL -OutFile $PostSignedObj_File
            }
            catch {
                Write-Host $_.Exception.Message -Foreground Red
                exit 1
            }
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
                $LocalCertPath = Resolve-LocalCertPath -CertFile $CertFile

                if ($LocalCertPath) {
                    'Using local "{0}" from "{1}".' -f $CertFile, $LocalCertPath
                    Copy-Item -Path $LocalCertPath -Destination $PreSignedObj_File -Force
                }
                else {
                    # Prefer local KEK cert when available
                    $LocalKEKDer = $null
                    $KEKDerName = ($KEK_DER_URL -split '/')[-1]
                    $KEKDerName = $KEKDerName -replace '%20',' '
                    if ($LocalRepo) { $LocalKEKDer = Join-Path $LocalRepo $KEKDerName }
                    if (-not $LocalKEKDer -and $PSScriptRoot) { $LocalKEKDer = Join-Path $PSScriptRoot $KEKDerName }
                    if (-not $LocalKEKDer -and $UpdatesFolder) { $LocalKEKDer = Join-Path $UpdatesFolder $KEKDerName }

                    if ($LocalKEKDer -and (Test-Path $LocalKEKDer)) {
                        'Using local "{0}".' -f $KEKDerName
                        Copy-Item -Path $LocalKEKDer -Destination $PreSignedObj_File -Force
                    }
                    else {
                        'Downloading "{0}" from GitHub.' -f $CertFile
                        Invoke-WebRequest -UseBasicParsing -Uri $KEK_DER_URL -OutFile $PreSignedObj_File
                    }
                }
            }
            catch {
                Write-Host $_.Exception.Message -Foreground Red
                exit 1
            }

            if (-not (Test-Path -LiteralPath $EFI_FolderPath)) {
                $null = New-Item -Path $EFI_FolderPath -Type Directory -Force
            }

            'Copying "{0}" to EFI.' -f $CertFile
            Copy-Item -Path $PreSignedObj_File -Destination $EFI_FolderPath -Force
            Copy-Item -Path $PreSignedObj_File -Destination "$EFI_FolderPath\$($CertFile -replace '\.der','.crt')" -Force

            Remove-Item $PreSignedObj_File -Force
        }

        $script:KEK_README = $true
    }
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

$ScriptBlock = {
    $CurrentVersion = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion'

    $SystemDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'

    # Ensure LocalRepo defaults to ./Certs under script root. Populate only when -DownloadContent (opt-in)
    if (-not $LocalRepo) { $LocalRepo = Join-Path $PSScriptRoot 'Certs' }

    if (-not (Test-Path -LiteralPath $LocalRepo)) {
        New-Item -Path $LocalRepo -ItemType Directory -Force | Out-Null
    }

    if ($DownloadContent -or $Offline) {
        Populate-LocalRepo -LocalRepoPath $LocalRepo
    }

    $Result = Confirm-MinimumUBR

    if ($Result -ne $true) {
        Write-Warning 'Minimum Windows UBR check failed. Staging local Secure Boot payloads instead of exiting with a KB-only error.'
        Invoke-PreReqStaging -Reason $Result
        Write-Output ''
        return
    }

    $SecureBoot = Confirm-SecureBootUEFI

    if ($SecureBoot -isnot [bool]) {
        "ERROR: This PC doesn't support Secure Boot.`n"
        exit 1
    }

    $VBS_Status = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus

    if ($VBS_Status -gt 0) {
        $VBS_Enabled = $true
    }

    foreach ($Variable in 'PK','KEK','db','dbx') {
        try {
            $Count = (Get-SecureBootUEFI $Variable).Bytes.Count
        }
        catch {
            if ($_.Exception.Message -eq 'Variable is currently undefined: 0xC0000100') {
                $Count = 0
            }
        }

        New-Variable -Name "${Variable}_BytesCount" -Value $Count
    }

    if (((Get-SecureBootUEFI SetupMode).Bytes -Join '') -eq 1) {
        $SetupMode = $true
    }

    try {
        $PK_Cert = Get-UEFICert PK
        $KEK_Certs = Get-UEFICert KEK
        $db_Certs = Get-UEFICert db
        $dbx_Certs = Get-UEFICert dbx
    }
    catch {
        Write-Host 'ERROR: Failed to read UEFI Secure Boot settings.' -Foreground Red
        exit 1
    }

    $PK_Trusted = Check-TrustedPK

    $SystemDisk = (Get-Disk | Where-Object {$_.IsSystem -eq $true}).Number
    $SystemPartition = Get-Partition -DiskNumber $SystemDisk | Where-Object { $_.Type -eq 'System' } | Select-Object -First 1

    if (-not $SystemPartition) {
        Write-Host 'ERROR: System partition not found. Unable to locate EFI volume.' -Foreground Red
        exit 1
    }

    $GUID = $SystemPartition.Guid

    $EFI_Path = "\\?\Volume$GUID\EFI"
    $EFI_FolderPath = "$EFI_Path\Certs"

    $BootMgrEX_File = "$env:SystemRoot\Boot\EFI_EX\bootmgfw_EX.efi"
    $SkuSiPolicy_File = "$env:SystemRoot\System32\SecureBootUpdates\SkuSiPolicy.p7b"

    $BootMgr_File = "$EFI_Path\Microsoft\Boot\bootmgfw.efi"
    $EFI_SkuSiPolicy_File = "$EFI_Path\Microsoft\Boot\SkuSiPolicy.p7b"

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
            Write-Host 'ERROR: Failed to read UEFI Secure Boot settings.' -Foreground Red
            exit 1
        }

        Remove-Item $EDK2_Folder -Recurse -Force
    }

    if (-not $PK_Trusted) {
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

    if ($Revoke) {
        if ($SecureBoot -and $KEK_Certs -notcontains 'Microsoft Corporation KEK 2K CA 2023') {
            'WARNING: Disable Secure Boot, before attempting to use -Revoke option.  No [KEK 2K CA 2023] cert is currently enrolled.'
            '{0}System will fail to boot due to a security violation.' -f $Tab4
            exit 1
        }

        if ($Latest) {
            # Prefer local DBX files when available (offline support)
            $LocalDBX = $null
            $LocalDBXSVN = $null
            if ($LocalRepo) {
                $LocalDBX = Join-Path $LocalRepo 'DBXUpdate.bin'
                $LocalDBXSVN = Join-Path $LocalRepo 'DBXUpdateSVN.bin'
            }
            if (-not $LocalDBX -and $PSScriptRoot) {
                $LocalDBX = Join-Path $PSScriptRoot 'DBXUpdate.bin'
                $LocalDBXSVN = Join-Path $PSScriptRoot 'DBXUpdateSVN.bin'
            }
            if (-not $LocalDBX -and $UpdatesFolder) {
                $LocalDBX = Join-Path $UpdatesFolder 'DBXUpdate.bin'
                $LocalDBXSVN = Join-Path $UpdatesFolder 'DBXUpdateSVN.bin'
            }

            try {
                if ($LocalDBX -and (Test-Path $LocalDBX)) {
                    Copy-Item -Path $LocalDBX -Destination "$env:TEMP\DBXUpdate.bin" -Force
                }
                else {
                    Invoke-WebRequest -UseBasicParsing -Uri $DBXUpdate_bin_URL -OutFile "$env:TEMP\DBXUpdate.bin"
                }

                if ($LocalDBXSVN -and (Test-Path $LocalDBXSVN)) {
                    Copy-Item -Path $LocalDBXSVN -Destination "$env:TEMP\DBXUpdateSVN.bin" -Force
                }
                else {
                    Invoke-WebRequest -UseBasicParsing -Uri $DBXUpdateSVN_bin_URL -OutFile "$env:TEMP\DBXUpdateSVN.bin"
                }
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

        $DBXSignatureData = (Get-SecureBootUEFI dbx | Get-UEFIDatabaseSignatures).SignatureList.SignatureData

        if (-not $(Match-DBXSignatureData $DBXUpdate_bin)) {
            Append-SecureBootSignedFile -Variable dbx -Filename $DBXUpdate_bin
        }
        elseif ($Latest) {
            '"dbxupdate.bin" is not a newer version of file.'
        }

        if ('Microsoft Windows Production PCA 2011' -notin (Get-UEFICert dbx)) {
            Append-SecureBootSignedFile -Variable dbx -Filename "$UpdatesFolder\DBXUpdate2024.bin"
        }

        if ('Microsoft Windows Production PCA 2011' -in (Get-UEFICert dbx)) {
            if (-not $(Match-DBXSignatureData $DBXUpdateSVN_bin)) {
                $Result = Append-SecureBootSignedFile -Variable dbx -Filename $DBXUpdateSVN_bin
                $SVN = Get-SecureBootUEFI_DBXSVN $EFI_BOOTMGR_DBXSVN_GUID

                $Result -replace ' to'," (SVN $SVN) to"
                $UEFI_Updated = $true
            }
            elseif ($Latest) {
                '"DBXUpdateSVN.bin" is not a newer version of file.'
            }
        }
    }

    if (($Revoke -and $VBS_Enabled) -or $SkuSiPolicy) {
        if ((Test-Path -LiteralPath $EFI_SkuSiPolicy_File)) {
            $SkuSiPolicy_File_Hash = (Get-FileHash $SkuSiPolicy_File).Hash
            $EFI_SkuSiPolicy_File_Hash = (Get-FileHash -LiteralPath $EFI_SkuSiPolicy_File).Hash

            if ($EFI_SkuSiPolicy_File_Hash -ne $SkuSiPolicy_File_Hash) {
                Copy-Item $SkuSiPolicy_File "$EFI_SkuSiPolicy_File" -Force

                'Deployed SkuSiPolicy.p7b (for VBS).'
                $UEFI_Updated = $true
            }
        }
        else {
            Copy-Item $SkuSiPolicy_File "$EFI_SkuSiPolicy_File" -Force

            'Deployed SkuSiPolicy.p7b (for VBS).'
            $UEFI_Updated = $true
        }
    }

    if ($Revoke -and $SBAT) {
        $null = Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name AvailableUpdates -Value 0x400
        Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"

        'Applying SBAT update for Linux.'
        $UEFI_Updated = $true
    }

    if ($Latest) {
        Remove-Item $DBXUpdate_bin,$DBXUpdateSVN_bin -Force
    }

    $BootMgrEX_File = "$env:SystemRoot\Boot\EFI_EX\bootmgfw_EX.efi"

    if ('Windows UEFI CA 2023' -in (Get-UEFICert db)) {
        $BootMgrEX_File_Hash = (Get-FileHash $BootMgrEX_File).Hash
        $BootMgr_File_Hash = (Get-FileHash -LiteralPath $BootMgr_File).Hash

        if ($BootMgr_File_Hash -ne $BootMgrEX_File_Hash) {
            'Copying EFI boot files.'

            $RE_info = reagentc /info

            if (($RE_info -match 'RE status:' -split ' ')[-1] -eq 'Enabled') {
                $WinRE = $true

                $WinRE_Path = ($RE_info -match 'RE location:' -split ' ')[-1]
                $WinRE_GUID = ($RE_info -match 'identifier:' -split ' ')[-1]
            }

            $EFI_DriveLetter = (& mountvol) -split "`n" | foreach { if ($_ -match '(.*mounted at )(.*)(\\)') { $Matches[2] } }

            if ($EFI_DriveLetter -eq $null) {
                $EFI_DriveLetter = ((68..89 | foreach { [char]$_ + ':' }) | where { (Get-WmiObject Win32_LogicalDisk).DeviceID -notcontains $_ }) | select -First 1

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

            if ($WinRE) {
                try {
                    Start-Process 'reagentc' -ArgumentList "/setreimage /path $WinRE_Path" -NoNewWindow -Wait
                    Start-Process 'bcdedit' -ArgumentList "/set {default} recoverysequence {$WinRE_GUID}" -NoNewWindow -Wait
                }
                catch {
                    $_.Exception.Message
                    exit 1
                }

                $null = New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name Enable_WinRE -Value 'conhost --headless C:\Windows\System32\reagentc.exe /enable' -Force
            }

            $UEFI_Updated = $true
        }

        if ($BootMedia) {
            $RemovableDrives = Get-Volume | where { $_.DriveType -eq 'Removable' -and $_.DriveLetter -ne $null } | sort DriveLetter

            if ($RemovableDrives.Count -eq 0) {
                "No USB removable media found.`n"
            }
            else {
                foreach ($Volume in $RemovableDrives) {
                    $DriveLetter = $Volume.DriveLetter
                    $EFI_BootFile = "${DriveLetter}:\EFI\boot\boot${EDK2_Arch}.efi"

                    if (-not (Test-Path $EFI_BootFile)) {
                        continue
                    }

                    $EFI_BootFile_Hash = (Get-FileHash -LiteralPath $EFI_BootFile).Hash

                    if ($EFI_BootFile_Hash -ne $BootMgrEX_File_Hash) {
                        $Label = (Get-Volume -DriveLetter $DriveLetter).FileSystemLabel

                        if ($Label -ne '') {
                            '{0}Copying EFI boot files to USB Drive {1}: "{2}"' -f $Tab4, $DriveLetter, $Label
                        }
                        else {
                            '{0}Copying EFI boot files to USB Drive {1}:' -f $Tab4, $DriveLetter
                        }

                         try {
                             Copy-Item "${DriveLetter}:\EFI\Microsoft\Boot\BCD" $env:TEMP -Force
                             Start-Process 'bcdboot' -ArgumentList "$env:SystemRoot /f UEFI /s $DriveLetter /bootex" -NoNewWindow -Wait
                             Copy-Item "$env:TEMP\BCD" "${DriveLetter}:\EFI\Microsoft\Boot\BCD" -Force
                             Remove-Item "$env:TEMP\BCD" -Force
                         }
                         catch {
                             $_.Exception.Message
                             exit 1
                         }

                        $Media_Updated = $true
                    }
                }

                if ($Media_Updated) { '' }
            }
        }
    }

    if ($UEFI_Updated -or $PK_README -or $KEK_README) {
        Reset-UpdatedMarkerState

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

        Write-UpdatedMarkerAfterTwoReboots

       'SUCCESS: NO UPDATES ARE REQUIRED.'
    }
}

if ($Log) {
    $System = Get-CimInstance -ClassName Win32_ComputerSystem
    $LogFile = '{0}\{1} {2} Update-UEFI.log' -f $PSScriptRoot, (Get-Date -Format 'yyyy-MM-dd'), $System.Model.ToUpper()

    & $ScriptBlock | Tee-Object $LogFile
    "`nLog file saved as `"{0}`"`n" -f $LogFile
}
else {
    & $ScriptBlock
    Write-Output ''
}

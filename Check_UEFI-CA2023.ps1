<#PSScriptInfo

.VERSION 2026.01.18

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

$ScriptVersion = '2026.01.18'

# https://github.com/microsoft/secureboot_objects/blob/main/Archived/dbx_info_msft_4_09_24_svns.csv
$EFI_BOOTMGR_DBXSVN_GUID = '01612B139DD5598843AB1C185C3CB2EB92'
$EFI_CDBOOT_DBXSVN_GUID =  '019D2EF8E827E15841A4884C18ABE2F284'
$EFI_WDSMGR_DBXSVN_GUID =  '01C2CA99C9FE7F6F4981279E2A8A535976'

$VMWARE_GUID = 'a3d5e95b-0a8f-4753-8735-445afb708f62'

$CN_Regex = '(CN=)([^,]+)'

$KEKUpdateMap_URL = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/KEK/kek_update_map.json'

$Tab4 = ' ' * 4
$Tab8 = ' ' * 8
$Tab12 = ' ' * 12

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

    $args = ($MyInvocation.BoundParameters.Keys.GetEnumerator() | where { $_ -notmatch 'ignored' } | foreach { '-{0}' -f $_ }) -join ' '

    Start-Process $PS -ArgumentList "-nop -ep bypass -NoLogo -NoExit -f $($MyInvocation.MyCommand.Path) $args" -Verb RunAs
    exit 0
}

if ($PSBoundParameters['Verbose']) {
    $Verbose = $true
    $VerbosePreference = 'SilentlyContinue'
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
        if ($_.Exception.Message -eq 'Variable is currently undefined: 0xC0000100') {
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
    $DBXUpdateSVN_File = "$env:SystemRoot\System32\SecureBootUpdates\DBXUpdateSVN.bin"

    try {
        $Signatures = Get-UEFIDatabaseSignatures -BytesIn ([IO.File]::ReadAllBytes($DBXUpdateSVN_File)) | where { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' }
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

    switch ($CertName) {
        { $_ -match '2011' } {
            if ($KEK_Certs -contains 'Microsoft Corporation KEK CA 2011' -and $db_Certs -contains $CertName -and $dbx_Certs -notcontains $CertName) {
               return 'ALLOWED'
            }
            else {
               return 'BANNED'
            }
        }

        { $_ -match '2023' } {
            if ($KEK_Certs -contains 'Microsoft Corporation KEK 2K CA 2023' -and $db_Certs -contains $CertName -and $dbx_Certs -notcontains $CertName) {
               return 'ALLOWED'
            }
            else {
               return 'BANNED'
            }
        }

        default { return 'UNKNOWN' }
    }
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
    }

    if ($PK_Cert.Count -and -not $PK_Trusted) {
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
        $script:UpdateFlags = $script:UpdateFlags -bor 0x1000 -bor 0x4000
    }

    if ('Microsoft Option ROM UEFI CA 2023' -notin $db_Certs) {
        $CheckList += "{0,-3} [Microsoft Option ROM UEFI CA 2023] is missing from UEFI DB`n" -f ('{0}.' -f $index++)
        $script:UpdateFlags = $script:UpdateFlags -bor 0x800 -bor 0x4000
    }

    if ('Microsoft Windows Production PCA 2011' -notin $dbx_Certs) {
        $CheckList += "{0,-3} [Production PCA 2011] is missing from UEFI DBX`n" -f ('{0}.' -f $index++)
        $script:RevokeFlags = $script:RevokeFlags -bor 0x80
    }

    if (($dbx_BytesCount -eq 0) -or -not (Match-DBXSignatureData "$env:SystemRoot\System32\SecureBootUpdates\dbxupdate.bin")) {
        $CheckList += "{0,-3} DBX Updates are missing from UEFI DBX`n" -f ('{0}.' -f $index++)
        $script:RevokeFlags = $script:RevokeFlags -bor 0x2
    }

    $UEFI_DBXSVN = Get-SecureBootUEFI_DBXSVN $EFI_BOOTMGR_DBXSVN_GUID

    if ($UEFI_DBXSVN -eq $null) {
        $CheckList += "{0,-3} Windows BootMgr SVN is missing from UEFI DBX`n" -f ('{0}.' -f $index++)
        $script:RevokeFlags = $script:RevokeFlags -bor 0x200
    }
    elseif ((Get-WindowsUpdate_DBXSVN) -gt $UEFI_DBXSVN) {
        $CheckList += "{0,-3} SecureBootUpdates SVN is higher than UEFI DBX`n" -f ('{0}.' -f $index++)
        $script:RevokeFlags = $script:RevokeFlags -bor 0x200
    }

    $BootMgr_File_Hash = (Get-FileHash -LiteralPath $BootMgr_File).Hash
    $BootMgrEX_File_Hash = (Get-FileHash $BootMgrEX_File).Hash

    if (($PFXCert -notmatch 'Windows UEFI CA 2023') -or ((Get-WindowsUpdate_DBXSVN) -gt $UEFI_DBXSVN) -and ($BootMgr_File_Hash -ne $BootMgrEX_File_Hash)) {
        $CheckList += "{0,-3} Windows Boot Manager [{1}] is wrong version`n" -f ('{0}.' -f $index++), ($PFXCert -replace 'Microsoft Windows ')
        $script:UpdateFlags = $script:UpdateFlags -bor 0x100
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

function Check-BootManager {
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
        if ($SecureBoot -eq $false -or $dbx_Certs -notcontains 'Microsoft Windows Production PCA 2011') {
            '{0}{1,-13} Boot Manager [Production PCA 2011] {2} ALLOWED.' -f $Tab8, $WIM_Image, $Verb
        }
        else {
            '{0}{1,-13} Boot Manager [Production PCA 2011] {2} BANNED.' -f $Tab8, $WIM_Image, $Verb
        }
    }
}

function Get-ProductVersion {
    param (
        [Parameter(Mandatory)]
        [string]$File
    )

    $ProductVersion = (Get-Item -LiteralPath $File).VersionInfo.ProductVersion -replace '^10.0.'
    return $ProductVersion
}

function Check-BootMedia {
    $RemovableDrives = Get-Volume | where { $_.DriveType -in 'CD-ROM','Removable' -and $_.DriveLetter -ne $null } | sort DriveLetter

    if ($RemovableDrives.Count -eq 0) {
        return
    }

    Print-Header 'Bootable Media'
    foreach ($Volume in $RemovableDrives) {
        $DriveLetter = $Volume.DriveLetter

        $EFI_BootFile = "${DriveLetter}:\EFI\boot\boot${Arch}.efi"
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

        if (Test-Path $EFI_BootFile) {
            $PFXCert = Get-PFXCert $EFI_BootFile

            if ((Validate-PFXCert $PFXCert) -eq 'BANNED') {
                '{0}Boot File [{1}] {2} BANNED.' -f $Tab8, ($PFXCert -replace 'Microsoft Windows '), $Verb
            }
            else {
                $BootMgrEX_File_Hash = (Get-FileHash $BootMgrEX_File).Hash
                $EFI_BootFile_Hash = (Get-FileHash -LiteralPath $EFI_BootFile).Hash

                if ($UEFI_DBXSVN -and ($EFI_BootFile_Hash -ne $BootMgrEX_File_Hash)) {
                    '{0}Boot File [{1}] {2} BANNED.' -f $Tab8, ($PFXCert -replace 'Microsoft Windows '), $Verb
                }
                else {
                    '{0}Boot File [{1}] {2} ALLOWED.' -f $Tab8, ($PFXCert -replace 'Microsoft Windows '), $Verb
                }
            }

            if ($Verbose) {
                "{0}boot${Arch}.efi File version: {1}`n" -f $Tab12, (Get-ProductVersion $EFI_BootFile)
            }
        }

        if (Test-Path $Boot_WIM) {
            try {
                $Index = (Get-WindowsImage -ImagePath $Boot_WIM -Name *Setup*).ImageIndex

                if ($Index -eq $null) {
                    $Index = (Get-WindowsImage -ImagePath $Boot_WIM).Count
                }

                Check-BootManager -WIM_File $Boot_WIM -Index $Index
            }
            catch {
                $ErrorMessage = $_.Exception.Message

                if ($ErrorMessage -ne 'There is no matching image.') {
                    $ErrorMessage
                }
            }
        }

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
                        Check-BootManager -WIM_File $ImageFile -Index $i
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
            }
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

    $SystemDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'

    # Force refresh of reg key 'WindowsUEFICA2023Capable'
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"

    if ($Verbose) {
        $CurrentBuild = $CurrentVersion.CurrentBuildNumber
        "Windows {0} {1} ({2}.{3})`n" -f $(if ($CurrentBuild -lt 22000) { '10' } else { '11' }), $CurrentVersion.DisplayVersion, $CurrentBuild, $CurrentVersion.UBR
    }

    $SecureBoot = Confirm-SecureBootUEFI
    $Verb = 'is'

    switch ($SecureBoot) {
        $true { 'Secure Boot: ON' }

        $false {
            if ($Audit) {
                'Secure Boot: OFF (Audit Report runs as ON)'
                $SecureBoot = $true
                $Verb = 'will be'
            }
            else {
                'Secure Boot: OFF'
            }
        }

        default {
            "ERROR: This PC doesn't support Secure Boot.`n"
            exit 1
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

    if ($Verbose) {
        $Model = '{0} {1}' -f ($System.Manufacturer -split ',')[0], $System.Model
        $BIOS_Version = $BIOS.SMBIOSBIOSVersion
        $BIOS_Date = $BIOS.ReleaseDate.ToString('yyyy-MM-dd')

        Print-Header 'BIOS Firmware'
        '{0}{1}' -f $Tab4, $Model
        '{0}Version: {1}' -f $Tab4, $BIOS_Version
        '{0}Date: {1}' -f $Tab4, $BIOS_Date
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

    if ((((Get-SecureBootUEFI SetupMode).Bytes -Join '') -eq 1) -or ($PK_BytesCount -eq 0 -and $KEK_BytesCount -eq 0 -and $db_BytesCount -eq 0 -and $dbx_BytesCount -eq 0)) {
        if (-not $Verbose) {
            "`nUEFI is in Setup Mode (NO CERTS)"
        }

        $SetupMode = $true
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
        Write-Host 'ERROR: Failed to read UEFI Secure Boot settings.' -Foreground Red
        $_.Exception.Message
        exit 1
    }

    $PK_Trusted = Check-TrustedPK

    if ($Verbose) {
        Print-UEFICerts -Name 'Default PK' -CertArray ([ref]$PKDefault_Cert)
    }

    if ((-not $SetupMode -and -not $PK_Trusted) -or $Verbose) {
        Print-UEFICerts -Name 'PK' -CertArray ([ref]$PK_Cert)

        if ($PK_Cert -ne $null -and -not $PK_Trusted) {
            '{0}Platform Key is UNTRUSTED.' -f $Tab8
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
                Write-Host $_ -Foreground Red
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
        Print-UEFICerts -Name 'Default DBX' -CertArray ([ref]$dbxDefault_Certs)
        '{0}EFI_CERT_SHA256_GUID Signatures: {1}' -f $Tab4, (Get-SecureBootUEFI -Name dbxDefault | Get-UEFIDatabaseSignatures | where { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' }).SignatureList.Count
    }

    if (-not $SetupMode -or $Verbose) {
        Print-UEFICerts -Name 'DBX' -CertArray ([ref]$dbx_Certs)
    }

    $DBX_BootMgrSVN = Get-SecureBootUEFI_DBXSVN $EFI_BOOTMGR_DBXSVN_GUID

    if ($DBX_BootMgrSVN -ne $null) {
        '{0}Windows BootMgr SVN {1}' -f $Tab4, $DBX_BootMgrSVN
    }

    if ($Verbose) {
        if ($DBX_BootMgrSVN -eq $null) {
            '{0}Windows BootMgr SVN is MISSING.' -f $Tab4
        }

        if ($dbx_BytesCount -ne 0) {
            '{0}EFI_CERT_SHA256_GUID Signatures: {1}' -f $Tab4, (Get-SecureBootUEFI -Name dbx | Get-UEFIDatabaseSignatures | where { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' }).SignatureList.Count
        }
        else {
            '{0}EFI_CERT_SHA256_GUID Signatures: 0' -f $Tab4
        }
    }

    $SystemDisk = (Get-Disk | Where-Object {$_.IsSystem -eq $true}).Number
    $GUID = (Get-Partition -DiskNumber $SystemDisk | Where-Object { $_.Type -eq 'System' }).Guid

    $EFI_Path = "\\?\Volume$GUID\EFI"

    $BootMgrEX_File = "$env:SystemRoot\Boot\EFI_EX\bootmgfw_EX.efi"
    $SkuSiPolicy_File = "$env:SystemRoot\System32\SecureBootUpdates\SkuSiPolicy.p7b"

    $BootMgr_File = "$EFI_Path\Microsoft\Boot\bootmgfw.efi"
    $EFI_SkuSiPolicy_File = "$EFI_Path\Microsoft\Boot\SkuSiPolicy.p7b"

    $PFXCert = Get-PFXCert $BootMgr_File

    Print-Header 'EFI Files'

    if ((Validate-PFXCert $PFXCert) -eq 'BANNED') {
        '{0}Disk {1}: Windows Boot Manager [{2}] {3} BANNED.' -f $Tab4, $SystemDisk, ($PFXCert -replace 'Microsoft Windows '), $Verb
    }
    else {
        $BootMgrEX_File_Hash = (Get-FileHash $BootMgrEX_File).Hash
        $BootMgr_File_Hash = (Get-FileHash -LiteralPath $BootMgr_File).Hash

        if ($UEFI_DBXSVN -and ($BootMgr_File_Hash -ne $BootMgrEX_File_Hash)) {
            '{0}Disk {1}: Windows Boot Manager [{2}] {3} BANNED.' -f $Tab4, $SystemDisk, ($PFXCert -replace 'Microsoft Windows '), $Verb
        }
        else {
            '{0}Disk {1}: Windows Boot Manager [{2}] {3} ALLOWED.' -f $Tab4, $SystemDisk, ($PFXCert -replace 'Microsoft Windows '), $Verb
        }
    }

    if ($Verbose) {
        "{0}bootmgfw.efi File version: {1}" -f $Tab8, (Get-ProductVersion $BootMgr_File)
    }

    $WindowsUEFICA2023Capable = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name WindowsUEFICA2023Capable -ErrorAction SilentlyContinue

    if ($WindowsUEFICA2023Capable -ne $null) {
        "`n{0}Registry: WindowsUEFICA2023Capable = {1}" -f $Tab4, $WindowsUEFICA2023Capable

        switch ($WindowsUEFICA2023Capable) {
            0  { '{0}[Windows UEFI CA 2023] not in UEFI DB.' -f $Tab8 }
            1  { '{0}[Windows UEFI CA 2023] in UEFI DB.' -f $Tab8 }
            2  { '{0}[Windows UEFI CA 2023] in UEFI DB, and Windows starting from CA 2023 Boot Manager.' -f $Tab8 }
            default { '{0}Unknown status.' -f $Tab8 }
        }
    }

    if ($VBS_Enabled) {
        if ((Test-Path -LiteralPath $EFI_SkuSiPolicy_File)) {
            $SkuSiPolicy_File_Hash = (Get-FileHash $SkuSiPolicy_File).Hash
            $EFI_SkuSiPolicy_File_Hash = (Get-FileHash -LiteralPath $EFI_SkuSiPolicy_File).Hash

            if ($EFI_SkuSiPolicy_File_Hash -eq $SkuSiPolicy_File_Hash) {
                "`n{0}Disk {1}: SkuSiPolicy.p7b (for VBS) is CURRENT." -f $Tab4, $SystemDisk
            }
            else {
                "`n{0}Disk {1}: SkuSiPolicy.p7b (for VBS) is WRONG VERSION." -f $Tab4, $SystemDisk
            }
        }
        else {
            "`n{0}Disk {1}: SkuSiPolicy.p7b (for VBS) is NOT PRESENT." -f $Tab4, $SystemDisk
        }
    }

    if ($BootMedia) {
        Check-BootMedia
    }

    $CheckList = Audit-UEFI

    if ($Audit) {
        Print-Header -Bold "`nAUDIT REPORT"
    
        if ($CheckList -ne $null) {
            $CheckList.TrimEnd("`n")
        }
        else {
            Write-Output ''
        }
    }

    switch ($UpdateFlags) {
        0x100 {
            $UpdateMessage = 'To install Windows Boot Manager [UEFI CA 2023]'
        }
        default {
            if ($RevokeFlags) {
                $UpdateMessage = 'To install [UEFI CA 2023] certs WITHOUT REVOKING the [PCA 2011] cert'
            }
            else {
                $UpdateMessage = 'To install [UEFI CA 2023] certs'
            }
        }
    }

    if ($RevokeFlags) {
        if ($UpdateFlags) {
            $RevokeMessage = 'To install [UEFI CA 2023] certs and REVOKE the [PCA 2011] cert'
        }
        else {
            $RevokeMessage = 'To revoke the [PCA 2011] cert, run the commands'
        }
    }

    if ($UpdateFlags -or $RevokeFlags -or $UpdateSkuSiPolicy) {
        if ($BitLocker_Enabled -and $UpdateFlags -ne 0x100) {
            $DeviceGuard_Running = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning

            if ($DeviceGuard_Running -eq 1) {
                $ManageBDE = "manage-bde -Protectors -Disable $SystemDrive -RebootCount 3"
            }
            else {
                $ManageBDE = "manage-bde -Protectors -Disable $SystemDrive -RebootCount 1"
            }
        }

        Print-Header -Bold "`nREQUIRED ACTION"

        if (('Microsoft Corporation KEK 2K CA 2023' -notin $KEK_Certs) -and ('Windows UEFI CA 2023' -in $db_Certs)) {
            "`nRun the command:`n{0}Update_UEFI-CA2023.ps1{1}`n" -f $Tab4, $(if ($RevokeFlags) { ' -Revoke' })

            if (-not $PK_Trusted) {
                "Finish the UEFI steps to manually add the Platform Key (PK) cert, if the script provided instructions.`n"
            }

            "Finish the UEFI steps to manually add the [KEK CA 2023] cert, if the script provided instructions.`n"

            break
        }

        if ($PK_Trusted -and (('Microsoft Corporation KEK 2K CA 2023' -in $KEK_Certs) -or $SignedKEK)) {
            $MergedFlags = $UpdateFlags -bor $RevokeFlags

            if ($UpdateFlags -and $RevokeFlags) {
                "`nOPTION 1:  DO NOTHING.  Windows will apply the UEFI updates in 2026 (supported BIOS)."

                "`nOPTION 2:  {0}, run the commands:`n" -f $UpdateMessage

                if ($ManageBDE -ne $null) { '{0}{1}' -f $Tab4, $ManageBDE }

                '{0}reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x{1:x} /f' -f $Tab4, $UpdateFlags
                '{0}powershell Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"' -f $Tab4

                "`nOPTION 3:  {0}, run the commands:`n" -f $RevokeMessage

                if ($ManageBDE -ne $null) { '{0}{1}' -f $Tab4, $ManageBDE }

                if ($UpdateFlags -eq 0x100) {
                    '{0}reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x{1:x} /f' -f $Tab4, $RevokeFlags
                }
                else {
                    '{0}reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x{1:x} /f' -f $Tab4, $MergedFlags
                }

                '{0}powershell Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"' -f $Tab4
            }
            elseif ($UpdateFlags) {
                "`n{0}, run the commands:`n" -f $UpdateMessage

                if ($ManageBDE -ne $null) { '{0}{1}' -f $Tab4, $ManageBDE }

                '{0}reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x{1:x} /f' -f $Tab4, $UpdateFlags
                '{0}powershell Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"' -f $Tab4
            }
            elseif ($RevokeFlags) {
                "`n{0}, run the commands:`n" -f $RevokeMessage

                if ($ManageBDE -ne $null) { '{0}{1}' -f $Tab4, $ManageBDE }

                '{0}reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x{1:x} /f' -f $Tab4, $RevokeFlags
                '{0}powershell Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"' -f $Tab4
            }

            if ($UpdateSkuSiPolicy) {
                "`nTo install SkuSiPolicy.p7b, run the command:"
                '{0}Update_UEFI-CA2023.ps1 -SkuSiPolicy' -f $Tab4
            }

        }
        else {
            if (-not $SetupMode) {
                "`nMANUAL UPDATE of the BIOS is required.`n"

                "Enter the BIOS menu, and search for User or Custom Mode option of updating the UEFI PK or KEK keys."
                "If your BIOS doesn't support this feature, select Setup Mode to clear all certs."
            }

            "`nOPTION 1:  To install [UEFI CA 2023] certs WITHOUT REVOKING the [PCA 2011] cert, run the command:`n"
            '{0}Update_UEFI-CA2023.ps1' -f $Tab4

            "`n`nOPTION 2:  To install [UEFI CA 2023] certs and REVOKE the [PCA 2011] cert, run the command:`n"
            '{0}Update_UEFI-CA2023.ps1 -Revoke' -f $Tab4
        }
    }
    else {
        Print-Header 'STATUS REPORT'
        $UEFICA2023Status = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name UEFICA2023Status -ErrorAction SilentlyContinue

        if ($UEFICA2023Status -ne $null) {
            "{0}Registry: UEFICA2023Status = {1}`n" -f $Tab4, $UEFICA2023Status
        }

        'SUCCESS: NO UPDATES ARE REQUIRED.'
    }
}

if ($Log) {
    $System = Get-CimInstance -ClassName Win32_ComputerSystem
    $LogFile = '{0}\{1} {2} Check-UEFI.log' -f $PSScriptRoot, (Get-Date -Format 'yyyy-MM-dd'), $System.Model.ToUpper()

    & $ScriptBlock | Tee-Object $LogFile
    "`nLog file saved as `"{0}`"`n" -f $LogFile
}
else {
    & $ScriptBlock
    Write-Output ''
}

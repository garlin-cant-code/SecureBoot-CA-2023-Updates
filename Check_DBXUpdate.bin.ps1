<#PSScriptInfo

.VERSION 2025.12.31

.GUID dbcc69b3-3e30-4e71-a1a9-29ef49f06afc

.AUTHOR garlin

.COPYRIGHT

.TAGS UEFI, Secure Boot, DBX, SVN, Windows Boot Manager

.RELEASENOTES

#>

<#
.SYNOPSIS
    Script to confirm every EFI_CERT_SHA256 signature read from a DBX Update .bin file, is contained in the UEFI DBX variable.

.DESCRIPTION
    Run this script to check if DBX Update files have been fully applied to UEFI DBX.

.PARAMETER Version
    Print the script's version number and exit.

.PARAMETER Verbose
    Download "dbx_info_msft_latest.json" from Microsoft's Secure Boot Objects GitHub, and identify unmatched EFI_CERT_SHA256 signatures
    by their signature hash, filename, vendor and revocation date.

    Identify if unmatched signatures contain a higher DBX SVN, than currently stored in UEFI DBX.

.PARAMETER Log
    Save script output to a file named "YYYY-MM-DD [Model] Check DBX.log"

.PARAMETER Paths
    Search a list of provided folder paths or individual filenames, for DBX Update files and check each file for confirmation that UEFI DBX
    contains every EFI_CERT_SHA256 signature in the file.

    Folder path defaults to "C:\Windows\System32\SecureBootUpdates".

.EXAMPLE
    Check_DBXUpdate.bin.ps1
.EXAMPLE
    Check_DBXUpdate.bin.ps1 \path\Folder1 \path\DBXUpdate2.bin
.EXAMPLE
    Check_DBXUpdate.bin.ps1 -Verbose -Log
#>

[CmdletBinding(DefaultParameterSetName='Default')]
param (
    [Parameter(Mandatory=$false,ParameterSetName='Version')]
    [switch]$Version,

    [Parameter(Mandatory=$false,ParameterSetName='Default')]
    [switch]$Log,

    [Parameter(Mandatory=$false,ParameterSetName='Default',DontShow,ValueFromRemainingArguments=$true)]
    [string[]]$Paths = @()
)

$ScriptVersion = '2025.12.31'

# https://github.com/microsoft/secureboot_objects/blob/main/Archived/dbx_info_msft_4_09_24_svns.csv
$EFI_BOOTMGR_DBXSVN_GUID = '01612B139DD5598843AB1C185C3CB2EB92'
$EFI_CDBOOT_DBXSVN_GUID =  '019D2EF8E827E15841A4884C18ABE2F284'
$EFI_WDSMGR_DBXSVN_GUID =  '01C2CA99C9FE7F6F4981279E2A8A535976'

$DBXinfo_URL = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/DBX/dbx_info_msft_latest.json'

$Tab4 = ' ' * 4

if ($Version) {
    '{0} (version {1}){2}' -f $MyInvocation.MyCommand.Name, $ScriptVersion, $(if ($MyInvocation.Line -ne '') { "`n" })
    exit 0
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($PSVersionTable.PSVersion.Major -gt 5) {
        $PS = 'pwsh'
    }
    else {
        $PS = 'powershell'
    }

    $args = ($MyInvocation.BoundParameters.Keys.GetEnumerator() | where { $_ -ne 'Paths' } | foreach { '-{0}' -f $_ }) -join ' '

    if ($MyInvocation.BoundParameters.'Paths' -ne $null) {
        $args += ' ' + ($MyInvocation.BoundParameters.'Paths' | foreach { '"{0}"' -f (Get-Item $_ -ErrorAction SilentlyContinue).FullName }) -join ' '
    }

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

    $SignatureTypeMapping = @{
        'C1C41626-504C-4092-ACA9-41F936934328' = 'EFI_CERT_SHA256_GUID' # Most often used for dbx
        'A5C059A1-94E4-4AA7-87B5-AB155C2BF072' = 'EFI_CERT_X509_GUID'   # Most often used for db
    }

    $Bytes = $null

    if ($Filename)
    {
        $Bytes = Get-Content -Encoding Byte $Filename -ErrorAction Stop
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
                    $SignatureData = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,([Byte[]] $SignatureDataBytes[16..($SignatureDataBytes.Count - 1)]))
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

function Compare-DBXSignatureData {
    <#
        .SYNOPSIS
        Parses EFI signatures from a DBX Update .bin file and compares the entire list against the current UEFI DBX.

        .DESCRIPTION
        From https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0#file-check-dbx-ps1
        Modified by github.com/cjee21
        Modified by github.com/garlin-cant-code

        .PARAMETER InputObject
        [PSCustomObject] containing list of signed DBX Update filenames

        .OUTPUTS
        List of unmatched DBX signatures
    #>

    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$InputObject
    )

    $DBXUpdateFile = $InputObject.FullPath

    if ($HidePath) {
        $Filename = '"{0}"' -f (Split-Path $InputObject.FullPath -Leaf)
    }
    else {
        $Filename = '"{0}"' -f $InputObject.RelativePath
    }

    if (-not (Test-Path $DBXUpdateFile)) {
        Write-Host "DBX update file `"$DBXUpdateFile`" not found." -Foreground Red
    }

    try {
        $RequiredSignatures = Get-UEFIDatabaseSignatures -BytesIn ([IO.File]::ReadAllBytes($DBXUpdateFile)) | where { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' }
    }
    catch {
        Write-Host "No EFI_CERT_SHA256 signatures in $DBXUpdateFile" -Foreground Red
        return $null
    }

    $RequiredSignatureData = $RequiredSignatures.SignatureList.SignatureData
    $RequiredCount = $RequiredSignatureData.Count

    if ($RequiredCount -eq 0) {
        Write-Host "No DBX signatures in $DBXUpdateFile" -Foreground Red
        return $null
    }

    $Matched = 0
    $MissingSigList = $null

    foreach ($RequiredSig in $RequiredSignatureData) {
        if ($DBXSignatureData -contains $RequiredSig) {
            $Matched++

            switch ($RequiredSig) {
                { $_ -match "^$EFI_BOOTMGR_DBXSVN_GUID" } { $SVN_SigCount++ }
                { $_ -match "^$EFI_CDBOOT_DBXSVN_GUID" }  { $SVN_SigCount++ }
                { $_ -match "^$EFI_WDSMGR_DBXSVN_GUID" }  { $SVN_SigCount++ }
                default { $EFI_SigCount++ }
             }
        }
        else {
            $RequiredSVN = Get-SignatureDataSVN $RequiredSig

            switch ($RequiredSig) {
                { $_ -match "^$EFI_BOOTMGR_DBXSVN_GUID" } {
                    $CurrentSVN = Get-SecureBootUEFI_DBXSVN $EFI_BOOTMGR_DBXSVN_GUID

                    if ($CurrentSVN -ge $RequiredSVN) {
                        $Matched++
                    }
                    else {
                        $MissingSigList += "{0}Missing [{1}] bootmgfw.efi SVN {2}`n" -f $Tab4, $RequiredSig, (Get-SignatureDataSVN $RequiredSig)
                    }
                }

                { $_ -match "^$EFI_CDBOOT_DBXSVN_GUID" } {
                    $CurrentSVN = Get-SecureBootUEFI_DBXSVN $EFI_CDBOOT_DBXSVN_GUID

                    if ($CurrentSVN -ge $RequiredSVN) {
                        $Matched++
                    }
                    else {
                        $MissingSigList += "{0}Missing [{1}] cdboot.efi SVN {2}`n" -f $Tab4, $RequiredSig, (Get-SignatureDataSVN $RequiredSig)
                    }
                }

                { $_ -match "^$EFI_WDSMGR_DBXSVN_GUID" } {
                    $CurrentSVN = Get-SecureBootUEFI_DBXSVN $EFI_WDSMGR_DBXSVN_GUID

                    if ($CurrentSVN -ge $RequiredSVN) {
                        $Matched++
                    }
                    else {
                        $MissingSigList += "{0}Missing [{1}] wdsmgfw.efi SVN {2}`n" -f $Tab4, $RequiredSig, (Get-SignatureDataSVN $RequiredSig)
                    }
                }

                default {
                    if ($Verbose) {
                        $MissingSig = $JSON.images.$Arch | where { $_.authenticodeHash -eq $RequiredSig }

                        if ($MissingSig -ne $null) {
                            if ($MissingSig.filename -eq '') {
                                $MissingSig.filename = '(none)'
                            }

                            $Columns = ('{0} {1} {2}' -f $MissingSig.filename, $MissingSig.companyName, $MissingSig.dateOfAddition) -replace '  '
                            $MissingSigList += "{0}Missing [{1}] {2}`n" -f $Tab4, $MissingSig.authenticodeHash, $Columns
                        }
                    }
                }
            }
        }
    }


    if ($EFI_SigCount -and $SVN_SigCount) {
        $SigType = 'EFI/SVN'
    }
    elseif ($EFI_SigCount) {
        $SigType = 'EFI'
    }
    else {
        $SigType = 'SVN'
    }

    if ($Matched -eq $RequiredCount) {
        $Result = 'SUCCESS: Matched {0}/{1} {2} signatures from {3}' -f $Matched, $RequiredCount, $SigType, $Filename
        Write-Host $Result -ForegroundColor Green

        if ($Log) {
            $Result | Add-Content $LogFile
        }
    }
    else {
        $Result = 'FAILED: Missing {0}/{1} {2} signatures from {3}' -f ($RequiredCount - $Matched), $RequiredCount, $SigType, $Filename
        Write-Host $Result -ForegroundColor Red

        if ($Verbose) {
            $MissingSigList
        }

        if ($Log) {
            @($Result; if ($Verbose) { $MissingSigList }) | Add-Content $LogFile
        }
    }
}


switch ($env:PROCESSOR_ARCHITECTURE) {
    'amd64' { $Arch = 'x64' }
    'x86'   { $Arch = 'x86' }
    'arm64' { $Arch = 'aa64' }
    'arm'   { $Arch = 'aa32' }
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

if ($Verbose) {
    try {
        $JSON = (Invoke-WebRequest -UseBasicParsing -Uri $DBXinfo_URL).Content | ConvertFrom-Json
    }
    catch {
        $_.Exception.Message
        exit 1
    }
}

$System = Get-CimInstance -ClassName Win32_ComputerSystem
$LogFile = '{0}\{1} {2} Check-DBXUpdate.log' -f $PSScriptRoot, (Get-Date -Format 'yyyy-MM-dd'), $System.Model.ToUpper()

if (Test-Path $LogFile) {
    Remove-Item $LogFile -Force
}

if ($Paths.Count -eq 0) {
    $Paths = @("$env:SystemRoot\System32\SecureBootUpdates")
    $HidePath = $true
}

try {
    $DBXSignatureData = (Get-SecureBootUEFI dbx | Get-UEFIDatabaseSignatures).SignatureList.SignatureData
}
catch {
    if ($_.Exception.Message -eq 'Variable is currently undefined: 0xC0000100') {
        $Result = "FAILED: UEFI DBX variable is currently empty.`n"
        Write-Host $Result -Foreground Red

        if ($Log) {
            $Result | Add-Content $LogFile
        }

        exit 1
    }
    else {
        throw $_.Exception.Message
    }
}

$DBX_Files = @()
$SortKey = 0

foreach ($item in $Paths) {
    if ($item -match '^\.') {
        $Path = Resolve-Path $item -Relative

        if (Test-Path $Path -PathType Container) {
            foreach ($File in (Resolve-Path (Get-ChildItem $Path -File).FullName -Relative)) {
                if ($File -match 'dbx.*bin$') {
                    $DBX_Files += [PSCustomObject]@{
                        RelativePath = $File
                        FullPath = (Get-Item $File).FullName
                        SortKey = $SortKey++
                    }
                }
            }
        }
        else {
            $DBX_Files += [PSCustomObject]@{
                RelativePath = $Path
                FullPath = (Get-Item $Path).FullName
                SortKey = $SortKey++
            }
        }
    }
    else {
        $Path = (Resolve-Path $item).Path

        if (Test-Path $Path -PathType Container) {
            foreach ($File in (Get-ChildItem $Path -File).FullName) {
                if ($File -match 'dbx.*bin$') {
                    $DBX_Files += [PSCustomObject]@{
                        RelativePath = $File
                        FullPath = $File
                        SortKey = $SortKey++
                    }
                }
            }
        }
        else {
            $DBX_Files += [PSCustomObject]@{
                RelativePath = $Path
                FullPath = (Get-Item $Path).FullName
                SortKey = $SortKey++
            }
        }
    }
}

foreach ($File in ($DBX_Files | sort FullPath -Unique | sort SortKey)) {
    Compare-DBXSignatureData $File
}

if ($Log) {
    "`nLog file saved as `"{0}`"`n" -f $LogFile
}
else {
    Write-Output ''
}

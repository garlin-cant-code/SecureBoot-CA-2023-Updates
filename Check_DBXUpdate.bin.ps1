<#PSScriptInfo

$VERSION 2026.08.31

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

$ScriptVersion = '2026.08.31'

# https://github.com/microsoft/secureboot_objects/blob/main/Archived/dbx_info_msft_4_09_24_svns.csv
$EFI_BOOTMGR_SVN_GUID = '01612B139DD5598843AB1C185C3CB2EB92'
$EFI_CDBOOT_SVN_GUID =  '019D2EF8E827E15841A4884C18ABE2F284'
$EFI_WDSMGR_SVN_GUID =  '01C2CA99C9FE7F6F4981279E2A8A535976'

$DBXinfo_URL = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/DBX/dbx_info_msft_latest.json'

<#  April 2026 LCU's DBXupdate.bin retired (2) sets of EFI_CERT_SHA256_GUID's
        1. Microsoft 2023-05-01
        2. Canonical 2020-07-01
#>
$EFI_CERT_SHA256_GUID_RETIRED = @(
    '0328f7dd12b552efa7a9e083730333b85f3f4e83d39387fc531863b422f75cc8',  # Microsoft 2023-05-01
    '03df4500273c43189296f09d734977c882a008fc056f43c309b9d2351f31792e',  # Microsoft 2023-05-01
    '065d94b9ea00397a2addb747e1e0978e4de6bf175339778fb9b0760fec3d3b61',  # Microsoft 2023-05-01
    '09f7699631c18db0c33491eb4b3c65b8f279238c5fc5e3ab0ba52737dbbd26f3',  # Microsoft 2023-05-01
    '0a3c2072ef4fbdbf045e1876e855bb8ad5dd0809f66ad1442239a7d856ad908e',  # Microsoft 2023-05-01
    '0a620707acf23a4e6cdc357a1499e14852b605d9eb6186422f57d458e627d6c0',  # Microsoft 2023-05-01
    '0c0c78837fa767eb045b8199e1e20ad666f90928daeeb8f5e5253d8e7877fcb4',  # Microsoft 2023-05-01
    '0e44212badf40d6b8de3311e632045370588e0b23b7a480eb5dc10db65d1b4b3',  # Microsoft 2023-05-01
    '1364b7b94ab2a93e79d297ebf6ce0a30f7997e5929e408ef0d3b5d54c64e7b90',  # Microsoft 2023-05-01
    '13a1f37bedfb5417b6b737e2a3816c8fd587d74d836914b2b2edc9fd6ca30e58',  # Microsoft 2023-05-01
    '13dba28447fdbe3c8a24fee3eb88638ce1d8f97cd4925056c0ad0e91ca51237d',  # Microsoft 2023-05-01
    '1510988d3dcce120f22696a9e87b02e7fad6367ef4ae8bfd54cdb528a5c48e99',  # Microsoft 2023-05-01
    '16598ee39b716ed9e4765a44abf86906c9b25c25abf631cc78ece6f7211b0365',  # Microsoft 2023-05-01
    '17c2b5b96693cdc2951c89dde641d14716063f5fc8795cebc635378b73044e8b',  # Microsoft 2023-05-01
    '19f4c7030ad74035f5bc07ace285bd7538f231d25787755d72071ede879c6978',  # Microsoft 2023-05-01
    '1da53f3a2c7c41c93099737266b5619ff616a433fb3b870234622d7aafab9a7a',  # Microsoft 2023-05-01
    '1eaed62c4abcb2524643e1723f6aadcc31a74af4d2285d3b13880cc44c22dec5',  # Microsoft 2023-05-01
    '21554d1f3bf9f52d3cd297d27df56215c0fd08a0bf673868f3d8c6c064dc5609',  # Microsoft 2023-05-01
    '21f27d89f2e77dee7cd4336e3a3ade362a2aae9fb2efe2079491a518f3d51fed',  # Microsoft 2023-05-01
    '23fcd6bf3084cee6a9f9885e5239230b0adde0c870589ee461551d1ca8f4e85b',  # Microsoft 2023-05-01
    '245e9b81342e45e1baf4f8d830d18ea7fae9fdff05497290ea6442c4ef0ffa57',  # Microsoft 2023-05-01
    '250ae0ba860d6d46894491d630d58b1ca008f695c92ce2084a295486f71f985b',  # Microsoft 2023-05-01
    '264cbc5765718a0bccb0f79c0fdd133a898203fb6f4f2052cb0647fbf6000ed0',  # Microsoft 2023-05-01
    '266c1429c8dc389481b3814bc3af8723db28eeceb0bb026bbbeda0cc41d36bc3',  # Microsoft 2023-05-01
    '2992068e4f616f2d7253e9d58116a97f22923f4dc1b78a58be4499b982ecf270',  # Microsoft 2023-05-01
    '2b1b9eccf585b11c5122651d7b94534bb131aa7c874e2262038b85db3ee83e4d',  # Microsoft 2023-05-01
    '2b21029fa033526d1dcd9e87ad8893f9b5a08987c3271b8a86716865de53d958',  # Microsoft 2023-05-01
    '3153b3e305575439914605d976cf6ead5a500e54d0b6abcdaafcced1bc47e04f',  # Microsoft 2023-05-01
    '326967c7ffc1b86db8b32b0570e88a89cc1534cfcf300b98c077e473f9b18fa1',  # Microsoft 2023-05-01
    '332450890f9c8fff7ec15c53921bf27227ab9ea06b0e1c816d819f8e21cfb55f',  # Microsoft 2023-05-01
    '36b7cdb6564c58cb54895b6d2c73f88d2908bcbd693bfd253945bd31e3ee81bc',  # Microsoft 2023-05-01
    '3860b7c7ff6f4bcd5865843b2e86b2eca5ff4fb071999f2129d4c7753b806f34',  # Microsoft 2023-05-01
    '399f9da6cf5a87839637b55f62bb2cc6a93fa5af7fe7ad76b4af0fb320c98127',  # Microsoft 2023-05-01
    '39abed2935891eef96e2b733bbc6951dafad1a4c6b500d2d9b28c358355a6ab8',  # Microsoft 2023-05-01
    '3b30c3e6a923cbb7cf65b539025f12b1c810d74480f25cbfcb9a7bfd633f06ed',  # Microsoft 2023-05-01
    '3b7696df627ade30bb15bdc5ce3f3c27240c973353e8551e7b036c90d01280c9',  # Microsoft 2023-05-01
    '3fe9f8d11edca3fc1899100484de4cc2c626abb38b73985a441b7c3a0d39ca54',  # Microsoft 2023-05-01
    '450effc827ca535a79d5c4ff3e1a3f614ca9126b3792f997d38791ca7399320c',  # Microsoft 2023-05-01
    '459457c48e1b450d8f22858ffb392fca78bb6f4da837862889ab798bdcbdf08f',  # Microsoft 2023-05-01
    '47f7a5f3821286a9c677f66cfe2a84d5ca94cb6fc1ebe8e1986e91edd58cbe33',  # Microsoft 2023-05-01
    '4a4873a319a3a3de35ea325771dffcbb31ec14550a4e029cf0feb9cd686b8c92',  # Microsoft 2023-05-01
    '50871141459a21faba3dbbf63da5aac8863fa3d8a9891f182ed72e3a74b64fdc',  # Microsoft 2023-05-01
    '52a3ca4db923c0648ac04be86ce02dbc6a3aaac8312366b106205dec6e2ca2d9',  # Microsoft 2023-05-01
    '54061ff50d91296f2f44d8b338aeedfbbe86df49db5de8a45191aaa931f5bcf6',  # Microsoft 2023-05-01
    '54c7d9c28672a1306e43ed7feed38b295f8eec279251f996fa293f68fc6cfb12',  # Microsoft 2023-05-01
    '57692fc2b80d809a3be409b44475dded7225c76fdd5ff09e4ed7d330a58733a5',  # Microsoft 2023-05-01
    '586898c60cff539b76d23dbf2c92e4105f6a7549e13f53d293708b793ca90d2d',  # Microsoft 2023-05-01
    '5a184e740657e218d635168286f0f70bb5672e4edb78717550c70686c232ea5b',  # Microsoft 2023-05-01
    '5a47b0b11d2fd9cd39c627d1e6bf4afed9601aa15d6a5d84fb10f39755d2d323',  # Microsoft 2023-05-01
    '5e2bb7bc8b16e0b9ddff75606668e69d76af1219c17180ef0a5b9b383f00b995',  # Microsoft 2023-05-01
    '5e67bf240b1d05f6f618908868a494c50a30ab255b06619fa28411eb260f674a',  # Microsoft 2023-05-01
    '5eb2c76843b253acbcecbb84767697128f000c18358c78c5baf135a5996c037f',  # Microsoft 2023-05-01
    '61535caa144761fc48cc9d7a835dfaf020b569edfc7fa628f983d58a3ac25f2a',  # Microsoft 2023-05-01
    '65625a143d220ea184dbd5cdfb1b9e9c3bd9654294eaa2b98628bc273ebc18b5',  # Microsoft 2023-05-01
    '6582dccb8b305efe0bbbafdcc7d295a6a8bf1df0397e1a8ac736e9098a2a64c0',  # Microsoft 2023-05-01
    '6730c911e6d91009420d202fb6f394568a06aa97e9f33f30c7e92aaa71332d68',  # Microsoft 2023-05-01
    '691ba3414e78622581bc519baf0bcb16fb262d3abbd8639f3e0eca2a29f99406',  # Microsoft 2023-05-01
    '6b54497ff9915a6977428bdf8f45b116d874c4f8a836b5bdfc373d05f4c0ef87',  # Microsoft 2023-05-01
    '6ce1f2986f0c46683ba07d296d0a84448ecf76c69db183fe29c36eed8f8e8f2f',  # Microsoft 2023-05-01
    '6cfddb6203f254d38a5bcdd4173d51647a487ca70ab21326aca0a03bb3d2bac0',  # Microsoft 2023-05-01
    '6d174dc1673f7cfb6f1ea75d71739afde2b784e214e41ae6f5aa30f622a400c4',  # Microsoft 2023-05-01
    '6f53cd5bf434b19b4e14ca127c596752079d989fcc98bb7d7cf3155619ec347d',  # Microsoft 2023-05-01
    '71b601ee3746da7177726db84f5b417c9721583d2d88ad857bf368a54ff76bfa',  # Microsoft 2023-05-01
    '736afb5df29ec9c88532be9c620ef80901bf23e72f2d3488b757aff17e734ace',  # Microsoft 2023-05-01
    '74b39c206dc8a11cd196d5998d2996b6ad477d72eaf86e19a3dc14ec0eab0f1e',  # Microsoft 2023-05-01
    '77cdcfc9644f8f80ff407cde316ac235ddd1ada9c3b6a5aa9544db2d64b79fed',  # Microsoft 2023-05-01
    '7836465bdffae768efaedcbaa8b5787baf51b2792a020e80e341a3f824ff82ca',  # Microsoft 2023-05-01
    '7a0294ba07a2aee3648afc0daf2efd526a5b76349ec906f819c03bc217257638',  # Microsoft 2023-05-01
    '7b94f0505f37b19b432aba08be2e3e003038c02ceb531e169d460db60c351649',  # Microsoft 2023-05-01
    '7c09d8b90b72b7c2ccf1a413e335c2d1a25d75bb8541f9bc16b4c4e26bda6855',  # Microsoft 2023-05-01
    '7c7372a60d71e04879b8930c164944d96d3753e0a2924a31231d1d5fb97882f2',  # Microsoft 2023-05-01
    '7eac80a915c84cd4afec638904d94eb168a8557951a4d539b0713028552b6b8c',  # Canonical 2020-07-01
    '7f292bce8dc97b601ef1ea72bdf7d96a12a87782bb1b1c547f85c55c7b3ff035',  # Microsoft 2023-05-01
    '7f964730cfb7b8cea284e2e810212ff9b0ee18227f64427a095d6886493db0c4',  # Microsoft 2023-05-01
    '7fddfe06c44dc4302da54577353c18fdbe11b41cb3e6064ec1c116ee102fe080',  # Microsoft 2023-05-01
    '800423ceb7e4759621a62c729babc81f53259d95f76457224ad601542b7b26d4',  # Microsoft 2023-05-01
    '804e354c6368bb27a90fae8e498a57052b293418259a019c4f53a2007254490f',  # Canonical 2020-07-01
    '812eb0fa2df13a889549729cadbf1720b68f6c9e21955741b72802590af1b5ca',  # Microsoft 2023-05-01
    '815d98aee498cf27fd6648c7e02cfc0a4a88aa73237cbb2352fe38384a72683d',  # Microsoft 2023-05-01
    '84d75f7a8913d66db946eaf1480eaddec3063d27a6f625f040b406718abcac44',  # Microsoft 2023-05-01
    '85255700890931c5b71a73dff09ea5125cd702ea65f45b4054c1463e00173fdc',  # Microsoft 2023-05-01
    '87176a15e766bd06528ed91a61481c3b3cde65ee95115403f9ffc6d3a26d43d0',  # Microsoft 2023-05-01
    '8806cf0c7bd5df7e01d120f56734113be916e183755577bd48026c25db268680',  # Microsoft 2023-05-01
    '8a305c5fbe7c56f9e3214d7adb8f176341f4020f234f3c14e52335967a2d365f',  # Microsoft 2023-05-01
    '8cb4fdae88f4f492ac6c87716602366df1ac84224b85ab2d3949f5aee79cefeb',  # Microsoft 2023-05-01
    '8d5332b350577ab7b1987f93fda104b2090f6a62e262214264f554b6163e8050',  # Microsoft 2023-05-01
    '8ed8aa03199de7d541ccbb3009a2b1ff575219662d8b23fba7fdff02d80abd29',  # Microsoft 2023-05-01
    '8ede7732284dab4aa384606ca07be29e72fded094597261a2f6473494a8aca0a',  # Microsoft 2023-05-01
    '90a483526b4238c55bc5ded289d7c1d376109b9d5f3e93529eda75c4d451523a',  # Microsoft 2023-05-01
    '9141ea1a4e6bf1f4d72c28a1d0d124a928d5a7d36b14fc7e7e53ef442360ff99',  # Microsoft 2023-05-01
    '915009d1cf9d68b9e53064de82d4b70b58d2f014a03805cc406427d323d9fc35',  # Microsoft 2023-05-01
    '92185c264285741fa7f198cad8f307c60891ad932d9e3c2a08d92546ff7099ed',  # Microsoft 2023-05-01
    '92f858f6a02bd2014618b05d7759e34e7781b15c34c8814ba4c930b320f8db09',  # Microsoft 2023-05-01
    '9335c9dd7001a2ec4e322ab6a2d11e6c4cd4ef1644c00d6314b7ba5a26f9eb7d',  # Microsoft 2023-05-01
    '93f5233e9970a7db1e4c9aa2de2404636728e7c66c03f2bbe74b18b20a93ba96',  # Microsoft 2023-05-01
    '9414f5fa5853978c07fc6bb17a1ca9460fe443ffca021fa52c8672a94460f44f',  # Microsoft 2023-05-01
    '996c1d55955dfb3698869bdc2a700e6bcc762468716b5cbda7295cf98841220a',  # Microsoft 2023-05-01
    '9af92541e63eacbc5784bb44db66f9b60726174f4ec178c6ce32eaf647eebca2',  # Microsoft 2023-05-01
    '9ebda9554ad5bb9e3d5ce700f7c86d4f5b0d782bf1dbf30a6a7234749a5dd517',  # Microsoft 2023-05-01
    'a0107a564e93989c57044fd18aa85beb1258101ac3d9f6e10bf12c1c6573bc2b',  # Microsoft 2023-05-01
    'a330fde65c067a5f0b75c80d0a300767c301eb75e0cf9b4ee240f0d60b3dc503',  # Microsoft 2023-05-01
    'a4b3fee324d25c53fb5cb48630dc80dd7ee78c1aac8c8deea927396997e33bce',  # Microsoft 2023-05-01
    'a983e73e57bdf014c9a29331290ee87df37f97c81dbcc43c6c933fe2209c0bd5',  # Microsoft 2023-05-01
    'abee522892fa10b22208b4d1540184617bc9875c9e03e5353b4ff476577d918b',  # Microsoft 2023-05-01
    'ad16de1e2ba27196395124683b80efc186ee7e51d434f8ff67d973f46e8e602f',  # Microsoft 2023-05-01
    'ae1dca8aab7c4bdd21c5aa19a323f597bd1850445d76695cb2910cccb5f163b8',  # Microsoft 2023-05-01
    'b149b29e8211e24827fbe0168d30cb2619cd3365bd6f8173e7a731c5f702dcd9',  # Microsoft 2023-05-01
    'b420509d0d69b294633fd7ae2c36b2b549d45a6a863ef16843a1116a11127f56',  # Microsoft 2023-05-01
    'b4938ed2ff001b73ef31e5bbbebe1d6dbb7d9888a9fbe5251a52a5ed016652cf',  # Microsoft 2023-05-01
    'b67db8d53c925febadafce4356206c85f73e22456eae4ed6ee77f6a9e11a078c',  # Microsoft 2023-05-01
    'b97915da9f05277fa5687f8c41132df69152517f2ba252d466395b40d4f2d155',  # Microsoft 2023-05-01
    'bb44fd8cd04abc3b54e5ccea97ef81e70fd3933c34288d8b86f6ecb4f3ed1fde',  # Microsoft 2023-05-01
    'bfcaa41445f20b54aea650d03d7c39b77cd82a7a14824dc55aa587c4c0f742a3',  # Microsoft 2023-05-01
    'c1547cf902570207a9694b6b8e353fe41419db6a3802221ddf10fb8f86947804',  # Microsoft 2023-05-01
    'c3297e35c3a9efc4c051706aab77d29a26e62d9a38de256dffeb77a0eec8666a',  # Microsoft 2023-05-01
    'c470161a06e6b452253a623536924979cdd11838e08d8e4dc86f763732e64b0b',  # Microsoft 2023-05-01
    'c875ae8a8db5441a577172869a4ec6e71dace7a875f42a2fbba4b52f293499de',  # Microsoft 2023-05-01
    'cb95a4d2e0e02a5b56d059c9f223c2326753ea8c44d2e3fa6c4486629be387a9',  # Microsoft 2023-05-01
    'cc202e8f2753ec75c9eeaac65c9d39eea6faed570664e930e3815976cd332d91',  # Microsoft 2023-05-01
    'cc7396d1c306adfce49e70d7daf32d093a8f2febe2ac0576ba853770e11b3ef2',  # Microsoft 2023-05-01
    'ce1af9fcce6ad19c00d8236b23b03cf83c593c6184a08266e58fe95c6caa4d13',  # Microsoft 2023-05-01
    'ce65c29521cd8498fad962e5f70d55c5044366ec09c761a60cc7c4a2001776a4',  # Microsoft 2023-05-01
    'ce8c44e185faaa03959cf23229607854ef7e316ed0773d66d7be5e0a48061de5',  # Microsoft 2023-05-01
    'cef75d1da8e991ac96d36f8a14562849207f9dd50fc63028ba83277d5c27d00b',  # Microsoft 2023-05-01
    'cf7f9e7d091023a1a1c3f5cbf7ddacf7b18f03a4d07961f71506fe9df4388eee',  # Microsoft 2023-05-01
    'cfd2a8f23bbce7424f4a6e27def368f17b086ffa226528900fa092736e705ef9',  # Microsoft 2023-05-01
    'd417c004525c7bb57523836278cee120fd66147983ba738aac011e24be75e6e2',  # Microsoft 2023-05-01
    'd5bc11fb619bfced64249b930c785ead5fca3927f0ce3c5efd3f1d9af04b37bf',  # Microsoft 2023-05-01
    'd87817f76309b1e420547808cb573aea0c8e7de14123793a42388582184286b7',  # Microsoft 2023-05-01
    'da9943277174960b0d7d3f0d656176f3723ed2f03a90518beb3c6c202b88cc14',  # Microsoft 2023-05-01
    'db1e5c6152a28d3eb6b1afeaad4974f3654ac6fbbe769d870abb74ede632b9e5',  # Microsoft 2023-05-01
    'dbb424cb8ad35ee68546092645c4689d6027a97fedf3c5af842b9572f1276997',  # Microsoft 2023-05-01
    'dc7cc8d1dc11e304abdf6e6227838f35b223b780f030de7b341e88a3f6a361b4',  # Microsoft 2023-05-01
    'e11bdbfbac4736918c497798d6ed018f529726a6b1894be0658d1b9519538b22',  # Microsoft 2023-05-01
    'e2cf881cf07195454505047d74810ed79ae20dfd0f1593afbbf08270a486c038',  # Microsoft 2023-05-01
    'e637002526221bc32e477455b12f864f20b27c44679a2e78e5c56da1ffce8b41',  # Microsoft 2023-05-01
    'e7681f153121ea1e67f74bbcb0cdc5e502702c1b8cc55fb65d702dfba948b5f4',  # Canonical 2020-07-01
    'e7d9bdbcc68b5bed590c29b72dca2b96779b8b68b12a47ded074b8f1b32f8fbe',  # Microsoft 2023-05-01
    'e808a337ed6911ef561c27cabacabf4ea6d6e20fb70f5413b121ac251abcc10c',  # Microsoft 2023-05-01
    'e8818666b7e014b6e4820afaa84d5a84fa42cb5d2663c848d358b2913274ba21',  # Microsoft 2023-05-01
    'e9c71b7cd5a4df0ba48d2ca48e6c468e657257f73f66017de45e18ee746ed7d5',  # Microsoft 2023-05-01
    'ea9c72c1ce865e6044abff576fd712d4df3f5114318753efcfefed70ee586884',  # Microsoft 2023-05-01
    'f0b3d0d4c5457880e2d9b7728eb64bd288b5d4a26ec883f3c0941d8af29d9466',  # Microsoft 2023-05-01
    'f197a171a09ab640aa8ac4ff7ddfc88377a89fdbb3fee014abb9097d92575b67',  # Microsoft 2023-05-01
    'f1cad3ac005b57d6e22ea57b9ebe1ee9e5052bdda499f5f2c1364317de87a794',  # Microsoft 2023-05-01
    'f254087746fdb5d9d9eae6df458485752beb0fcf295c36d273511b45f7480287',  # Microsoft 2023-05-01
    'f4d8ead6c325030538d10ebb39f0efdc2f553794c14a5e45f9555c335925d9d3',  # Microsoft 2023-05-01
    'f51bc0b8fce1bae71b76cb3ade28b712669d4e938fd37c9f5872493acc25fae1',  # Microsoft 2023-05-01
    'f74947590a87a005023e9ef89cdf0c38d8d582ca4173f8201cebc443ef796790',  # Microsoft 2023-05-01
    'f8f38c4febe9d8e45e71a459c5bff171755c348d5f619f3c6ef30a3f8fd02bd1',  # Microsoft 2023-05-01
    'fb0bbc256aea5cf93da99cf26481cc42f4e7ba6b32db63b827620807e79e805c',  # Microsoft 2023-05-01
    'fd3062358e0e1dc4c3a60380ef1bdfd4c51f4473b8600937d921df472fbf9b65',  # Microsoft 2023-05-01
    'fd4591add2e5b0664363720c71492982d5b223a141a6248246cd2381f67e926c',  # Microsoft 2023-05-01
    'ffd7688e7d2b8c3c3140b415e728bbe7663c54e23bd288ff2cf4617835088f39'   # Microsoft 2023-05-01
)

$Tab4 = ' ' * 4
$Tab8 = ' ' * 8

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

    $args = ($MyInvocation.BoundParameters.Keys.GetEnumerator() | where { $_ -ne 'Paths' } | foreach { '-{0}' -f $_ }) -join ' '

    if ($MyInvocation.BoundParameters.'Paths' -ne $null) {
        $args += ' ' + ($MyInvocation.BoundParameters.'Paths' | foreach { '"{0}"' -f (Get-Item $_ -Force -ErrorAction SilentlyContinue).FullName }) -join ' '
    }

    Start-Process $PS -ArgumentList "-nop -ep bypass -NoLogo -NoExit -f `"$($MyInvocation.MyCommand.Path)`" $args" -Verb RunAs
    exit 0
}

if ($PSBoundParameters['Verbose']) {
    $Verbose = $true
    $VerbosePreference = 'SilentlyContinue'
}

switch ($env:PROCESSOR_ARCHITECTURE) {
    'amd64' { $Arch = 'x64' }
    'x86'   { if ($env:PROCESSOR_ARCHITEW6432) { $Arch = 'x64' } else { $Arch = 'ia32' } }
    'arm64' { $Arch = 'aarch64' }
}

$System = Get-CimInstance -ClassName Win32_ComputerSystem

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

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

function Get-SignatureDataSVN {
    param (
        [Parameter(Mandatory)]
        [string]$SignatureData
    )

    # https://github.com/microsoft/secureboot_objects/blob/main/scripts/utility_functions.py
    $SVN = '{0}.{1}' -f [System.Convert]::ToUInt16($SignatureData.Substring(40,2) + $SignatureData.Substring(38,2), 16), [System.Convert]::ToUInt16($SignatureData.Substring(36,2) + $SignatureData.Substring(34,2), 16)

    return $SVN
}

function Get-SecureBootUEFI_SVN {
    param (
        [Parameter(Mandatory)]
        [string]$SVN
    )

    try {
        $SignatureData = (Get-SecureBootUEFI dbx | Get-UEFIDatabaseSignatures).SignatureList.SignatureData
    }
    catch {
        if ($_.Exception.Message -match '0xC0000100') {
            return $null
        }
        else {
            throw $_.Exception.Message
        }
    }

    $LatestSVN = $SignatureData -match "^$SVN" | foreach { [version](Get-SignatureDataSVN $_) } | sort | select -Last 1

    if ($LatestSVN.Count) {
        $SVN = '{0}.{1}' -f $LatestSVN.Major, $LatestSVN.Minor
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
        [PSCustomObject]$InputObject,

        [Parameter(Mandatory=$false)]
        [bool]$ShowPath = $false
    )

    $DBXUpdate_File = $InputObject.FullPath

    if ($ShowPath) {
        $Filename = '"{0}"' -f (Split-Path $InputObject.FullPath -Leaf)
    }
    else {
        $Filename = '"{0}"' -f $InputObject.RelativePath
    }

    if (-not (Test-Path $DBXUpdate_File)) {
        Write-Host "DBX update file `"$DBXUpdate_File`" not found." -ForegroundColor Red
    }

    try {
        $RequiredSignatures = Get-UEFIDatabaseSignatures -BytesIn ([IO.File]::ReadAllBytes($DBXUpdate_File)) | where { $_.SignatureType -eq 'EFI_CERT_SHA256_GUID' }
    }
    catch {
        Write-Host "No EFI_CERT_SHA256 signatures in $DBXUpdate_File" -ForegroundColor Red
        return $null
    }

    $RequiredSignatureData = $RequiredSignatures.SignatureList.SignatureData
    $RequiredCount = $RequiredSignatureData.Count

    if ($RequiredCount -eq 0) {
        Write-Host "No DBX signatures in $DBXUpdate_File" -ForegroundColor Red
        return $null
    }

    $Matched = 0
    $Retired_Count = 0
    $MissingSigList = $null

    foreach ($RequiredSig in $RequiredSignatureData) {
        if ($DBXSignatureData -contains $RequiredSig) {
            $Matched++

            switch -Regex ($RequiredSig) {
                "^$EFI_BOOTMGR_SVN_GUID"  { $SVN_SigCount++ }
                "^$EFI_CDBOOT_SVN_GUID"   { $SVN_SigCount++ }
                "^$EFI_WDSMGR_SVN_GUID"   { $SVN_SigCount++ }
                default { $EFI_SigCount++ }
             }
        }
        else {
            $RequiredSVN = Get-SignatureDataSVN $RequiredSig

            switch -Regex ($RequiredSig) {
                "^$EFI_BOOTMGR_SVN_GUID" {
                    $CurrentSVN = Get-SecureBootUEFI_SVN $EFI_BOOTMGR_SVN_GUID

                    if ($CurrentSVN -ge $RequiredSVN) {
                        $Matched++
                    }
                    else {
                        $MissingSigList += "{0}Missing [{1}] bootmgfw.efi SVN {2}`n" -f $Tab4, $RequiredSig, (Get-SignatureDataSVN $RequiredSig)
                    }
                }

                "^$EFI_CDBOOT_SVN_GUID" {
                    $CurrentSVN = Get-SecureBootUEFI_SVN $EFI_CDBOOT_SVN_GUID

                    if ($CurrentSVN -ge $RequiredSVN) {
                        $Matched++
                    }
                    else {
                        $MissingSigList += "{0}Missing [{1}] cdboot.efi SVN {2}`n" -f $Tab4, $RequiredSig, (Get-SignatureDataSVN $RequiredSig)
                    }
                }

                "^$EFI_WDSMGR_SVN_GUID" {
                    $CurrentSVN = Get-SecureBootUEFI_SVN $EFI_WDSMGR_SVN_GUID

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
                        else {
                            $MissingSigList += "{0}Missing [{1}]`n" -f $Tab4, $RequiredSig
                        }
                    }

                    if ($EFI_CERT_SHA256_GUID_RETIRED -contains $RequiredSig) {
                        $Retired_Count++
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
        $Missing = $RequiredCount - $Matched

        if ($Retired_Count) {
            $Result1 = 'FAILED: Missing {0}/{1} {2} signatures from {3}' -f $Missing, $RequiredCount, $SigType, $Filename
            Write-Host $Result1 -ForegroundColor Red

            $Active_Count = $Missing - $Retired_Count

            if ($Active_Count) {
                $Result2 = '{0}Microsoft retired {1}/{2} of missing signatures (April 2026). {3} signatures are still required' -f $Tab4, $Retired_Count, $Missing, $Active_Count
            }
            else {
                $Result2 = '{0}Microsoft retired all of the missing {1} signatures (April 2026)' -f $Tab4, $Retired_Count
            }

            Write-Host $Result2 -ForegroundColor Yellow
            $Result = "{0}`n{1}" -f $Result1, $Result2
        }
        else {
            $Result = 'FAILED: Missing {0}/{1} {2} signatures from {3}' -f $Missing, $RequiredCount, $SigType, $Filename
            Write-Host $Result -ForegroundColor Red
        }

        if ($Verbose) {
            $MissingSigList -replace "`n$"
        }

        if ($Log) {
            @($Result; if ($Verbose) { $MissingSigList }) | Add-Content $LogFile
        }
    }
}

if ($Verbose) {
    try {
        $JSON = (Invoke-WebRequest -UseBasicParsing -Uri $DBXinfo_URL).Content | ConvertFrom-Json
    }
    catch {
        $_.Exception.Message
        exit 1
    }
}

$LogFile = '{0}\{1} {2} Check-DBXUpdate.log' -f $PSScriptRoot, (Get-Date -Format 'yyyy-MM-dd'), ($System.Model.ToUpper().Split([IO.Path]::GetInvalidFileNameChars()) -join '_')

if (Test-Path $LogFile) {
    Remove-Item $LogFile -Force
}

$Paths = $Paths -notmatch '^-'

if ($Paths.Count -eq 0) {
    if ([Environment]::Is64BitProcess) {
        $Paths = @("$env:SystemRoot\System32\SecureBootUpdates")
    }
    else {
        $Paths = @("$env:SystemRoot\SysNative\SecureBootUpdates")
    }

    $ShowPath = $true
}
else {
    $ShowPath = $false
}

try {
    $DBXSignatureData = (Get-SecureBootUEFI dbx | Get-UEFIDatabaseSignatures).SignatureList.SignatureData
}
catch {
    if ($_.Exception.Message -match '0xC0000100') {
        $Result = "UEFI DBX variable is currently empty.`n"
        Write-Host $Result -ForegroundColor Red

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
    try {
        $null = Get-Item $item -Force -ErrorAction Stop
    }
    catch {
        'Skipping file or folder path: "{0}"' -f $item
        continue
    }

    if ($item -match '^\.') {
        $Path = Resolve-Path $item -Relative

        if (Test-Path $Path -PathType Container) {
            foreach ($File in (Resolve-Path (Get-ChildItem $Path -Force -File).FullName -Relative)) {
                if ($File -match '(.*dbx.*)\.bin$') {
                    $DBX_Files += [PSCustomObject]@{
                        RelativePath = $File
                        FullPath = (Get-Item $File -Force).FullName
                        SortKey = $SortKey++
                    }
                }
            }
        }
        else {
            $DBX_Files += [PSCustomObject]@{
                RelativePath = $Path
                FullPath = (Get-Item $Path -Force).FullName
                SortKey = $SortKey++
            }
        }
    }
    else {
        if (-not [Environment]::Is64BitProcess) {
            $item = $item -replace 'System32\\SecureBootUpdates','SysNative\SecureBootUpdates'
        }

        $Path = (Resolve-Path $item).Path

        if (Test-Path $Path -PathType Container) {
            foreach ($File in (Get-ChildItem $Path -File -Force).FullName) {
                if ($File -match '(.*dbx.*)\.bin$') {
                    $regex = "$env:SystemRoot\System32\SecureBootUpdates|$env:SystemRoot\SysNative\SecureBootUpdates" -replace '\\','\\'

                    if ($File -match 'Legacy' -and $Path -match $regex) {
                        continue
                    }

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
                FullPath = (Get-Item $Path -Force).FullName
                SortKey = $SortKey++
            }
        }
    }
}

foreach ($File in ($DBX_Files | sort FullPath -Unique | sort SortKey)) {
    Compare-DBXSignatureData $File -ShowPath $ShowPath
}

if ($Log) {
    "`nLog file saved as `"{0}`"`n" -f $LogFile
}
else {
    Write-Output ''
}

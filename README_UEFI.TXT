Manual installation of [Windows OEM Devices PK]
===============================================

1. Shutdown Windows, and enter your UEFI's Secure Boot menu.

2. Enter "PK Options / Enroll PK / Enroll PK Using File" or "Key Management / PK Management / Set Key".
   The menu options may be different for your BIOS.

   - Browse the system drive's EFI partition
   - Enter the <EFI> folder
   - Enter the <Certs> sub-folder

3. Find the file "WindowsOEMDevicesPK.der".  Add the certificate.

4. Enter "KEK Options / Enroll KEK / Enroll KEK Using File" or "Key Management / KEK Management / Append Key".
   The menu options may be different for your BIOS.

   - Browse the system drive's EFI partition
   - Enter the <EFI> folder
   - Enter the <Updates> sub-folder

5. Find the file "Microsoft Corporation KEK 2K CA 2023.der".  Add this certificate.

6. Save changes and exit.

7. Start Windows, and re-run the 'Update-UEFI_CA2023.ps1' script.


Manual installation of [KEK 2K CA 2023]
=======================================

1. Shutdown Windows, and enter your UEFI's Secure Boot menu.

2. Enter "KEK Options / Enroll KEK / Enroll KEK Using File" or "Key Management / KEK Management / Append Key".
   The menu options may be different for your BIOS.

   - Browse the system drive's EFI partition
   - Enter the <EFI> folder
   - Enter the <Certs> sub-folder

3. Find the file "Microsoft Corporation KEK 2K CA 2023.der".  Add this certificate.
   If you encounter an error, try the file "Microsoft Corporation KEK 2K CA 2023.crt".

4. Save changes and exit.

5. Start Windows, and re-run the 'Update-UEFI_CA2023.ps1' script.



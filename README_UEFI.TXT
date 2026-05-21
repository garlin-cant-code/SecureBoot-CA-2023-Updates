Manual installation of [Windows OEM Devices PK]
===============================================

1. WARNING: Disable Windows Hello PIN for all users, before proceeding.  Otherwise TPM will detect
   recent changes to Secure Boot and invalidate your PIN.

2. Shutdown Windows, and enter your UEFI's Secure Boot menu.

3. Enter "PK Options / Enroll PK / Enroll PK Using File" or "Key Management / PK Management / Set Key".
   The menu options may be different for your BIOS.

   - Browse the system drive's EFI partition
   - Enter the <EFI> folder
   - Enter the <Certs> sub-folder

4. Find the file "WindowsOEMDevicesPK.der".  Add the certificate.

5. Enter "KEK Options / Enroll KEK / Enroll KEK Using File" or "Key Management / KEK Management / Append Key".
   The menu options may be different for your BIOS.

   - Browse the system drive's EFI partition
   - Enter the <EFI> folder
   - Enter the <Updates> sub-folder

6. Find the file "Microsoft Corporation KEK 2K CA 2023.der".  Add this certificate.

7. Save changes and exit.

8. Leave the BIOS in Custom Mode.

9. Start Windows, and re-run the 'Update-UEFI_CA2023.ps1' script.


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


NOTES FOR HP PC's
=================

Please check if your PC has HP Sure Start, which reverts any "unauthorized" changes to the Secure Boot keys.
Failure to follow these instructions may result in a boot loop.

Disabling HP Sure Start Secure Boot Keys Protection:

1. Disable Secure Boot and restart into BIOS.  A BIOS Admin password may be needed before you're allowed to use this option.

2. Disable Sure Start Secure Boot Keys Protection and restart BIOS.

3. Enable Clear Secure Boot Keys and restart Windows.  Run this step *only* if you have to be in Setup Mode, otherwise skip.

4. Run the update script.  Ignore any signature violation errors from writing the PK (in Setup Mode).

5. Enable Secure Boot and restart Windows.

6. Enable Sure Start.


NOTES FOR DELL PC's
===================

For instructions on the Dell BIOS menus, please read:
https://www.dell.com/support/kbdoc/en-us/000368610/how-to-update-secure-boot-active-database-from-bios

If manual key enrollment reports the KEK .der file is the wrong format, then manual enrollment will not work for
this BIOS version.

Use the "Delete All Keys" option in the UEFI menu, before running the 'Update_UEFI-CA2023.ps1' script.


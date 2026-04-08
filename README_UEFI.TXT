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

7. Leave the BIOS in Custom Mode.

8. Start Windows, and re-run the 'Update-UEFI_CA2023.ps1' script.


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

HP Sure Start Secure Boot Keys Protection

"With this setting at the factory default of enable, HP Sure Start provides enhanced protection of the
secure boot databases and keys used by BIOS to verify the integrity and authenticity of the OS bootloader
before launching it at boot. When set to "Disable", only standard UEFI secure boot variable protection
is used, and no backup copy is kept by the HP Sure Start subsystem."


NOTES FOR DELL PC's
===================

If manual key enrollment reports the KEK .der file is the wrong format, then manual enrollment will not
work for this BIOS version.

You must use the "Delete All Keys" option in the UEFI menu, and run the 'Update_UEFI-CA2023.ps1' script.

For more instructions on the Dell BIOS menus, please read:
https://www.dell.com/support/kbdoc/en-us/000368610/how-to-update-secure-boot-active-database-from-bios

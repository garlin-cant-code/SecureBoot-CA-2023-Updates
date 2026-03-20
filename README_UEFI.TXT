SECURE BOOT UEFI CA 2023 UPDATE - FULLY OFFLINE, ESU FREE, BIG-CRUNCH READY
==========================================================================

This toolkit is FULLY OFFLINE and ESU FREE.
No cloud dependency. No subscription gate. No enterprise lock-in.

Designed to work across EVERY Windows 10/11 environment targeted by this package,
so you can harden and update Secure Boot before a bad boot-chain day becomes a big crunch.

Critical timing note:
Applying this update path helps prevent Windows 10/11 computers from being blocked around June 2026 policy enforcement windows.
It is built to keep Secure Boot protections and core security features active, not weaken them.

What this means for you:
- Fully offline deployment and verification workflow
- ESU-FREE operation model for this update process
- Helps avoid June 2026 Windows 10/11 boot-blocking scenarios
- Keeps key security features and Secure Boot protections in place
- Practical scripts and fallback manual steps if firmware menus vary by vendor

Recommended flow:
1. Run the automated update/check scripts first.
2. If firmware blocks automation, use the manual certificate enrollment steps below.
3. Re-run the verification scripts and confirm success before broad rollout.


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



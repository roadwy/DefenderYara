
rule Trojan_Win32_SpyKeylogger_DE_MTB{
	meta:
		description = "Trojan:Win32/SpyKeylogger.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 6f 75 6e 74 76 6f 6c 20 5a 3a 20 2f 64 } //01 00  mountvol Z: /d
		$a_01_1 = {63 6f 70 79 20 42 4f 4f 54 58 36 34 2e 65 66 69 20 5a 3a 5c 45 46 49 5c 42 6f 6f 74 5c 42 4f 4f 54 58 36 34 2e 65 66 69 } //01 00  copy BOOTX64.efi Z:\EFI\Boot\BOOTX64.efi
		$a_01_2 = {63 6f 70 79 20 42 4f 4f 54 58 36 34 2e 65 66 69 20 5a 3a 5c 45 46 49 5c 4d 69 63 72 6f 73 6f 66 74 5c 42 6f 6f 74 5c 62 6f 6f 74 6d 67 66 77 2e 65 66 69 } //01 00  copy BOOTX64.efi Z:\EFI\Microsoft\Boot\bootmgfw.efi
		$a_01_3 = {43 75 73 74 6f 6d 4d 53 47 42 6f 78 2e 65 78 65 } //01 00  CustomMSGBox.exe
		$a_01_4 = {42 61 6e 61 6e 61 41 6e 74 69 6d 61 74 74 65 72 54 72 6f 6a 61 6e 2e 70 64 62 } //01 00  BananaAntimatterTrojan.pdb
		$a_81_5 = {54 61 73 6b 20 4d 61 6e 61 67 65 72 } //00 00  Task Manager
	condition:
		any of ($a_*)
 
}
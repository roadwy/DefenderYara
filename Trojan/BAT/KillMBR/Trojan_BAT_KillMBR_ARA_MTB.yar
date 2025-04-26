
rule Trojan_BAT_KillMBR_ARA_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 07 11 07 11 07 1a 63 11 07 1e 63 5f 11 07 1f 0a 63 61 5a d2 9c 11 07 17 58 13 07 11 07 11 06 8e 69 32 da } //2
		$a_01_1 = {50 6c 61 79 53 79 6e 63 } //2 PlaySync
		$a_01_2 = {53 6f 75 6e 64 50 6c 61 79 65 72 } //2 SoundPlayer
		$a_80_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_80_3  & 1)*1) >=7
 
}
rule Trojan_BAT_KillMBR_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 50 73 79 63 68 6f 6d 65 6d 65 2e 70 64 62 } //2 \Psychomeme.pdb
		$a_01_1 = {44 65 73 74 72 6f 79 42 6f 6f 74 4c 6f 61 64 65 72 } //2 DestroyBootLoader
		$a_01_2 = {44 65 73 74 72 6f 79 46 6f 6c 64 65 72 } //2 DestroyFolder
		$a_01_3 = {44 65 73 74 72 6f 79 46 69 6c 65 } //2 DestroyFile
		$a_01_4 = {54 61 6b 65 4f 77 6e 65 72 53 68 69 70 4f 66 46 69 6c 65 } //2 TakeOwnerShipOfFile
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}
rule Trojan_BAT_KillMBR_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 10 00 00 13 04 11 04 17 da 17 d6 8d ?? ?? ?? 01 0c 16 6a 0d 09 20 ?? ?? ?? 00 6a 31 02 2b 2c 06 08 08 8e b7 b8 08 8e b7 b8 13 05 12 05 7e ?? ?? ?? 0a 28 ?? ?? ?? 06 26 07 08 16 08 8e b7 6f ?? ?? ?? 0a 09 11 04 6a d6 0d 2b c9 } //2
		$a_80_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  2
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}
rule Trojan_BAT_KillMBR_ARA_MTB_4{
	meta:
		description = "Trojan:BAT/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {5c 50 6f 77 65 72 2e 70 64 62 } //\Power.pdb  2
		$a_80_1 = {50 6f 77 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Power.Properties.Resources  2
		$a_01_2 = {24 38 64 62 62 32 64 35 38 2d 62 39 64 65 2d 34 38 36 62 2d 62 65 38 33 2d 31 30 30 36 34 62 39 64 32 63 38 35 } //2 $8dbb2d58-b9de-486b-be83-10064b9d2c85
		$a_01_3 = {49 73 57 69 6e 64 6f 77 73 44 65 66 65 6e 64 65 72 49 6e 73 74 61 6c 6c 65 64 } //2 IsWindowsDefenderInstalled
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}
rule Trojan_BAT_KillMBR_ARA_MTB_5{
	meta:
		description = "Trojan:BAT/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {6f 6f 62 65 5c 77 69 6e 64 65 70 6c 6f 79 2e 65 78 65 } //oobe\windeploy.exe  2
		$a_80_1 = {74 72 6f 6a 61 6e 20 69 73 20 67 6f 69 6e 67 20 74 6f 20 72 65 62 6f 6f 74 20 79 6f 75 72 20 64 65 76 69 63 65 } //trojan is going to reboot your device  2
		$a_80_2 = {6f 76 65 72 77 72 69 74 65 20 74 68 65 20 4d 42 52 20 73 65 63 74 6f 72 } //overwrite the MBR sector  2
		$a_80_3 = {4c 6f 67 6f 6e 55 49 20 77 69 6c 6c 20 62 65 20 6f 76 65 72 77 72 69 74 74 65 6e } //LogonUI will be overwritten  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}
rule Trojan_BAT_KillMBR_ARA_MTB_6{
	meta:
		description = "Trojan:BAT/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 50 72 69 6d 61 72 79 53 63 72 65 65 6e } //1 get_PrimaryScreen
		$a_01_1 = {63 6c 65 61 72 5f 73 63 72 65 65 6e } //1 clear_screen
		$a_01_2 = {47 44 49 5f 70 61 79 6c 6f 61 64 73 } //1 GDI_payloads
		$a_01_3 = {72 65 67 5f 64 65 73 74 72 6f 79 } //1 reg_destroy
		$a_01_4 = {6d 62 72 5f 64 65 73 74 72 6f 79 } //1 mbr_destroy
		$a_01_5 = {64 65 73 74 72 75 63 74 69 76 65 5f 74 72 6f 6a 61 6e } //2 destructive_trojan
		$a_80_6 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  2
		$a_80_7 = {2f 6b 20 72 65 67 20 64 65 6c 65 74 65 20 48 4b 43 52 20 2f 66 } ///k reg delete HKCR /f  2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2) >=11
 
}
rule Trojan_BAT_KillMBR_ARA_MTB_7{
	meta:
		description = "Trojan:BAT/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 00 6b 00 20 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 20 00 26 00 26 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 33 00 30 00 20 00 26 00 26 00 20 00 73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 20 00 2f 00 73 00 20 00 2f 00 74 00 20 00 31 00 30 00 20 00 2f 00 63 00 } //2 /k taskkill /f /im explorer.exe && timeout 30 && shutdown /s /t 10 /c
		$a_01_1 = {2f 00 6b 00 20 00 72 00 64 00 20 00 43 00 3a 00 5c 00 20 00 2f 00 73 00 20 00 2f 00 71 00 } //2 /k rd C:\ /s /q
		$a_01_2 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } //2 \\.\PhysicalDrive0
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
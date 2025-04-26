
rule Trojan_Win32_KillMBR_ARA_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 99 f7 fe 8a f8 8b c1 99 8a df f7 ff 8b 45 ec fe cb 02 55 e4 41 32 d3 0a d7 8b 5d e0 88 10 83 c0 04 89 45 ec 3b cb 7c d6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_KillMBR_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 10 68 00 21 40 00 ff 15 ?? ?? ?? ?? 6a 00 8b f0 8d 45 f8 50 68 00 02 00 00 68 28 21 40 00 56 ff 15 ?? ?? ?? ?? 56 ff 15 } //2
		$a_80_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  2
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}
rule Trojan_Win32_KillMBR_ARA_MTB_3{
	meta:
		description = "Trojan:Win32/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 20 74 68 69 6e 6b 20 6d 62 72 20 77 69 6c 6c 20 64 69 65 } //2 I think mbr will die
		$a_01_1 = {54 68 69 73 20 69 73 20 61 20 76 69 72 75 73 21 } //2 This is a virus!
		$a_01_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //2 DisableTaskMgr
		$a_01_3 = {44 69 73 61 62 6c 65 43 4d 44 } //2 DisableCMD
		$a_01_4 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //2 \\.\PhysicalDrive0
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}
rule Trojan_Win32_KillMBR_ARA_MTB_4{
	meta:
		description = "Trojan:Win32/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 6f 6f 74 6c 6f 61 64 65 72 3a 20 53 75 63 63 65 73 66 75 6c 6c 79 20 6c 6f 61 64 65 64 } //2 Bootloader: Succesfully loaded
		$a_01_1 = {4d 65 6d 6f 72 79 20 72 65 67 69 6f 6e 3a 20 30 78 38 30 30 30 20 68 61 73 20 62 65 65 6e 20 6c 6f 61 64 65 64 2e 22 2c 31 33 2c 31 30 2c 31 33 2c 31 30 2c } //2 Memory region: 0x8000 has been loaded.",13,10,13,10,
		$a_01_2 = {52 65 73 65 74 20 64 69 73 6b 20 73 79 73 74 65 6d } //2 Reset disk system
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_Win32_KillMBR_ARA_MTB_5{
	meta:
		description = "Trojan:Win32/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {40 72 65 67 20 64 65 6c 65 74 65 20 22 48 4b 45 59 5f 43 4c 41 53 53 45 53 5f 52 4f 4f 54 22 20 2f 66 } //2 @reg delete "HKEY_CLASSES_ROOT" /f
		$a_01_1 = {40 72 65 67 20 64 65 6c 65 74 65 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 22 20 2f 66 } //2 @reg delete "HKEY_CURRENT_USER" /f
		$a_01_2 = {40 72 65 67 20 64 65 6c 65 74 65 20 22 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 22 20 2f 66 } //2 @reg delete "HKEY_LOCAL_MACHINE" /f
		$a_01_3 = {40 72 65 67 20 64 65 6c 65 74 65 20 22 48 4b 45 59 5f 55 53 45 52 53 22 20 2f 66 } //2 @reg delete "HKEY_USERS" /f
		$a_01_4 = {40 72 65 67 20 64 65 6c 65 74 65 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 43 4f 4e 46 49 47 22 20 2f 66 } //2 @reg delete "HKEY_CURRENT_CONFIG" /f
		$a_01_5 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //2 \\.\PhysicalDrive0
		$a_01_6 = {5c 5c 2e 5c 48 61 72 64 64 69 73 6b 30 50 61 72 74 69 74 69 6f 6e } //2 \\.\Harddisk0Partition
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}
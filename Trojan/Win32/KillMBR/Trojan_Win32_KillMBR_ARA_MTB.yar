
rule Trojan_Win32_KillMBR_ARA_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 10 68 00 21 40 00 ff 15 90 01 04 6a 00 8b f0 8d 45 f8 50 68 00 02 00 00 68 28 21 40 00 56 ff 15 90 01 04 56 ff 15 90 00 } //2
		$a_80_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  2
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}
rule Trojan_Win32_KillMBR_ARA_MTB_2{
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
rule Trojan_Win32_KillMBR_ARA_MTB_3{
	meta:
		description = "Trojan:Win32/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 6f 6f 74 6c 6f 61 64 65 72 3a 20 53 75 63 63 65 73 66 75 6c 6c 79 20 6c 6f 61 64 65 64 } //2 Bootloader: Succesfully loaded
		$a_01_1 = {4d 65 6d 6f 72 79 20 72 65 67 69 6f 6e 3a 20 30 78 38 30 30 30 20 68 61 73 20 62 65 65 6e 20 6c 6f 61 64 65 64 2e 22 2c 31 33 2c 31 30 2c 31 33 2c 31 30 2c } //2 Memory region: 0x8000 has been loaded.",13,10,13,10,
		$a_01_2 = {52 65 73 65 74 20 64 69 73 6b 20 73 79 73 74 65 6d } //2 Reset disk system
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
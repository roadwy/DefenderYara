
rule Trojan_Win64_KillMBR_ARA_MTB{
	meta:
		description = "Trojan:Win64/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {5c 63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 79 7c 20 66 6f 72 6d 61 74 20 63 3a 20 2f 66 73 3a 4e 54 46 53 20 2f 71 } //\cmd.exe /c echo y| format c: /fs:NTFS /q  2
		$a_80_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}
rule Trojan_Win64_KillMBR_ARA_MTB_2{
	meta:
		description = "Trojan:Win64/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 20 72 65 67 20 64 65 6c 65 74 65 20 48 4b 43 52 2f 2a } //2 Start reg delete HKCR/*
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 66 69 20 22 70 69 64 20 6e 65 20 31 } //2 taskkill /f /fi "pid ne 1
		$a_01_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //2 \\.\PhysicalDrive0
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
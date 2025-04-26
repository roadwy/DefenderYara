
rule Trojan_Win32_KillMBR_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 41 50 4d 20 30 38 32 37 39 2b 35 32 35 35 2e 70 64 62 } //2 \APM 08279+5255.pdb
		$a_80_1 = {6f 76 65 72 77 72 69 74 65 20 74 68 65 20 62 6f 6f 74 20 72 65 63 6f 72 64 } //overwrite the boot record  2
		$a_80_2 = {4d 61 6c 77 61 72 65 2c 20 52 75 6e } //Malware, Run  2
		$a_80_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}
rule Trojan_Win32_KillMBR_ARAZ_MTB_2{
	meta:
		description = "Trojan:Win32/KillMBR.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 64 65 73 74 6f 72 79 65 64 21 } //2 Your system has been destoryed!
		$a_01_1 = {5c 57 69 6e 64 6f 77 53 6d 61 73 68 65 72 2e 70 64 62 } //2 \WindowSmasher.pdb
		$a_00_2 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } //2 \\.\PhysicalDrive0
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
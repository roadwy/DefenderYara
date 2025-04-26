
rule Trojan_BAT_KillMBR_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 20 00 2f 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 7b 00 62 00 6f 00 6f 00 74 00 6d 00 67 00 72 00 7d 00 20 00 2f 00 66 00 } //2 bcdedit /delete {bootmgr} /f
		$a_00_1 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } //2 \\.\PhysicalDrive0
		$a_01_2 = {4d 62 72 4f 76 65 72 77 72 69 74 65 72 } //2 MbrOverwriter
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
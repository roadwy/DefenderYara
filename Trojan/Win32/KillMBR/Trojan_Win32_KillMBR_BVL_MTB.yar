
rule Trojan_Win32_KillMBR_BVL_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.BVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 72 50 65 70 73 69 5c 6f 62 6a 5c 44 65 62 75 67 5c 44 72 50 65 70 73 69 2e 70 64 62 } //2 DrPepsi\obj\Debug\DrPepsi.pdb
		$a_01_1 = {6d 61 6c 77 61 72 65 } //2 malware
		$a_01_2 = {74 72 6f 6a 61 6e } //2 trojan
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
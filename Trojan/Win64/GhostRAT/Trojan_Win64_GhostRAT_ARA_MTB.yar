
rule Trojan_Win64_GhostRAT_ARA_MTB{
	meta:
		description = "Trojan:Win64/GhostRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 52 65 6c 65 61 73 65 5c 43 6f 64 65 5f 53 68 65 6c 6c 63 6f 64 65 2e 70 64 62 } //2 \Release\Code_Shellcode.pdb
		$a_01_1 = {56 46 50 6f 77 65 72 } //2 VFPower
		$a_01_2 = {7a 68 75 78 69 61 6e 6c 75 } //2 zhuxianlu
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
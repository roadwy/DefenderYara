
rule Trojan_Win64_Negetsog_UL_MTB{
	meta:
		description = "Trojan:Win64/Negetsog.UL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7a 76 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 64 6c 6c 5f 6e 65 74 77 6f 72 6b 2e 70 64 62 } //1 zver\x64\Release\dll_network.pdb
		$a_01_1 = {63 66 63 63 66 33 62 30 36 65 30 37 65 31 66 32 65 36 61 33 31 37 } //1 cfccf3b06e07e1f2e6a317
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
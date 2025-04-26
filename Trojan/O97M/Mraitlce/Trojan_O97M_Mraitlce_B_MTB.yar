
rule Trojan_O97M_Mraitlce_B_MTB{
	meta:
		description = "Trojan:O97M/Mraitlce.B!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {48 54 54 50 44 6f 77 6e 6c 6f 61 64 20 27 68 74 74 70 3a 2f 2f [0-30] 2e 65 78 65 27 2c 20 27 43 3a 5c 74 65 6d 70 27 } //1
		$a_02_1 = {53 68 65 6c 6c 20 22 77 73 63 72 69 70 74 20 63 3a 5c 74 65 6d 70 5c [0-08] 2e 76 62 73 } //1
		$a_02_2 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 27 63 3a 5c 74 65 6d 70 5c [0-08] 2e 65 78 65 27 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}

rule Trojan_O97M_Obfuse_K{
	meta:
		description = "Trojan:O97M/Obfuse.K,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 } //1 On Error Resume Next
		$a_03_1 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-20] 2c 20 54 72 75 65 2c 20 54 72 75 65 29 0d 0a [0-20] 2e 57 72 69 74 65 20 [0-20] 0d 0a [0-20] 2e 43 6c 6f 73 65 } //1
		$a_00_2 = {57 69 74 68 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 43 68 72 } //1 With CreateObject(Chr
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
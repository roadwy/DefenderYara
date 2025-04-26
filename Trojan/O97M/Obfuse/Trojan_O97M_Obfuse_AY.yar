
rule Trojan_O97M_Obfuse_AY{
	meta:
		description = "Trojan:O97M/Obfuse.AY,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {46 75 6e 63 74 69 6f 6e 20 [0-20] 28 29 } //1
		$a_01_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 } //1 Call Shell(
		$a_02_2 = {3d 20 22 63 6d 64 20 2f 56 3a 4f 4e 2f 43 22 22 73 65 74 [0-05] 3d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}

rule Trojan_O97M_Obfuse_G{
	meta:
		description = "Trojan:O97M/Obfuse.G,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 [0-15] 2e 53 61 76 65 54 6f 46 69 6c 65 28 45 6e 76 69 72 6f 6e 28 [0-ff] 29 2c 20 35 20 2b 20 33 20 2d 20 36 29 } //1
		$a_03_1 = {20 3d 20 53 70 61 63 65 28 [0-04] 29 20 2b 20 55 43 61 73 65 28 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
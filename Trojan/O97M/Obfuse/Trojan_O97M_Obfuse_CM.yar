
rule Trojan_O97M_Obfuse_CM{
	meta:
		description = "Trojan:O97M/Obfuse.CM,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {41 72 72 61 79 28 [0-20] 2c 20 [0-20] 2c 20 [0-20] 2c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-99] 29 2e 52 75 6e [0-01] 28 } //1
		$a_01_1 = {22 57 73 63 52 69 70 74 2e 73 48 65 4c 6c 22 } //1 "WscRipt.sHeLl"
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
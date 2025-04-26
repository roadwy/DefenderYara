
rule Trojan_O97M_Obfuse_CN{
	meta:
		description = "Trojan:O97M/Obfuse.CN,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {41 72 72 61 79 28 [0-40] 2c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 20 2b 20 [0-90] 29 2e 52 75 6e } //1
		$a_00_1 = {22 57 73 63 52 69 70 74 2e 73 48 65 4c 6c 22 20 2b } //1 "WscRipt.sHeLl" +
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
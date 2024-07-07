
rule Trojan_O97M_Obfuse_CJ{
	meta:
		description = "Trojan:O97M/Obfuse.CJ,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {41 72 72 61 79 28 90 02 20 2c 20 90 02 20 2c 20 90 02 20 2c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 70 29 2e 52 75 6e 90 02 01 28 28 90 02 70 2e 54 65 78 74 42 6f 78 31 90 02 50 2c 20 90 10 02 00 20 2d 20 90 10 02 00 29 2c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
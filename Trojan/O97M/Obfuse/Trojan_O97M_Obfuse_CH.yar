
rule Trojan_O97M_Obfuse_CH{
	meta:
		description = "Trojan:O97M/Obfuse.CH,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {41 72 72 61 79 28 90 02 10 2c 20 90 02 10 2c 20 90 02 10 2c 20 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 28 90 02 50 2e 54 65 78 74 42 6f 78 31 90 02 40 2c 20 90 10 03 00 20 2d 20 90 10 03 00 29 2c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
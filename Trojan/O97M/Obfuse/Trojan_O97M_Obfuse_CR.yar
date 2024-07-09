
rule Trojan_O97M_Obfuse_CR{
	meta:
		description = "Trojan:O97M/Obfuse.CR,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 0d 0a [0-20] 20 3d 20 53 68 65 6c 6c 28 [0-20] 20 2b 20 [0-60] 2c 20 76 62 48 69 64 65 29 0d 0a 0d 0a 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
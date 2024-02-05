
rule Trojan_O97M_Obfuse_CP{
	meta:
		description = "Trojan:O97M/Obfuse.CP,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 73 68 61 70 65 73 } //activedocument.shapes  01 00 
		$a_80_1 = {2e 61 6c 74 65 72 6e 61 74 69 76 65 74 65 78 74 } //.alternativetext  01 00 
		$a_02_2 = {69 00 6e 00 74 00 65 00 72 00 61 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 90 02 50 76 00 62 00 68 00 69 00 64 00 65 00 90 00 } //01 00 
		$a_02_3 = {69 6e 74 65 72 61 63 74 69 6f 6e 2e 73 68 65 6c 6c 90 02 50 76 62 68 69 64 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
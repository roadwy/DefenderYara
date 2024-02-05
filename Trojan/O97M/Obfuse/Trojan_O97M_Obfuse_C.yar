
rule Trojan_O97M_Obfuse_C{
	meta:
		description = "Trojan:O97M/Obfuse.C,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 6e 20 5f 0d 0a 45 72 72 6f 72 20 5f 0d 0a 52 65 73 75 6d 65 20 5f 0d 0a 4e 65 78 74 0d 0a 44 69 6d 20 } //01 00 
		$a_01_1 = {2f 2f 5e 3a 5e 22 20 2b 20 22 70 5e 74 74 68 40 76 } //01 00 
		$a_01_2 = {29 29 20 2b 20 46 6f 72 6d 61 74 28 43 68 72 28 } //00 00 
	condition:
		any of ($a_*)
 
}
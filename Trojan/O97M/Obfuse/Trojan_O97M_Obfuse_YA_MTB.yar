
rule Trojan_O97M_Obfuse_YA_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {28 55 73 65 72 46 6f 72 6d 90 02 02 2e 54 65 78 74 42 6f 78 90 02 02 2e 54 65 78 74 29 90 00 } //01 00 
		$a_00_1 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_O97M_Obfuse_YA_MTB_2{
	meta:
		description = "Trojan:O97M/Obfuse.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {25 54 45 4d 50 25 5c 90 02 40 2e 65 78 65 90 00 } //01 00 
		$a_03_1 = {2e 52 75 6e 20 90 02 40 2c 90 00 } //01 00 
		$a_00_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //00 00 
	condition:
		any of ($a_*)
 
}
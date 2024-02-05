
rule TrojanDropper_O97M_Hancitor_JOAK_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JOAK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 6f 72 6f 2e 22 20 26 20 22 6b 22 20 26 20 22 6c } //01 00 
		$a_01_1 = {43 61 6c 6c 20 50 72 69 6d 65 72 31 28 46 6f 6c 64 65 72 20 26 20 22 5c 22 20 26 20 66 31 2e 4e 61 6d 65 20 26 20 22 5c 22 29 } //01 00 
		$a_01_2 = {43 61 6c 6c 20 62 76 78 66 63 73 64 } //00 00 
	condition:
		any of ($a_*)
 
}
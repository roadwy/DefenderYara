
rule TrojanDropper_O97M_Hancitor_JOBA_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JOBA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 63 62 64 66 20 3d 20 62 63 62 64 66 20 26 20 22 68 74 74 } //01 00 
		$a_01_1 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 66 64 77 65 73 64 66 } //01 00 
		$a_01_2 = {43 61 6c 6c 20 78 63 76 73 64 66 73 } //01 00 
		$a_01_3 = {70 2e 64 22 20 26 20 22 6f 63 22 29 } //01 00 
		$a_01_4 = {43 61 6c 6c 20 6f 6f 61 73 70 70 } //01 00 
		$a_01_5 = {43 61 6c 6c 20 6d 6d 28 22 70 3a 2f 2f 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
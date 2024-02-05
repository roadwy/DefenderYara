
rule TrojanDropper_O97M_Hancitor_JAG_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 68 69 28 6d 79 68 6f 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //01 00 
		$a_01_1 = {44 69 6d 20 70 6c 6f 70 20 41 73 20 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {44 69 6d 20 70 61 66 68 20 41 73 20 53 74 72 69 6e 67 } //01 00 
		$a_01_3 = {70 61 66 68 20 3d 20 69 65 70 } //01 00 
		$a_01_4 = {70 6c 6f 70 20 3d 20 70 61 66 68 } //01 00 
		$a_03_5 = {43 61 6c 6c 20 6a 6f 70 28 6d 79 68 6f 6d 65 2c 20 70 6c 6f 70 20 26 20 22 5c 53 74 61 74 69 63 2e 64 6c 6c 22 29 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
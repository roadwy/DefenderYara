
rule TrojanDropper_O97M_Hancitor_EMTV_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EMTV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 5c 65 64 67 65 2e 64 22 } //01 00 
		$a_01_1 = {26 20 6a 73 64 20 26 20 22 6c 22 20 26 20 6c 61 7a 20 26 20 68 68 } //01 00 
		$a_01_2 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 54 61 62 6c 65 73 28 31 29 2e 43 65 6c 6c 28 31 2c 20 31 29 2e 52 61 6e 67 65 2e 54 65 78 74 } //01 00 
		$a_01_3 = {43 61 6c 6c 20 72 6e 65 65 28 75 75 75 2c 20 61 61 61 61 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_O97M_Hancitor_EMTV_MTB_2{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EMTV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 66 20 44 69 72 28 6a 6f 73 20 26 20 22 5c 66 65 72 75 73 2e 64 22 20 26 20 22 6c 22 20 26 20 22 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //01 00 
		$a_01_1 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 54 61 62 6c 65 73 28 31 29 2e 43 65 6c 6c 28 31 2c 20 31 29 2e 52 61 6e 67 65 2e 54 65 78 74 } //01 00 
		$a_01_2 = {53 75 62 20 62 63 76 78 7a 63 28 29 } //01 00 
		$a_01_3 = {3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 6e 6d 22 2c 20 6f 6c 6f 6c 6f 77 29 } //00 00 
	condition:
		any of ($a_*)
 
}
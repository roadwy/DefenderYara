
rule TrojanDropper_O97M_Hancitor_EOBE_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 6f 75 73 78 } //01 00 
		$a_01_1 = {6f 78 6c 20 3d 20 22 5c 72 65 66 6f 72 6d 2e 64 6f 63 22 } //01 00 
		$a_01_2 = {66 66 66 66 66 20 3d 20 22 72 65 66 6f 72 6d 2e 69 6f 65 22 } //01 00 
		$a_01_3 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4d 6f 64 75 6c 65 31 32 33 33 34 35 22 } //01 00 
		$a_01_4 = {53 75 62 20 75 6f 69 61 28 66 66 66 73 20 41 73 20 53 74 72 69 6e 67 29 } //00 00 
	condition:
		any of ($a_*)
 
}
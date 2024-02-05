
rule TrojanDropper_O97M_Hancitor_DRP_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.DRP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c } //01 00 
		$a_01_1 = {45 6e 76 69 72 6f 6e 24 28 22 74 65 6d 70 22 29 } //01 00 
		$a_01_2 = {28 76 63 62 63 20 26 20 22 5c 6f 6d 73 68 2e 64 6c 6c 22 29 } //01 00 
		$a_01_3 = {43 61 6c 6c 20 53 65 61 72 63 68 28 61 73 64 61 66 2e } //01 00 
		$a_01_4 = {45 6e 76 69 72 6f 6e 24 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6f 6d 73 68 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDropper_O97M_Hancitor_EMLW_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EMLW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 6e 6d 28 6f 6c 6f 6c 6f 77 20 41 73 20 53 74 72 69 6e 67 29 } //01 00 
		$a_01_1 = {4e 61 6d 65 20 6f 6c 6f 6c 6f 77 20 26 20 22 5c 6d 75 72 70 75 73 2e 6d 22 20 41 73 20 70 69 74 20 26 20 22 5c 22 20 26 20 22 68 75 72 70 75 73 2e 64 22 20 26 20 22 6c 6c 22 } //01 00 
		$a_01_2 = {2e 52 75 6e 28 22 6e 6d 22 2c 20 6f 6c 6f 6c 6f 77 29 } //00 00 
	condition:
		any of ($a_*)
 
}
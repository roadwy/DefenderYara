
rule TrojanDropper_O97M_Hancitor_JOBC_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JOBC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 66 64 77 65 73 64 66 } //01 00 
		$a_01_1 = {43 61 6c 6c 20 78 63 76 73 64 66 73 } //01 00 
		$a_01_2 = {43 61 6c 6c 20 6d 6d 28 22 70 3a 22 20 26 20 22 2f 2f 22 29 } //01 00 
		$a_01_3 = {49 66 20 44 69 72 28 75 75 20 26 20 22 5c 69 66 66 22 20 26 20 70 6c 66 20 26 20 22 62 22 20 26 20 22 69 6e 22 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 20 3d 20 22 22 20 54 68 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}
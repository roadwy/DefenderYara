
rule TrojanDropper_O97M_GraceWire_BB_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 49 66 20 56 42 41 37 20 41 6e 64 20 57 69 6e 36 34 20 54 68 65 6e } //01 00 
		$a_03_1 = {74 74 20 3d 20 74 74 20 26 20 73 54 28 69 69 29 20 26 20 22 5c 22 90 02 10 4e 65 78 74 20 69 69 90 00 } //01 00 
		$a_01_2 = {4d 69 2e 64 24 28 43 6f 6d 6d 61 2e 6e 64 24 2c 20 69 2c 20 31 29 } //01 00 
		$a_01_3 = {31 20 54 6f 20 4c 65 6e 28 43 6f 6d 6d 61 2e 6e 64 24 29 } //01 00 
		$a_01_4 = {46 4d 4f 44 5f 4f 4b 20 54 68 65 6e } //01 00 
		$a_03_5 = {55 6e 6c 6f 61 64 20 4d 2e 65 90 02 10 45 6e 64 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
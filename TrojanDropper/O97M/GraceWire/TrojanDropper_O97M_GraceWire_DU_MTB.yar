
rule TrojanDropper_O97M_GraceWire_DU_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 72 6f 63 68 65 20 4c 69 62 20 22 73 74 72 5f 6a 6f 69 6e 31 2e 64 6c 6c 22 20 28 29 20 41 73 20 49 6e 74 65 67 65 72 } //01 00 
		$a_01_1 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 2b 20 22 6c 2e 78 6c 73 78 } //01 00 
		$a_01_2 = {6f 66 62 6c 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //01 00 
		$a_01_3 = {6f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 22 5c 73 74 72 5f 6a 6f 69 6e } //01 00 
		$a_01_4 = {4c 72 69 67 61 74 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 31 2e 54 61 67 } //00 00 
	condition:
		any of ($a_*)
 
}
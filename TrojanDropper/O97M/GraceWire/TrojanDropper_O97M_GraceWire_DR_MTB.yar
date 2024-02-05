
rule TrojanDropper_O97M_GraceWire_DR_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 2b 20 22 6c 2e 78 6c 73 78 22 } //01 00 
		$a_01_1 = {6f 66 62 6c 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //01 00 
		$a_01_2 = {6f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 22 5c 73 74 72 5f 6a 6f 69 6e 22 } //01 00 
		$a_01_3 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b } //01 00 
		$a_01_4 = {43 6f 6d 70 6f 73 69 74 69 6f 6e 20 64 65 72 73 68 6c 65 70 20 2b 20 22 22 20 2b 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 20 2b 20 22 22 20 2b 20 22 22 2c 20 73 4f 66 62 6c 2c 20 4e 75 6d 42 46 6f 72 52 65 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}
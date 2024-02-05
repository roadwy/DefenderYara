
rule TrojanDropper_O97M_GraceWire_AY_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 6f 75 74 70 75 74 2e 72 61 77 22 20 46 6f 72 20 52 61 6e 64 6f 6d 20 41 73 20 23 } //01 00 
		$a_01_1 = {6f 75 74 66 70 20 3d 20 6c 4f 2e 70 65 6e 28 22 6f 75 74 70 75 74 2e 72 61 77 22 2c 20 31 29 } //01 00 
		$a_01_2 = {43 61 6c 6c 20 6c 57 2e 72 69 74 65 28 6f 75 74 66 70 2c } //01 00 
		$a_01_3 = {3d 20 46 4d 4f 44 } //00 00 
	condition:
		any of ($a_*)
 
}
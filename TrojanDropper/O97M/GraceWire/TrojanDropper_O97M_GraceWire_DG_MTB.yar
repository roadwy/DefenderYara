
rule TrojanDropper_O97M_GraceWire_DG_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c 90 02 10 22 90 00 } //01 00 
		$a_01_1 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 2b 20 22 6c 2e 78 6c 73 78 22 } //01 00 
		$a_01_2 = {73 4f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 66 6c 61 79 53 74 72 69 6e 67 20 2b 20 22 2e 64 6c 6c 22 } //01 00 
		$a_01_3 = {6f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 22 5c 73 72 74 5f 6a 6f 69 6e 22 } //00 00 
	condition:
		any of ($a_*)
 
}
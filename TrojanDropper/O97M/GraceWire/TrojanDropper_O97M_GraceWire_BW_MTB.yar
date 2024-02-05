
rule TrojanDropper_O97M_GraceWire_BW_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 65 72 73 68 6c 65 70 20 3d 20 22 22 20 2b 20 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //01 00 
		$a_03_1 = {63 74 61 63 6b 50 75 70 20 3d 20 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c 90 02 12 2e 78 6c 73 22 20 2b 20 22 78 22 90 00 } //01 00 
		$a_01_2 = {63 74 61 63 6b 50 6f 70 20 3d 20 64 65 72 73 68 6c 65 70 20 26 20 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 33 2e 56 61 6c 75 65 } //01 00 
		$a_01_3 = {6f 66 62 6c 20 3d 20 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 } //00 00 
	condition:
		any of ($a_*)
 
}
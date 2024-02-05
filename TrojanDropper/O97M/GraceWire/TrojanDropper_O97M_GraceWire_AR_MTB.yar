
rule TrojanDropper_O97M_GraceWire_AR_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {26 20 22 64 22 90 02 12 6c 90 02 09 6c 90 02 09 22 90 00 } //01 00 
		$a_01_1 = {50 52 50 20 3d 20 22 25 22 20 26 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //01 00 
		$a_01_2 = {3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 5c 73 74 61 64 72 5f 22 } //01 00 
		$a_01_3 = {4b 69 6c 6c 20 4b 65 79 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDropper_O97M_Dallawot_A{
	meta:
		description = "TrojanDropper:O97M/Dallawot.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6e 76 6e 31 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 22 20 26 20 64 73 67 66 37 37 7a 70 7a 33 33 33 67 33 33 33 38 33 37 36 67 66 68 64 66 67 79 66 74 65 29 0d 0a 64 73 67 66 37 37 7a 70 7a 33 33 33 67 33 33 33 38 33 37 36 67 66 68 64 66 67 79 66 74 65 20 3d 20 22 6f 73 74 2e 65 22 20 26 20 22 78 65 22 0d 0a 74 6e 33 33 6e 31 20 3d 20 74 6e 76 6e 31 20 26 20 22 73 76 63 6e 22 20 26 } //00 00 
	condition:
		any of ($a_*)
 
}
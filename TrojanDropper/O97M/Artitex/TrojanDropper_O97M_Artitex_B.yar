
rule TrojanDropper_O97M_Artitex_B{
	meta:
		description = "TrojanDropper:O97M/Artitex.B,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {26 20 22 65 22 20 2b 20 22 78 65 22 } //01 00 
		$a_00_1 = {2b 20 22 72 74 22 20 2b 20 22 66 22 } //01 00 
		$a_00_2 = {26 20 22 45 4d 50 22 } //01 00 
		$a_00_3 = {2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d 4e 61 6d 65 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 52 54 46 } //01 00 
		$a_01_4 = {3d 20 54 4d 50 20 2b 20 22 33 31 31 22 20 2b } //00 00 
		$a_00_5 = {5d 04 00 } //00 35 
	condition:
		any of ($a_*)
 
}
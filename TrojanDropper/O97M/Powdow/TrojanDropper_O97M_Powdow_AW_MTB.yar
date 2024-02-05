
rule TrojanDropper_O97M_Powdow_AW_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.AW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 20 22 2e 6a 73 65 22 } //01 00 
		$a_01_1 = {26 20 22 2e 64 6f 63 22 } //01 00 
		$a_01_2 = {45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 } //01 00 
		$a_01_3 = {26 20 22 5c 22 } //01 00 
		$a_01_4 = {3d 20 4d 69 64 28 63 6f 6c 6c 65 63 74 44 61 74 61 2e 54 65 78 74 2c 20 31 2c 20 4c 65 6e 28 63 6f 6c 6c 65 63 74 44 61 74 61 2e 54 65 78 74 29 20 2d 20 32 29 } //01 00 
		$a_03_5 = {50 72 69 6e 74 20 23 90 02 02 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
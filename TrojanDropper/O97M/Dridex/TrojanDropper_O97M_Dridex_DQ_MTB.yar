
rule TrojanDropper_O97M_Dridex_DQ_MTB{
	meta:
		description = "TrojanDropper:O97M/Dridex.DQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 76 69 72 6f 6e 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 62 52 4e 75 59 6d 7a 46 56 74 55 42 41 72 65 55 64 4b 53 2e 73 63 74 22 } //01 00 
		$a_01_1 = {72 72 71 74 59 64 44 6a 59 47 2e 52 61 6e 67 65 2e 54 65 78 74 } //01 00 
		$a_01_2 = {53 70 6c 69 74 28 69 62 4f 6d 51 4a 64 6d 61 79 54 41 65 4e 4d 5a 2c 20 22 74 4a 4f 57 42 6b 73 44 6a 68 6f 4d 22 29 } //01 00 
		$a_01_3 = {2e 45 78 65 63 20 28 45 69 46 4b 4e 46 4f 56 71 46 29 } //00 00 
	condition:
		any of ($a_*)
 
}
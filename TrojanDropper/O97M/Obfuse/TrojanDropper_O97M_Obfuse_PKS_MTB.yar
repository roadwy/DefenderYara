
rule TrojanDropper_O97M_Obfuse_PKS_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.PKS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 75 70 64 61 74 65 2e 6a 73 } //01 00 
		$a_03_1 = {77 69 6e 6d 67 6d 74 73 3a 27 2c 27 43 3a 5c 90 02 05 50 72 6f 67 72 61 6d 44 61 74 61 5c 90 02 05 64 64 6f 6e 64 2e 63 6f 6d 90 00 } //01 00 
		$a_01_2 = {6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f 76 77 74 32 75 38 37 6a 66 7a 70 62 30 66 34 2f 33 2e 68 74 6d 2f 66 69 6c 65 } //01 00 
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 90 02 0a 2c 20 22 90 02 05 22 2c 20 22 90 02 03 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
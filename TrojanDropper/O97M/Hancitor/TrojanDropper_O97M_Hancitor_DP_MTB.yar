
rule TrojanDropper_O97M_Hancitor_DP_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.DP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 4c 6f 63 61 6c 2f 54 65 6d 70 22 } //01 00 
		$a_01_1 = {28 76 63 62 63 20 26 20 22 5c 71 71 2e 64 6f 63 22 29 } //01 00 
		$a_01_2 = {43 61 6c 6c 20 62 76 78 66 63 73 64 } //01 00 
		$a_01_3 = {22 71 71 2e 66 61 78 22 } //01 00 
		$a_01_4 = {43 61 6c 6c 20 53 65 61 72 63 68 28 4d 79 46 53 4f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 61 29 2c 20 68 64 76 29 } //00 00 
	condition:
		any of ($a_*)
 
}
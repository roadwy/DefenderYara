
rule TrojanDropper_O97M_Powdow_RVC_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.RVC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 6f 61 74 73 20 3d 20 22 63 6d 22 20 26 20 22 64 20 2f 22 20 26 20 22 63 20 25 74 65 6d 70 25 5c 69 6e 73 74 78 2e 65 22 20 26 20 22 78 65 22 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 70 6c 61 63 65 68 6f 6c 64 65 72 32 2c 20 22 22 29 2e 52 75 6e 20 63 6f 6e 74 61 69 6e 65 72 2c 20 30 } //01 00 
		$a_01_2 = {3d 20 22 73 74 2e 65 22 0d 0a 20 20 20 20 74 77 6f 6c 65 74 74 65 72 73 20 3d 20 22 78 65 22 } //01 00 
		$a_01_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDropper_O97M_Powdow_AX_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.AX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 20 22 2e 6a 73 65 22 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 4d 69 64 28 41 73 6b 55 73 65 72 2e 63 6d 64 2e 43 61 70 74 69 6f 6e 2c 20 39 2c 20 31 37 29 29 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 41 73 6b 55 73 65 72 2e 70 61 74 68 2e 43 61 70 74 69 6f 6e } //01 00 
		$a_01_2 = {45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 22 } //00 00 
	condition:
		any of ($a_*)
 
}
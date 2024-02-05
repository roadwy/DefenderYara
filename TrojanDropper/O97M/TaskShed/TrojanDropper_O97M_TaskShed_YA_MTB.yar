
rule TrojanDropper_O97M_TaskShed_YA_MTB{
	meta:
		description = "TrojanDropper:O97M/TaskShed.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 68 65 64 75 6c 65 2e 53 65 72 76 69 63 65 22 29 } //01 00 
		$a_01_1 = {2e 43 72 65 61 74 65 28 41 63 74 69 6f 6e 54 79 70 65 45 78 65 63 75 74 61 62 6c 65 29 } //01 00 
		$a_01_2 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e } //00 00 
	condition:
		any of ($a_*)
 
}
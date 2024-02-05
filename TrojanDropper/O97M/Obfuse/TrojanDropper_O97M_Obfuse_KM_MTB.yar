
rule TrojanDropper_O97M_Obfuse_KM_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.KM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 2e 6a 73 65 22 } //01 00 
		$a_01_1 = {22 55 53 45 52 22 } //01 00 
		$a_01_2 = {22 50 52 4f 46 49 4c 45 22 } //01 00 
		$a_01_3 = {55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 54 65 78 74 } //01 00 
		$a_01_4 = {22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 } //01 00 
		$a_01_5 = {3d 20 45 6e 76 69 72 6f 6e 28 } //00 00 
	condition:
		any of ($a_*)
 
}
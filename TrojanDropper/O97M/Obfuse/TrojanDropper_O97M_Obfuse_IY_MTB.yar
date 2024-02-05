
rule TrojanDropper_O97M_Obfuse_IY_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.IY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 20 22 6c 69 22 20 26 20 22 62 63 22 20 26 20 22 75 72 6c 22 20 26 20 22 2e 64 22 20 26 20 22 6c 6c 22 20 26 20 22 2c 23 35 32 22 2c 20 30 2c 20 46 61 6c 73 65 } //01 00 
		$a_01_1 = {6e 20 3d 20 22 70 65 6e 22 20 26 20 22 73 65 31 2e 74 22 20 26 20 22 78 74 22 } //01 00 
		$a_01_2 = {3d 20 66 73 6f 31 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 20 26 20 22 5c 22 20 26 20 6e } //00 00 
	condition:
		any of ($a_*)
 
}
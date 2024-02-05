
rule TrojanDownloader_O97M_Obfuse_OR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.OR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 52 75 6e 20 90 02 40 28 53 68 65 65 74 73 28 22 90 02 14 22 29 2e 43 65 6c 6c 73 28 90 02 10 29 2e 56 61 6c 75 65 2c 20 90 02 02 29 2c 20 30 2c 20 46 61 6c 73 65 90 00 } //01 00 
		$a_01_1 = {3d 20 43 68 72 28 49 6e 74 28 30 } //01 00 
		$a_03_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 40 28 22 90 02 30 22 2c 20 90 02 02 29 29 90 00 } //01 00 
		$a_03_3 = {3d 20 4d 69 64 28 90 02 38 2c 20 90 02 38 2c 20 32 29 90 00 } //01 00 
		$a_03_4 = {3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 40 29 20 53 74 65 70 20 32 90 00 } //01 00 
		$a_03_5 = {26 20 43 68 72 28 90 02 40 20 2d 20 90 02 40 29 90 02 02 4e 65 78 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
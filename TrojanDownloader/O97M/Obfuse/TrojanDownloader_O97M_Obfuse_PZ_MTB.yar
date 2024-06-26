
rule TrojanDownloader_O97M_Obfuse_PZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 75 62 20 90 02 10 28 90 02 10 2c 20 4f 70 74 69 6f 6e 61 6c 20 42 79 56 61 6c 20 90 02 10 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 90 02 10 2e 70 64 66 22 29 90 00 } //01 00 
		$a_02_1 = {2b 20 22 73 76 72 33 32 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 90 02 10 2e 70 64 66 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_PZ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 20 90 02 40 2c 20 90 02 40 2c 20 90 02 42 2c 20 4e 75 6c 6c 90 00 } //01 00 
		$a_03_1 = {3d 20 31 20 54 6f 20 4c 65 6e 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 90 02 14 22 29 2e 56 61 6c 75 65 29 20 53 74 65 70 20 32 90 00 } //01 00 
		$a_03_2 = {26 20 4d 69 64 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 90 02 14 22 29 2e 56 61 6c 75 65 2c 20 90 02 40 2c 20 90 02 02 29 29 20 2d 20 90 02 02 29 90 02 02 4e 65 78 74 90 00 } //01 00 
		$a_01_3 = {3d 20 22 22 } //01 00  = ""
		$a_01_4 = {3d 20 43 68 72 28 49 6e 74 28 30 } //00 00  = Chr(Int(0
	condition:
		any of ($a_*)
 
}
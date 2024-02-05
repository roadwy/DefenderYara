
rule TrojanDownloader_O97M_Obfuse_BKO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BKO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 64 20 3d 20 43 68 72 28 64 66 20 2d 20 31 30 33 29 } //01 00 
		$a_01_1 = {2e 52 75 6e 28 73 6f 68 6d 71 79 76 61 62 6a 2c 20 72 73 79 64 77 6d 62 6b 68 69 66 78 63 29 } //01 00 
		$a_01_2 = {7a 76 69 63 20 3d 20 7a 76 69 63 20 26 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BKO_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BKO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6c 6c 45 78 78 63 75 74 65 28 30 2c 20 90 02 0f 2c 20 76 65 69 75 72 65 35 32 37 38 65 75 32 2c 20 6d 36 37 74 37 38 37 33 72 37 32 2c 20 22 22 2c 20 53 57 5f 53 48 4f 57 4d 49 4e 49 4d 49 5a 45 44 29 90 00 } //01 00 
		$a_01_1 = {63 61 6c 6c 20 78 64 65 63 64 28 68 68 66 66 77 79 6a 69 68 77 67 65 66 39 65 69 77 32 2c 20 75 69 79 74 76 64 76 65 72 77 74 36 37 66 68 72 65 79 29 22 20 26 20 76 62 43 72 4c 66 } //00 00 
	condition:
		any of ($a_*)
 
}
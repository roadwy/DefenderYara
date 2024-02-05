
rule TrojanDownloader_O97M_BazarLoader_R_MTB{
	meta:
		description = "TrojanDownloader:O97M/BazarLoader.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 63 6d 64 22 2c 20 22 2f 63 20 22 20 26 20 90 02 0f 2c 20 22 22 2c 20 22 22 2c 20 30 90 00 } //01 00 
		$a_01_1 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 73 68 65 6c 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00 
		$a_01_2 = {6d 78 20 22 74 22 2c 20 22 22 } //01 00 
		$a_03_3 = {52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 90 02 07 22 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
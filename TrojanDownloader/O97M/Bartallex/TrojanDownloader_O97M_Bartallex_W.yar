
rule TrojanDownloader_O97M_Bartallex_W{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.W,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 3d 20 41 72 72 61 79 28 90 10 05 00 2c 20 90 10 05 00 2c 20 90 10 05 00 90 00 } //01 00 
		$a_01_1 = {53 70 6c 69 74 28 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 2c 20 22 2f 22 29 } //01 00 
		$a_03_2 = {52 65 70 6c 61 63 65 28 90 12 10 00 28 90 10 02 00 29 2c 20 22 74 22 2c 20 22 65 22 29 90 00 } //01 00 
		$a_03_3 = {2e 4f 70 65 6e 20 90 02 10 28 90 10 02 00 29 2c 20 90 02 14 5f 90 0f 01 00 2c 20 46 61 6c 73 65 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_O97M_Powdow_RVAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 90 02 14 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 64 73 73 64 64 2e 63 6d 7a 64 22 90 00 } //01 00 
		$a_03_1 = {3d 20 22 68 65 6c 6c 22 0d 0a 90 02 14 20 3d 20 52 65 70 6c 61 63 65 28 90 02 14 2c 20 22 2e 63 6d 7a 22 2c 20 22 2e 63 6d 22 29 0d 0a 90 02 14 20 3d 20 22 70 6f 77 65 72 73 5e 22 90 00 } //01 00 
		$a_03_2 = {50 72 69 6e 74 20 23 33 2c 20 90 02 14 20 26 20 90 02 14 20 26 20 22 20 2d 77 20 68 69 20 73 5e 6c 65 65 70 20 2d 53 65 20 33 31 3b 53 74 61 72 74 2d 42 69 74 73 54 72 5e 61 6e 5e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 90 00 } //01 00 
		$a_03_3 = {64 6f 67 65 28 30 2c 20 53 74 72 43 6f 6e 76 28 22 6f 70 65 6e 22 2c 20 36 34 29 2c 20 53 74 72 43 6f 6e 76 28 22 65 78 70 6c 6f 72 65 72 22 2c 20 36 34 29 2c 20 53 74 72 43 6f 6e 76 28 90 02 14 2c 20 36 34 29 2c 20 22 22 2c 20 31 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
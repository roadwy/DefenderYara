
rule TrojanDownloader_O97M_Powdow_RVCH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 65 2e 39 39 39 4f 5f 50 2f 36 34 32 2e 34 39 31 2e 33 2e 32 39 31 2f 2f 3a 70 74 74 68 } //01 00 
		$a_01_1 = {58 4e 46 6a 68 4c 2e 52 75 6e 20 22 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 20 2b 20 65 62 71 72 6e 20 2b 20 22 20 22 20 2b 20 79 4f 73 68 69 43 } //01 00 
		$a_01_2 = {41 75 74 6f 5f 4f 70 65 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_RVCH_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 22 68 74 74 70 3a 2f 2f 22 26 75 26 22 2f 74 71 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f 70 72 6f 64 75 63 74 5f 64 65 74 61 69 6c 73 5f 30 31 38 5f 72 66 71 2e 65 78 65 22 22 7a 63 6c 64 78 76 71 63 69 6f 70 67 79 6b 6a 65 2e 65 78 65 2e 65 78 65 } //01 00 
		$a_01_1 = {73 68 65 6c 6c 28 63 63 2c 76 62 68 69 64 65 29 6e 65 78 74 75 65 6e 64 73 75 62 } //01 00 
		$a_01_2 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
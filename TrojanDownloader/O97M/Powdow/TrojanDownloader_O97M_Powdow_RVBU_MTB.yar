
rule TrojanDownloader_O97M_Powdow_RVBU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {27 27 73 62 76 2e 64 61 70 65 74 6f 6e 5c 27 27 2b 70 6d 65 74 3a 76 6e 65 24 2c 27 27 73 62 76 2e 74 6e 65 69 6c 43 20 64 65 74 63 65 74 6f 72 50 2f 72 65 73 67 69 63 2f 6b 74 2e 67 64 63 65 69 66 76 2f 2f 3a 70 74 74 68 27 27 } //01 00 
		$a_01_1 = {22 70 6f 77 65 22 20 2b 20 22 72 73 22 20 2b 20 52 61 6e 67 65 28 22 46 31 30 30 22 29 2e 56 61 6c 75 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_RVBU_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 28 22 77 73 63 72 69 70 74 22 2b 6d 79 66 69 6c 65 2c 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73 29 65 6e 64 73 75 62 } //01 00 
		$a_01_1 = {70 72 69 6e 74 23 74 65 78 74 66 69 6c 65 2c 22 65 76 22 2b 22 61 6c 28 66 75 6e 63 74 69 6f 6e 28 70 2c 61 2c 63 2c 6b 2c 65 2c 64 29 7b 65 3d 66 75 6e 63 74 69 6f 6e 28 63 29 7b 72 65 74 75 72 6e 28 63 3c 61 22 2b 75 73 65 72 66 6f 72 6d 31 2e 74 62 78 63 6c 61 76 65 2e 74 61 67 2b 75 73 65 72 66 6f 72 6d 31 } //01 00 
		$a_01_2 = {72 61 6e 67 65 28 22 61 31 3a 61 31 33 22 29 69 63 6f 6c 3d 6d 79 72 61 6e 67 65 2e 63 6f 75 6e 74 } //01 00 
		$a_01_3 = {6d 79 66 69 6c 65 3d 22 74 65 78 74 66 69 6c 65 2e 6a 73 22 } //01 00 
		$a_01_4 = {73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
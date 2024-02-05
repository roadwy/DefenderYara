
rule TrojanDownloader_O97M_Powdow_RVBW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 5f 73 68 65 6c 6c 40 5f 28 78 78 78 78 78 78 78 78 78 78 6c 6f 72 61 29 65 6e 64 73 75 62 } //01 00 
		$a_01_1 = {78 78 78 78 78 78 78 78 78 78 6c 6f 72 61 5f 3d 6e 6f 74 65 70 61 64 2e 6e 6f 74 65 70 61 64 2e 76 61 6c 75 65 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 64 65 62 75 67 5f 2e 5f 70 72 69 6e 74 } //01 00 
		$a_01_2 = {73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 3a 3a } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_RVBW_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 74 70 3a 2f 2f 31 37 33 2e 32 33 32 2e 31 34 36 2e 37 38 2f 35 30 35 2f 64 6f 63 31 30 36 2d 37 30 30 2d 31 31 33 30 30 37 2e 65 78 65 22 22 20 2d 4f 75 74 46 69 6c 65 20 24 54 65 6d 70 46 69 6c 65 3b 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 24 54 65 6d 70 46 69 6c 65 3b } //01 00 
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 62 79 70 61 73 73 3b } //01 00 
		$a_01_2 = {6f 57 73 68 53 68 65 6c 6c 45 78 65 63 2e 53 74 64 4f 75 74 2e 52 65 61 64 41 6c 6c } //01 00 
		$a_01_3 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
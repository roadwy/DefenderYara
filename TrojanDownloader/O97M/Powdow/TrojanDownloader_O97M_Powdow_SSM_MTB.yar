
rule TrojanDownloader_O97M_Powdow_SSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 38 37 2e 32 35 31 2e 38 35 2e 31 30 30 2f 6c 6f 76 65 2f 6c 6f 76 65 37 2e 68 74 6d 6c } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_SSM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 63 6f 6c 6c 20 3d 20 46 69 6c 65 6e 61 6d 65 73 43 6f 6c 6c 65 63 74 69 6f 6e 28 66 6f 6c 64 65 72 24 2c 20 22 2a 2e 78 6c 73 2a 22 29 } //01 00 
		$a_01_1 = {53 65 74 20 57 42 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 46 69 6c 65 4e 61 6d 65 2c 20 2c 20 2c 20 2c 20 50 61 73 73 4f 6c 64 24 29 } //01 00 
		$a_03_2 = {54 68 65 6e 20 90 02 15 20 3d 20 90 1b 00 20 2b 20 22 3a 5c 70 72 6f 22 20 2b 20 90 02 15 20 2b 20 22 67 72 61 6d 64 22 90 00 } //01 00 
		$a_01_3 = {2b 20 22 61 74 61 5c 73 64 66 68 69 75 77 75 2e 62 22 } //01 00 
		$a_03_4 = {53 68 65 6c 6c 20 66 68 32 6f 65 38 77 64 73 68 66 20 2b 20 22 61 74 22 2c 20 30 90 02 03 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_SSM_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 90 02 03 62 61 74 63 68 20 3d 20 22 90 02 25 2e 62 61 74 22 90 00 } //01 00 
		$a_01_1 = {50 72 69 6e 74 20 23 31 2c 20 22 73 74 61 72 74 20 2f 4d 49 4e 20 43 3a 5c 57 69 6e 64 6f 22 20 2b 20 22 77 73 5c 53 79 73 57 4f 57 36 34 5c 22 20 2b 20 63 61 6c 6c 31 20 2b 20 22 20 2d 77 69 6e 20 31 20 2d 65 6e 63 20 22 20 2b } //01 00 
		$a_03_2 = {69 20 3d 20 53 68 65 6c 6c 28 62 61 74 63 68 2c 20 30 29 90 02 03 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_3 = {63 61 6c 6c 31 20 3d 20 22 57 69 6e 64 6f 77 73 50 6f 22 20 2b 20 22 77 65 72 53 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 22 20 2b 20 22 65 72 73 68 65 6c 6c 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}
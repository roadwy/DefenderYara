
rule TrojanDownloader_O97M_Powdow_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 30 2c 20 22 68 74 74 70 3a 2f 2f 77 66 70 79 75 74 66 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 74 7a 65 33 2e 63 61 62 22 2c 20 22 31 2e 65 78 70 22 2c 20 30 2c 20 30 29 } //01 00 
		$a_01_1 = {2e 72 75 6e 20 22 72 65 67 73 76 72 33 32 20 31 2e 65 78 70 22 } //01 00 
		$a_01_2 = {22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 72 6d 2e 64 6f 77 6e 6c 6f 61 64 20 90 02 02 2c 20 22 63 32 2e 70 64 66 22 90 00 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 77 75 20 26 20 62 6e 20 26 20 22 33 32 20 63 32 2e 70 64 66 22 } //01 00 
		$a_01_2 = {22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } //01 00 
		$a_01_3 = {2e 53 65 6c 65 63 74 4e 6f 64 65 73 28 22 2f 2f 49 74 65 6d 73 22 29 28 31 29 2e 43 68 69 6c 64 4e 6f 64 65 73 28 32 29 2e 54 65 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 22 68 74 74 70 3a 2f 2f 65 39 62 6a 61 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 6b 70 74 34 2e 63 61 62 22 2c 20 56 77 2c 20 30 2c 20 30 29 } //01 00 
		$a_01_1 = {2e 72 75 6e 20 22 72 65 67 73 22 20 2b 20 22 76 72 33 32 20 22 20 26 20 56 77 } //01 00 
		$a_01_2 = {22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Powdow!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 22 68 74 74 70 3a 2f 2f 39 79 67 77 32 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 6b 70 74 90 01 01 2e 63 61 62 22 2c 20 56 77 2c 20 30 2c 20 30 29 90 00 } //01 00 
		$a_01_1 = {2e 72 75 6e 20 22 72 65 67 73 22 20 2b 20 22 76 72 33 32 20 22 20 26 20 56 77 } //01 00 
		$a_01_2 = {22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Powdow!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 22 68 74 74 70 3a 2f 2f 6e 32 66 37 39 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 6b 70 74 90 01 01 2e 63 61 62 22 2c 20 56 77 2c 20 30 2c 20 30 29 90 00 } //01 00 
		$a_01_1 = {2e 72 75 6e 20 22 72 65 67 73 22 20 2b 20 22 76 72 33 32 20 22 20 26 20 56 77 } //01 00 
		$a_01_2 = {22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Powdow!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 20 22 68 74 74 70 3a 2f 2f 73 61 67 63 2e 62 65 2f 73 2e 74 78 74 22 2c 20 45 6e 76 69 72 6f 6e 24 28 22 54 45 4d 50 22 29 20 26 20 22 5c 49 6e 74 65 6c 2e 74 78 74 22 2c 20 54 72 75 65 } //01 00 
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 54 45 4d 50 22 29 20 26 20 22 5c 49 6e 74 65 6c 2e 65 78 65 22 } //01 00 
		$a_01_2 = {46 53 4f 2e 46 6f 6c 64 65 72 45 78 69 73 74 73 28 46 69 6c 65 6e 61 6d 65 29 } //01 00 
		$a_01_3 = {50 75 74 20 23 31 2c 20 2c 20 62 69 74 73 } //01 00 
		$a_01_4 = {3d 20 49 6e 74 65 72 6e 65 74 4f 70 65 6e 28 22 22 2c 20 30 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 30 29 } //00 00 
	condition:
		any of ($a_*)
 
}
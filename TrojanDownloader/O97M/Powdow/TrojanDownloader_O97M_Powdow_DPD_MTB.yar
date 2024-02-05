
rule TrojanDownloader_O97M_Powdow_DPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 38 35 2e 32 32 32 2e 35 38 2e 35 36 2f 30 30 2e 65 78 65 22 } //01 00 
		$a_03_1 = {2e 65 78 65 2e 65 78 65 20 26 26 20 90 02 0f 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_DPD_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 71 71 71 78 78 78 2e 69 74 73 6f 6e 65 2b 69 68 74 2e 6f 70 65 6e 73 68 69 74 6d 73 67 62 6f 78 22 6f 66 66 69 63 65 65 72 72 6f 72 21 21 21 22 3a 5f 63 61 6c 6c 73 68 65 6c 6c 90 02 01 28 62 72 6f 6b 65 6e 73 68 6f 77 6f 66 66 29 65 6e 64 66 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_01_1 = {3d 67 68 74 2e 65 6c 65 70 68 61 6e 74 5f 2b 6c 6c 74 2e 6c 6f 72 61 74 77 6f 3d 6c 6c 74 2e 6b 2b 6c 6c 74 2e 74 5f 2b 6c 6c 74 2e 78 74 74 68 72 65 65 3d 6f 6e 65 5f 2b 74 77 6f 6f 70 65 6e 73 68 69 74 3d 74 68 72 65 65 65 6e 64 66 75 6e 63 74 69 6f 6e } //01 00 
		$a_01_2 = {3d 73 75 72 65 74 68 69 6e 67 2e 6d 75 6c 74 69 2e 74 61 67 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 79 74 28 29 } //01 00 
		$a_01_3 = {3d 68 71 74 2e 78 79 2b 68 71 74 2e 79 74 74 77 6f 77 61 79 3d 68 71 74 2e 7a 2b 68 71 74 2e 64 66 65 69 74 73 6f 6e 65 3d 6f 6e 65 77 61 79 2b 74 77 6f 77 61 79 65 6e 64 66 75 6e 63 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
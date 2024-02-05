
rule TrojanDownloader_O97M_Dridex_RD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.RD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 46 69 6e 64 28 57 68 61 74 3a 3d 22 2a 22 2c 20 4c 6f 6f 6b 49 6e 3a 3d 78 6c 56 61 6c 75 65 73 } //01 00 
		$a_01_1 = {20 3d 20 53 70 6c 69 74 28 6a 69 2c 20 22 21 22 29 } //01 00 
		$a_01_2 = {26 20 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 52 65 70 6c 61 63 65 28 61 2c 20 22 3f 22 2c 20 65 29 29 2c 20 31 2c 20 31 29 } //01 00 
		$a_01_3 = {20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 61 2c 20 69 2c 20 31 29 29 20 2b 20 32 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_RD_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Dridex.RD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 3d 20 22 3d 52 45 22 3a 20 } //01 00 
		$a_01_1 = {20 3d 20 22 3d 22 20 26 20 52 65 70 6c 61 63 65 28 45 2c 20 22 5b 22 2c 20 22 4a 22 29 3a 20 52 75 6e 20 28 6d 67 20 26 20 22 6f 5f 69 62 6e 32 22 29 } //01 00 
		$a_01_2 = {20 3d 20 6d 67 20 26 20 22 6f 5f 69 62 6e 32 22 3a 20 63 20 3d 20 66 75 20 2b 20 66 75 20 2b 20 66 75 3a } //01 00 
		$a_01_3 = {75 20 3d 20 75 20 26 20 43 68 72 28 41 73 63 28 4d 69 64 28 6e 2c 20 58 2c 20 66 75 29 29 20 2b 20 6b 29 3a 20 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_RD_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Dridex.RD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 6f 20 26 20 63 68 61 6f 5f 73 28 5a 2c 20 4d 69 64 28 65 2c 20 6d 6b 2c 20 76 29 29 } //01 00 
		$a_01_1 = {3d 20 53 70 6c 69 74 28 6f 6f 2c 20 61 72 65 61 63 6c 69 65 6e 74 6f 29 } //01 00 
		$a_01_2 = {28 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 22 22 20 26 20 52 65 70 6c 61 63 65 28 4f 2c 20 6d 69 6c 6f 77 5f 73 2c 20 72 65 70 6f 72 74 5f 72 65 70 29 29 2c 20 31 2c 20 32 29 } //01 00 
		$a_01_3 = {3d 20 43 68 72 28 41 73 63 28 73 29 20 2b 20 67 29 } //00 00 
	condition:
		any of ($a_*)
 
}
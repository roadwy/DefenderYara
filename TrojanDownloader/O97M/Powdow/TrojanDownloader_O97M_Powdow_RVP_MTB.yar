
rule TrojanDownloader_O97M_Powdow_RVP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 66 6a 6b 65 72 6f 6f 6f 73 2c 20 66 67 66 6a 68 66 67 66 67 2c 20 22 22 2c 20 22 22 2c 20 30 } //01 00 
		$a_01_1 = {66 79 53 4d 48 44 62 6b 41 4d 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 2e 49 74 65 6d 28 31 29 } //01 00 
		$a_01_2 = {45 62 6f 50 66 55 58 61 55 69 42 65 57 55 67 78 71 4a 46 4a 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 6f 30 74 35 29 } //00 00 
	condition:
		any of ($a_*)
 
}
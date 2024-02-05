
rule TrojanDownloader_O97M_Powdow_KT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 90 02 25 2e 68 74 61 22 90 00 } //01 00 
		$a_03_1 = {2e 65 78 65 63 20 70 28 90 02 07 29 90 00 } //01 00 
		$a_03_2 = {3d 20 53 70 6c 69 74 28 70 28 66 72 6d 2e 90 02 07 29 2c 20 22 20 22 29 90 00 } //01 00 
		$a_01_3 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b } //01 00 
		$a_03_4 = {3d 20 52 65 70 6c 61 63 65 28 90 02 19 2c 20 90 02 19 2c 20 90 02 19 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_O97M_Powdow_AJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {46 75 6e 63 74 69 6f 6e 20 6f 64 6f 78 28 29 90 02 05 6f 64 6f 78 20 3d 20 22 68 74 74 70 3a 2f 2f 22 90 00 } //01 00 
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 6f 64 6f 78 28 29 } //01 00 
		$a_01_2 = {78 7a 6e 67 39 7a 72 63 69 68 74 6d 39 6a 66 73 2e 63 6f 6d 2f 77 31 6b 62 73 37 71 66 66 77 72 33 67 35 6e 6e 2f 68 7a 31 37 30 34 69 38 6b 38 62 77 68 79 6f 31 2e 70 68 70 3f 6c 3d 6b 79 77 74 39 2e 63 61 62 22 2c } //00 00 
	condition:
		any of ($a_*)
 
}
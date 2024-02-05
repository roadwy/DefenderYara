
rule TrojanDownloader_O97M_Powdow_DPH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DPH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 5e 75 5e 72 6c 68 74 74 5e 70 3a 2f 2f 31 38 38 2e 33 34 2e 31 38 37 2e 31 31 30 2f 31 32 33 34 2e 73 34 79 74 6a 71 6e 6f 5e 78 73 34 79 74 6a 71 6e 6f 2d 6f 22 26 68 67 6d 66 } //01 00 
		$a_01_1 = {61 5f 64 5f 66 2c 6f 70 65 6e 75 72 6c 22 26 66 70 34 66 77 75 74 66 73 32 6e 2c } //01 00 
		$a_01_2 = {3d 72 65 70 6c 61 63 65 28 22 40 6f 72 40 69 6c 65 73 22 2c 22 40 22 2c 22 66 22 29 72 65 63 6f 2e 73 } //00 00 
	condition:
		any of ($a_*)
 
}
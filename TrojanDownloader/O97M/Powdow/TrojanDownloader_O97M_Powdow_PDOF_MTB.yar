
rule TrojanDownloader_O97M_Powdow_PDOF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDOF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 6f 70 65 6e 28 29 3d 22 72 75 6e 24 33 32 23 3e 7e 2e 24 2c 23 3e 6c 6c 65 78 65 63 2a 75 6e 24 22 22 25 40 22 22 22 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 6e 64 73 61 66 65 74 79 2e 78 79 7a 2f 70 2f 37 2e 68 74 6d 6c 22 22 22 3a 3a 3a 3a 3a 3d 76 62 61 2e } //01 00 
		$a_01_1 = {2e 72 65 70 6c 61 63 65 28 2c 22 3e 22 2c 22 68 65 22 29 3a 3a 3a 3a 3a 73 65 74 3d 67 65 74 6f 62 6a 65 63 74 28 22 6e 65 77 3a 7b 37 32 63 32 34 64 64 35 2d 64 37 30 61 2d 34 33 38 62 2d 38 61 34 32 2d 39 38 34 32 34 62 38 38 61 66 62 38 7d 22 29 3a 3a 3a 3a 3a 3a 3a 73 65 74 3d 5f 2e 5f 5f 65 78 65 63 23 28 29 65 6e 64 73 75 62 } //00 00 
	condition:
		any of ($a_*)
 
}
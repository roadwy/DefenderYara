
rule TrojanDownloader_O97M_Powdow_RVCA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {67 65 74 6f 62 6a 65 63 74 28 22 6e 65 77 3a 7b 37 32 63 32 34 64 64 35 2d 64 37 30 61 2d 34 33 38 62 2d 38 61 34 32 2d 39 38 34 32 34 62 38 38 61 66 62 38 7d 22 29 3a 3a 3a 3a 3a 73 65 74 72 3d 5f 2e 5f 5f 65 78 65 63 90 02 01 28 78 78 78 78 78 78 6c 6f 72 61 29 65 6e 64 73 75 62 90 00 } //01 00 
		$a_01_1 = {78 78 78 78 78 78 6c 6f 72 61 3d 2e 31 2e 63 6f 6e 74 72 6f 6c 74 69 70 74 65 78 74 2b 2e 32 2e 76 61 6c 75 65 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 64 65 62 75 67 2e 70 72 69 6e 74 } //01 00  xxxxxxlora=.1.controltiptext+.2.value:::::::::::::::::::::::::debug.print
		$a_01_2 = {73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 3a 3a } //00 00  subworkbook_open()::
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_RVCA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 5e 90 02 14 72 73 5e 68 90 1b 00 6c 6c 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 73 3a 2f 2f 74 72 61 6e 73 66 90 1b 00 72 2e 73 68 2f 67 90 1b 00 74 2f 90 02 1e 2f 90 02 0a 2e 90 1b 00 5e 78 90 1b 00 20 2d 6f 20 22 20 26 20 90 02 20 20 26 20 22 3b 22 20 26 20 90 02 20 2c 20 22 90 1b 00 22 2c 20 22 65 22 29 90 00 } //01 00 
		$a_03_1 = {47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 22 20 26 20 90 02 14 20 26 20 22 44 35 2d 44 37 30 41 2d 34 33 22 20 26 20 6d 67 6b 73 20 26 20 22 42 2d 38 41 34 32 2d 39 38 34 22 20 26 20 43 4c 6e 67 28 90 01 03 29 20 26 20 22 34 42 38 22 20 26 20 6d 67 6b 73 20 26 20 22 41 46 42 22 20 26 20 6d 67 6b 73 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
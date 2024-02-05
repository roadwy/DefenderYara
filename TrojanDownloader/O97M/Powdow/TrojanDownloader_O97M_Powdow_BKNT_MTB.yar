
rule TrojanDownloader_O97M_Powdow_BKNT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKNT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 62 75 69 6c 64 69 6e 67 73 6f 63 69 65 74 79 2e 62 61 74 22 } //01 00 
		$a_01_1 = {70 6f 77 65 72 72 20 26 20 72 6c 20 26 20 22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 } //01 00 
		$a_01_2 = {2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 66 61 63 74 66 72 69 65 6e 64 2e 65 78 65 } //01 00 
		$a_03_3 = {43 61 6c 6c 20 90 02 0f 2e 4f 70 65 6e 28 90 02 0f 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
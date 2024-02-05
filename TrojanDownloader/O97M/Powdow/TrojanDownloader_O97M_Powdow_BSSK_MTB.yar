
rule TrojanDownloader_O97M_Powdow_BSSK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BSSK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 64 73 73 64 64 2e 63 6d 7a 64 22 } //01 00 
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 68 61 70 70 65 6e 62 75 79 2c 20 22 2e 63 6d 7a 22 2c 20 22 2e 63 6d 22 29 } //01 00 
		$a_01_2 = {44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 70 72 65 73 69 64 65 6e 74 6c 6f 77 2e 65 60 78 65 } //01 00 
		$a_01_3 = {3d 20 64 6f 67 77 61 74 65 72 28 30 2c 20 22 6f 70 65 6e 22 2c 20 22 65 78 70 6c 6f 72 65 72 22 2c 20 68 61 70 70 65 6e 62 75 79 2c 20 22 22 2c 20 31 29 } //00 00 
	condition:
		any of ($a_*)
 
}
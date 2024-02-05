
rule TrojanDownloader_O97M_Powdow_YE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.YE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 74 74 61 63 6b 31 20 3d 20 22 5e 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 24 4d 6f 3d 40 28 } //01 00 
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 7b 69 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 4c 65 76 65 6c 3d 69 6d 70 65 72 73 6f 6e 61 74 65 7d } //01 00 
		$a_01_2 = {72 6f 6f 74 5c 63 69 6d 76 32 } //01 00 
		$a_01_3 = {6f 62 6a 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 28 52 65 70 6c 61 63 65 28 61 74 74 61 63 6b 31 2c 20 22 5e 22 2c 20 22 50 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
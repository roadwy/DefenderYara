
rule TrojanDownloader_O97M_Powdow_ANDT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ANDT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } //01 00 
		$a_01_1 = {2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //01 00 
		$a_01_2 = {74 74 70 73 3a 2f 2f 70 69 63 6b 6c 65 62 61 6c 6c 72 65 64 75 63 65 72 2e 63 6f 6d 2f 72 6f 62 6f 74 2f 74 6f 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_ANDT_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ANDT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 22 20 26 20 68 65 6c 6c 6c 20 26 20 22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 20 68 74 74 60 70 73 3a 2f 2f 74 68 75 6e 64 65 72 63 72 61 63 6b 2e 6f 72 67 2f 6f 66 66 75 70 64 61 74 65 2e 65 78 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 65 76 65 72 79 6f 6e 65 68 69 67 68 2e 65 78 65 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 65 76 65 72 79 6f 6e 65 68 69 67 68 2e 65 78 65 } //01 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 66 73 76 2e 62 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}
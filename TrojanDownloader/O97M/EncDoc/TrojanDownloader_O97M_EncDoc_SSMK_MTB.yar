
rule TrojanDownloader_O97M_EncDoc_SSMK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 62 6e 6d 2e 6e 61 76 65 72 63 6c 6f 75 64 2e 6f 72 67 2f 6d 6f 6e 67 6f 2f 72 74 76 77 69 79 64 6f 2e 67 69 66 } //01 00 
		$a_01_1 = {3a 66 74 70 3a 2f 2f 6d 6f 6e 3a 64 62 40 } //01 00 
		$a_01_2 = {72 65 67 73 76 72 33 32 20 2f 75 20 2f 6e 20 2f 73 20 2f 69 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_SSMK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 74 52 58 52 54 42 4a 56 4a 50 53 57 4a 4c 4c 4c 54 4f 52 43 42 43 42 48 42 59 44 42 49 44 47 5a 55 55 58 48 56 5a 48 4e 4e 54 47 42 58 5a 48 45 4b 4c 51 59 4f 56 46 53 4b 52 59 43 56 48 4e 59 59 42 47 4b 58 3a 2f 2f 33 38 31 40 5d 38 35 32 33 40 29 28 23 5c 2b 24 3c 35 3d 34 30 3d 23 25 34 29 36 36 25 5f 35 2a 5b 35 5e 2f 36 2d 24 5d 3c 35 32 5d 5b 28 31 38 39 40 5d 5e 3c 40 3c 28 3d 37 34 21 35 34 36 34 39 5e 36 23 31 33 32 31 40 5d 38 35 32 33 40 29 28 23 5c 2b 24 3c 35 3d 34 30 3d 23 25 34 29 36 36 25 5f 35 2a 5b 35 5e 2f 36 2d 24 5d 3c 35 32 5d 5b 28 31 38 39 40 5d 5e 3c 40 3c 28 3d 37 34 21 35 34 36 34 39 5e 36 23 31 30 31 90 02 6f 34 35 2f 33 33 2f 45 6e 63 90 02 6f 74 78 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
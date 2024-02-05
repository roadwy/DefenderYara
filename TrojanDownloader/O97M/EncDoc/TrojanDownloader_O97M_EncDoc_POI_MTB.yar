
rule TrojanDownloader_O97M_EncDoc_POI_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.POI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 6b 20 70 5e 6f 77 65 72 5e 73 68 65 6c 6c 20 2d 77 20 31 20 28 6e 45 77 2d 6f 42 6a 65 60 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } //01 00 
		$a_01_1 = {28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 2e 49 6e 76 6f 6b 65 28 28 27 68 74 27 2b 27 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 6d 67 67 4d 38 69 41 27 29 2c 27 76 6a 2e 65 78 65 27 29 } //01 00 
		$a_01_2 = {24 65 6e 76 3a 61 70 70 64 61 74 61 3b } //00 00 
	condition:
		any of ($a_*)
 
}
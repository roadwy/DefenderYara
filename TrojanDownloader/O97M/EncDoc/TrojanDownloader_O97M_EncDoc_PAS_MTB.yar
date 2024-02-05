
rule TrojanDownloader_O97M_EncDoc_PAS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 6f 62 6a 65 63 74 28 73 74 72 72 65 76 65 72 73 65 5f 28 22 30 22 2b 22 30 22 2b 22 30 22 2b 22 30 22 2b 22 34 } //01 00 
		$a_01_1 = {30 22 2b 22 37 22 2b 22 33 22 2b 22 31 22 2b 22 3a 22 2b 22 77 22 2b 22 65 22 2b 22 6e 22 29 29 65 6e 64 66 75 6e 63 74 69 6f 6e } //01 00 
		$a_01_2 = {6f 70 65 6e 28 29 64 69 6d 6f 62 6a 61 73 6e 65 77 63 6c 61 73 73 31 63 61 6c 6c 6f 62 6a 2e 6a 61 6e 75 67 2e 73 68 65 6c 6c 65 78 65 63 75 74 65 28 6b 31 2e 75 31 2e 63 6f 6e 74 72 6f 6c 74 69 70 74 65 78 74 2c 22 68 74 74 70 73 3a 2f 2f 62 69 74 6c 79 2e 63 6f 6d 2f 65 79 77 75 69 71 64 68 6e 6a 6b 61 73 62 64 6a 73 67 68 61 68 22 2c 22 22 2c 22 6f 70 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_O97M_EncDoc_PAAZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 68 74 74 70 73 3a 2f 2f 75 72 62 69 22 26 22 7a 73 74 61 72 22 26 22 74 75 22 26 22 70 2e 63 22 26 22 6f 22 26 22 6d 2f 63 22 26 22 79 4c 35 22 26 22 66 7a 5a 22 26 22 67 62 22 26 22 48 38 2f 48 22 26 22 6e 66 22 26 22 68 6f 2e 70 6e 22 26 22 67 } //01 00 
		$a_01_1 = {22 68 74 74 70 73 3a 2f 2f 61 72 22 26 22 79 61 22 26 22 6e 67 6c 22 26 22 6f 62 61 6c 73 63 22 26 22 68 6f 22 26 22 6f 6c 2e 69 22 26 22 6e 2f 4c 32 58 22 26 22 65 34 50 22 26 22 61 53 70 22 26 22 77 22 26 22 59 69 2f 48 6e 22 26 22 66 68 22 26 22 6f 2e 70 6e 22 26 22 67 } //01 00 
		$a_01_2 = {22 68 74 74 70 73 3a 2f 2f 67 22 26 22 75 72 75 22 26 22 6e 61 22 26 22 6e 61 6b 69 22 26 22 6e 74 65 22 26 22 72 6e 22 26 22 61 74 69 22 26 22 6f 6e 22 26 22 61 6c 2e 63 22 26 22 6f 22 26 22 6d 2f 37 22 26 22 5a 66 6c 52 22 26 22 31 75 22 26 22 62 69 62 22 26 22 4e 54 2f 48 22 26 22 6e 66 22 26 22 68 22 26 22 6f 2e 70 6e 22 26 22 67 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_O97M_Emotet_SVS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SVS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 75 70 73 63 61 6c 69 66 6f 72 6e 69 61 2e 75 73 2f 6c 69 62 72 61 72 69 65 73 2f 56 44 75 39 6b 61 4d 75 2f 22 } //01 00 
		$a_01_1 = {3a 2f 2f 66 74 70 2e 79 6f 75 72 62 61 6e 6b 72 75 70 74 63 79 70 61 72 74 6e 65 72 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 6b 73 64 74 6a 66 46 6a 69 2f 22 } //01 00 
		$a_01_2 = {3a 2f 2f 77 65 62 62 61 6e 64 69 2e 68 75 2f 69 6d 61 67 65 2f 6d 37 49 7a 6a 57 51 66 74 51 31 4a 79 77 36 2f 22 } //01 00 
		$a_01_3 = {3a 2f 2f 7a 61 72 7a 61 6d 6f 72 61 2e 63 6f 6d 2e 6d 78 2f 63 67 69 2d 62 69 6e 2f 68 41 75 47 6a 36 35 53 75 4b 72 2f 22 } //00 00 
	condition:
		any of ($a_*)
 
}
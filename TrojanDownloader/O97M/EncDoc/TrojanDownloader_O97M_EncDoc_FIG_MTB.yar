
rule TrojanDownloader_O97M_EncDoc_FIG_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.FIG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 62 68 74 74 2e 76 6e 2f 64 73 2f 30 32 31 32 32 30 2e 67 69 66 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 68 6f 70 65 65 2e 67 72 2f 64 73 2f 30 32 31 32 32 30 2e 67 69 66 } //01 00 
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 67 65 72 72 75 73 69 2e 72 75 2f 64 73 2f 30 32 31 32 32 30 2e 67 69 66 } //01 00 
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 70 72 6f 63 6f 2e 6c 74 2f 64 73 2f 30 32 31 32 32 30 2e 67 69 66 } //01 00 
		$a_01_4 = {68 74 74 70 73 3a 2f 2f 6c 65 6e 69 6d 61 72 2e 63 6f 6d 2f 64 73 2f 30 32 31 32 32 30 2e 67 69 66 } //01 00 
		$a_01_5 = {63 68 74 66 6a 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}
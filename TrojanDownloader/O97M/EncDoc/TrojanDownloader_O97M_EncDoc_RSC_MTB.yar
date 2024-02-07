
rule TrojanDownloader_O97M_EncDoc_RSC_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RSC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 66 69 2e 63 6f 6d 2e 70 6c 2f 32 31 2e 74 78 74 90 0a 18 00 68 74 74 70 3a 2f 2f 90 00 } //02 00 
		$a_03_1 = {61 62 65 6c 6d 65 2e 63 6f 6d 2e 62 72 2f 32 31 2e 74 78 74 90 0a 1b 00 68 74 74 70 3a 2f 2f 90 00 } //02 00 
		$a_03_2 = {6c 75 70 61 70 6f 6c 69 74 69 63 61 2e 63 6f 6d 2e 62 72 2f 32 31 2e 74 78 74 90 0a 21 00 68 74 74 70 3a 2f 2f 90 00 } //02 00 
		$a_03_3 = {61 6c 6b 61 6e 66 61 74 69 68 2e 63 6f 6d 2f 32 31 2e 74 78 74 90 0a 1c 00 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_01_4 = {43 3a 5c 54 72 61 73 74 5c 46 72 69 6f 73 5c 47 6f 6c 61 73 44 68 } //00 00  C:\Trast\Frios\GolasDh
	condition:
		any of ($a_*)
 
}
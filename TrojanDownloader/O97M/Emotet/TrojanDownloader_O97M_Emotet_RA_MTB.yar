
rule TrojanDownloader_O97M_Emotet_RA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {5c 73 6f 61 6d ?? 2e 4f 43 58 } //1
		$a_03_1 = {5c 73 6f 61 6d ?? 2e 6f 63 78 } //1
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //5 URLDownloadToFileA
		$a_01_3 = {75 72 6c 6d 6f 6e } //5 urlmon
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=11
 
}
rule TrojanDownloader_O97M_Emotet_RA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 28 [0-35] 2c 20 [0-25] 2c 20 [0-25] 2c 20 [0-25] 29 } //1
		$a_03_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-20] 28 [0-20] 2e [0-45] 29 29 } //1
		$a_03_2 = {2e 52 65 70 6c 61 63 65 [0-01] 28 [0-15] 2c 20 [0-15] 2e [0-18] 2c 20 22 22 29 } //1
		$a_03_3 = {3d 20 4d 73 67 42 6f 78 28 [0-20] 2e [0-20] 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 [0-20] 2e [0-20] 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
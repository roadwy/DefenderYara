
rule TrojanDownloader_O97M_Obfuse_SKR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SKR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 22 22 22 22 20 2b 20 22 6d 73 22 20 2b 20 22 68 74 61 22 22 22 22 68 74 74 70 73 3a 5c 5c 25 34 30 25 34 30 40 6a 2e 6d 70 5c 90 02 14 22 22 22 90 00 } //01 00 
		$a_01_1 = {53 75 62 20 63 61 6c 63 75 6c 61 74 6f 72 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SKR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SKR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 22 22 22 22 20 2b 20 22 6d 73 22 20 2b 20 22 68 74 61 22 22 22 22 22 20 2b 20 22 68 74 74 70 73 3a 5c 5c 25 34 30 25 34 30 40 6a 2e 6d 70 5c 90 02 14 22 22 22 90 00 } //01 00 
		$a_01_1 = {53 75 62 20 41 75 74 6f 5f 43 6c 6f 73 65 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
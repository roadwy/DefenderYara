
rule TrojanDownloader_O97M_Obfuse_JAQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JAQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_03_1 = {68 74 74 70 3a 2f 2f 73 70 61 72 65 70 61 72 74 69 72 61 6e 2e 63 6f 6d 2f 6a 73 2f 73 30 2f 90 02 0f 2e 6a 70 67 90 00 } //01 00 
		$a_03_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 22 20 2b 22 90 02 2e 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
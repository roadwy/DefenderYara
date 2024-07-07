
rule TrojanDownloader_O97M_Lokibot_NA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Lokibot.NA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 73 70 61 72 65 70 61 72 74 69 72 61 6e 2e 63 6f 6d 2f 6a 73 2f 64 31 2f 90 02 14 2e 65 78 65 90 00 } //1
		$a_02_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 22 20 2b 22 90 02 32 2e 65 78 65 90 00 } //1
		$a_02_2 = {53 68 65 6c 6c 28 90 02 32 2c 90 00 } //1
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_4 = {75 72 6c 6d 6f 6e } //1 urlmon
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
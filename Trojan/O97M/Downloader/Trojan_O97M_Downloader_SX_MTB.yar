
rule Trojan_O97M_Downloader_SX_MTB{
	meta:
		description = "Trojan:O97M/Downloader.SX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3a 5c 47 72 61 76 69 74 79 5c 47 72 61 76 69 74 79 32 90 02 06 70 6e 67 21 90 02 06 68 74 74 70 3a 2f 2f 65 72 69 6b 76 61 6e 77 65 6c 2e 6e 6c 2f 78 79 71 66 6f 73 6e 6d 63 6d 71 2f 90 00 } //1
		$a_81_1 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //1 CreateDirectoryA
		$a_81_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_03_3 = {65 78 70 6c 6f 72 65 72 90 02 0a 3a 5c 47 72 61 76 69 74 79 5c 47 72 61 76 69 74 79 32 5c 90 02 0a 2e 65 78 65 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
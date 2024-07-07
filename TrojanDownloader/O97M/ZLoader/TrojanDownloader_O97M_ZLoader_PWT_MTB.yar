
rule TrojanDownloader_O97M_ZLoader_PWT_MTB{
	meta:
		description = "TrojanDownloader:O97M/ZLoader.PWT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 64 6f 77 6e 6c 66 69 6c 65 32 34 2e 74 6f 70 2f 6b 64 6a 61 73 64 2e 70 68 70 } //1 https://downlfile24.top/kdjasd.php
		$a_01_1 = {43 3a 5c 54 6c 4c 6c 77 71 4a 5c 73 50 79 4a 50 4c 58 5c 59 79 49 55 77 51 76 2e 64 6c 6c } //1 C:\TlLlwqJ\sPyJPLX\YyIUwQv.dll
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
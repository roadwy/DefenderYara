
rule TrojanDownloader_O97M_ZLoader_PLL_MTB{
	meta:
		description = "TrojanDownloader:O97M/ZLoader.PLL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 70 75 72 65 64 6f 63 32 30 32 30 2e 74 6f 70 2f 64 6c 6c 44 64 73 32 32 78 64 64 66 32 33 32 2f 78 6c 73 2e 63 31 30 } //1 https://puredoc2020.top/dllDds22xddf232/xls.c10
		$a_01_1 = {43 3a 5c 61 75 4f 49 78 64 6d 5c 6d 6b 70 62 55 62 47 5c 79 42 4b 54 4f 72 49 2e 64 6c 6c } //1 C:\auOIxdm\mkpbUbG\yBKTOrI.dll
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
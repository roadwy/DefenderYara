
rule TrojanDownloader_O97M_Donoff_DL{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DL,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 35 31 2e 37 35 2e 31 33 33 2e 31 36 35 } //4 http://51.75.133.165
		$a_00_1 = {57 69 6e 64 6f 77 73 5c 5c 54 65 6d 70 5c 5c 4d 69 63 72 6f 73 6f 66 74 4f 66 66 69 63 65 57 6f 72 64 2e 65 78 65 22 } //4 Windows\\Temp\\MicrosoftOfficeWord.exe"
		$a_02_2 = {3d 20 22 43 3a 5c 5c 57 69 6e 64 6f 77 73 5c 5c 54 65 6d 70 5c 5c [0-20] 2e 65 78 65 22 } //2
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 22 } //2 URLDownloadToFile Lib "urlmon"
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 67 65 74 55 72 6c 2c 20 67 65 74 50 74 68 2c 20 30 2c 20 30 29 } //2 URLDownloadToFile(0, getUrl, getPth, 0, 0)
		$a_02_5 = {43 61 6c 6c 20 53 68 65 6c 6c 28 [0-10] 29 } //2
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*4+(#a_02_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_02_5  & 1)*2) >=8
 
}
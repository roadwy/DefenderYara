
rule TrojanDownloader_Linux_Adnel_G{
	meta:
		description = "TrojanDownloader:Linux/Adnel.G,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c } //1 Lib "shell32.dll" Alias "ShellExecuteA" (ByVal
		$a_01_1 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c } //1 Lib "urlmon" Alias "URLDownloadToFileA" (ByVal
		$a_01_2 = {30 2c 20 22 6f 70 65 6e 22 2c 20 45 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29 20 26 } //1 0, "open", Environ$("tmp") &
		$a_01_3 = {22 29 2c 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 } //1 "), Environ("temp") &
		$a_01_4 = {26 20 43 68 72 28 41 73 63 28 4d 69 64 28 } //1 & Chr(Asc(Mid(
		$a_01_5 = {2c 20 31 29 29 20 2d 20 41 73 63 28 4d 69 64 28 } //1 , 1)) - Asc(Mid(
		$a_01_6 = {20 3d 20 53 74 72 52 65 76 65 72 73 65 28 } //1  = StrReverse(
		$a_01_7 = {22 29 2c 20 22 22 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 } //1 "), "", vbNullString, vbNormalFocus
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}

rule TrojanDownloader_O97M_Mulseyco_A{
	meta:
		description = "TrojanDownloader:O97M/Mulseyco.A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c } //1 ShellExecuteA" (ByVal
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c } //1 URLDownloadToFileA" (ByVal
		$a_01_2 = {79 6c 6c 4d 20 3d 20 22 33 36 30 73 65 63 75 72 69 74 79 2e 65 78 65 } //1 yllM = "360security.exe
		$a_01_3 = {45 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29 20 26 20 22 5c 22 20 26 20 79 6c 6c 4d } //1 Environ$("tmp") & "\" & yllM
		$a_01_4 = {43 68 61 6e 67 65 54 65 78 74 20 30 2c 20 22 6f 70 65 6e } //1 ChangeText 0, "open
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}

rule TrojanDownloader_O97M_Jaranat_A{
	meta:
		description = "TrojanDownloader:O97M/Jaranat.A,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Document_Open()
		$a_00_1 = {22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } //1 "URLDownloadToFileA"
		$a_00_2 = {22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 } //1 "ShellExecuteA"
		$a_00_3 = {22 75 72 6c 6d 6f 6e 22 } //1 "urlmon"
		$a_00_4 = {4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 } //1 Lib "shell32.dll"
		$a_02_5 = {2e 65 78 65 2e 45 58 45 22 [0-20] 45 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}
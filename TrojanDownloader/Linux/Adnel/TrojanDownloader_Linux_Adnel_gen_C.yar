
rule TrojanDownloader_Linux_Adnel_gen_C{
	meta:
		description = "TrojanDownloader:Linux/Adnel.gen!C,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_01_1 = {2c 20 30 2c 20 30 29 } //1 , 0, 0)
		$a_03_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 (41 70 70 44 61 74 61|54 65 6d 70) 22 29 20 26 20 22 5c 22 20 26 20 22 [0-26] 2e 90 05 05 03 22 20 26 65 78 65 22 } //1
		$a_01_3 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 5f } //1 Lib "urlmon" Alias "URLDownloadToFileA" _
		$a_02_4 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 [0-09] 72 69 70 74 2e 73 68 90 05 05 03 22 20 26 65 6c 90 05 05 03 22 20 26 6c 22 29 [0-26] 2e (65 78 65 63|72 75 6e) } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}
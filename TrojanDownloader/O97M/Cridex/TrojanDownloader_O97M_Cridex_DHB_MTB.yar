
rule TrojanDownloader_O97M_Cridex_DHB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Cridex.DHB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c 20 [0-30] 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 [0-30] 20 41 73 20 53 74 72 69 6e 67 2c 20 5f } //1
		$a_81_1 = {22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c 20 } //1 "URLDownloadToFileA" (ByVal 
		$a_81_2 = {3d 20 45 6e 76 69 72 6f 6e } //1 = Environ
		$a_81_3 = {41 70 70 44 61 74 61 20 3d 20 41 70 70 44 61 74 61 20 26 20 43 68 72 28 41 73 63 28 78 29 20 2d 20 31 29 } //1 AppData = AppData & Chr(Asc(x) - 1)
		$a_81_4 = {3d 20 22 66 61 64 7a 6a 67 64 69 6c 61 7a 75 22 } //1 = "fadzjgdilazu"
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}

rule TrojanDownloader_O97M_Donoff_AE{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AE,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 90 02 20 55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f 90 00 } //1
		$a_02_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 22 90 05 20 06 61 2d 7a 30 2d 39 2e 73 63 72 22 90 00 } //1
		$a_01_2 = {3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 55 52 4c 2c 20 57 48 45 52 45 2c 20 30 2c 20 30 29 } //1 = URLDownloadToFile(0, URL, WHERE, 0, 0)
		$a_01_3 = {29 2e 52 75 6e 20 57 48 45 52 45 } //1 ).Run WHERE
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
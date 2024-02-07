
rule TrojanDownloader_O97M_Bartallex_I{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.I,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c } //01 00  Lib "urlmon" Alias "URLDownloadToFileA" (ByVal
		$a_01_1 = {4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 47 65 74 54 65 6d 70 50 61 74 68 41 } //01 00  Lib "kernel32" Alias "GetTempPathA
		$a_01_2 = {48 54 54 50 66 69 6c 65 20 3d 20 22 68 74 74 70 3a 2f 2f } //01 00  HTTPfile = "http://
		$a_03_3 = {4c 6f 63 61 6c 46 69 6c 65 20 3d 20 73 50 61 74 68 20 26 20 22 90 02 08 2e 65 78 65 90 00 } //01 00 
		$a_01_4 = {53 68 65 6c 6c 20 4c 6f 63 61 6c 46 69 6c 65 2c 20 76 62 48 69 64 65 } //00 00  Shell LocalFile, vbHide
	condition:
		any of ($a_*)
 
}
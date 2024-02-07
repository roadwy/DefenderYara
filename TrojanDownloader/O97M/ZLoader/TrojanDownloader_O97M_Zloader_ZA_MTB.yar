
rule TrojanDownloader_O97M_Zloader_ZA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Zloader.ZA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 76 69 72 6f 6e 24 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 22 20 26 } //01 00  Environ$("AppData") & "\" &
		$a_01_1 = {44 65 63 72 79 70 74 28 22 66 79 66 2f 74 74 73 64 22 29 } //01 00  Decrypt("fyf/ttsd")
		$a_01_2 = {41 70 70 44 61 74 61 20 26 20 43 68 72 28 41 73 63 28 62 29 20 2d 20 31 29 } //01 00  AppData & Chr(Asc(b) - 1)
		$a_01_3 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 65 6e 63 29 } //01 00  = StrReverse(enc)
		$a_01_4 = {4c 4f 50 20 26 20 43 68 72 28 41 73 63 28 4d 69 64 28 4a 4f 4f 4f 4b 2c 20 56 4f 4e 2c 20 31 29 29 20 2d 20 31 33 29 } //01 00  LOP & Chr(Asc(Mid(JOOOK, VON, 1)) - 13)
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}
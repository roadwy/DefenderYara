
rule TrojanDownloader_O97M_Donoff_YH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.YH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 72 65 62 72 61 6e 64 2e 6c 79 2f 6f 68 78 6e 71 61 6b } //01 00  http://rebrand.ly/ohxnqak
		$a_01_1 = {53 68 65 6c 6c 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 63 72 73 63 73 73 2e 65 78 65 } //01 00  Shell "C:\Users\Public\crscss.exe
		$a_01_2 = {46 75 6e 63 74 69 6f 6e 20 76 43 45 4e 6c 67 28 55 52 4c 2c 20 70 61 74 68 29 20 41 73 20 42 6f 6f 6c 65 61 6e } //00 00  Function vCENlg(URL, path) As Boolean
	condition:
		any of ($a_*)
 
}
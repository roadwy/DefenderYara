
rule TrojanDownloader_O97M_Gozi_LIU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.LIU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6c 69 76 65 73 77 69 6e 64 6f 77 73 2e 63 79 6f 75 2f 6f 70 7a 69 30 6e 31 2e 64 6c 6c } //1 http://liveswindows.cyou/opzi0n1.dll
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {43 3a 5c 47 51 6c 79 6c 59 7a 5c 56 55 77 65 76 68 6c 5c 57 47 6e 71 4c 6e 72 2e 64 6c 6c } //1 C:\GQlylYz\VUwevhl\WGnqLnr.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
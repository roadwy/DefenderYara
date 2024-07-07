
rule TrojanDownloader_O97M_Gozi_LIV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.LIV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6c 69 76 65 73 77 69 6e 64 6f 77 73 2e 63 61 73 61 2f 6f 70 7a 69 30 6e 31 2e 64 6c 6c 30 } //1 http://liveswindows.casa/opzi0n1.dll0
		$a_01_1 = {43 3a 5c 79 45 6f 69 70 54 67 5c 66 76 7a 43 74 54 69 5c 49 62 57 4c 71 7a 42 2e 64 6c 6c } //1 C:\yEoipTg\fvzCtTi\IbWLqzB.dll
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
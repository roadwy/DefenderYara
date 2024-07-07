
rule TrojanDownloader_O97M_Gozi_AGN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.AGN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 62 6c 6f 67 69 6c 69 76 65 2e 62 61 72 2f 69 6e 73 74 61 6c 6c 61 2e 64 6c 6c } //1 http://blogilive.bar/installa.dll
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {43 3a 5c 75 6a 67 61 73 70 4e 5c 69 48 4e 4a 56 59 } //1 C:\ujgaspN\iHNJVY
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
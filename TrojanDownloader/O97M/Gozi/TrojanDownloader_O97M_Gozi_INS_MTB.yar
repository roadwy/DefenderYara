
rule TrojanDownloader_O97M_Gozi_INS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.INS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 70 72 65 6d 69 75 6d 63 6c 61 73 73 2e 62 61 72 2f 30 70 7a 69 6f 6e 61 6c 31 61 2e 64 6c 6c } //1 http://premiumclass.bar/0pzional1a.dll
		$a_01_1 = {43 3a 5c 7a 5a 43 67 65 4e 42 5c 57 4d 44 52 62 4b 4b } //1 C:\zZCgeNB\WMDRbKK
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
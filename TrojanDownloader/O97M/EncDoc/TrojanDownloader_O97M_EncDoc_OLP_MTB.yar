
rule TrojanDownloader_O97M_EncDoc_OLP_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.OLP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {72 65 67 73 76 72 33 32 20 90 02 04 5c 70 6f 6c 79 31 2e 64 6c 6c 90 00 } //1
		$a_01_1 = {5c 70 6f 6c 79 32 2e 64 6c 6c } //1 \poly2.dll
		$a_01_2 = {2f 6d 6f 6f 6e 2e 68 74 6d 6c } //1 /moon.html
		$a_01_3 = {55 52 4c 4d 6f 6e } //1 URLMon
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
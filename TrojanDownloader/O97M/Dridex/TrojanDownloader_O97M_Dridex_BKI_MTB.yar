
rule TrojanDownloader_O97M_Dridex_BKI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.BKI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 4d 4f 4e } //1 URLMON
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 43 } //1 URLDownloadToFileAC
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 64 61 76 69 64 63 6f 72 74 65 73 2e 6f 74 74 69 6d 6f 73 6f 66 74 2e 63 6f 6d 2f 6e 37 72 35 37 74 33 2e 7a 69 70 43 } //1 https://davidcortes.ottimosoft.com/n7r57t3.zipC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
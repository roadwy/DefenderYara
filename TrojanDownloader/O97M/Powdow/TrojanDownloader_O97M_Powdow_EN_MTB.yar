
rule TrojanDownloader_O97M_Powdow_EN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.EN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 7a 6f 6e 69 63 73 65 6c 6c 65 72 2e 63 6f 6d 2f 90 02 10 2e 65 78 65 90 00 } //1
		$a_01_1 = {43 3a 5c 57 70 76 45 73 59 68 5c 69 67 6c 4a 51 58 42 5c 4f 4e 64 68 6a 62 42 2e 65 78 65 } //1 C:\WpvEsYh\iglJQXB\ONdhjbB.exe
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
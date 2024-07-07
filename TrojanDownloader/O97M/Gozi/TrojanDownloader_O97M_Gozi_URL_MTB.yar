
rule TrojanDownloader_O97M_Gozi_URL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.URL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6c 6f 67 2e 6c 65 6e 73 73 65 78 79 2e 63 6f 6d 2f 69 6e 73 74 61 6c 6c 61 7a 69 6f 6e 65 2e 64 6c 6c } //1 http://log.lenssexy.com/installazione.dll
		$a_01_1 = {61 73 46 73 71 6b 44 2e 64 6c 6c } //1 asFsqkD.dll
		$a_01_2 = {43 3a 5c 7a 57 47 51 57 53 65 } //1 C:\zWGQWSe
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_4 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
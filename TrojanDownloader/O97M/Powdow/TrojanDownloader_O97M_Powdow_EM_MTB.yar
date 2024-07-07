
rule TrojanDownloader_O97M_Powdow_EM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.EM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 75 74 6f 2d 6d 65 6e 74 6f 2e 68 75 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 67 75 69 64 65 2f 39 } //1 http://auto-mento.hu/wp-content/uploads/guide/9
		$a_01_1 = {65 6d 70 5c 6d 72 36 35 31 39 2e 65 78 65 } //1 emp\mr6519.exe
		$a_01_2 = {54 66 61 38 73 37 31 4d 56 53 } //1 Tfa8s71MVS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_EM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.EM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 6f 77 65 6e 74 69 2e 63 6f 6d 2f 90 02 10 2e 65 78 65 90 00 } //1
		$a_01_1 = {43 3a 5c 44 58 63 6b 61 47 50 5c 50 4f 53 70 77 45 69 5c 75 75 4c 4f 52 4a 68 2e 65 78 65 } //1 C:\DXckaGP\POSpwEi\uuLORJh.exe
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
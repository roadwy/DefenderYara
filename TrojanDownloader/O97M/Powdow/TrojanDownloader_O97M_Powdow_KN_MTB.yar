
rule TrojanDownloader_O97M_Powdow_KN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 6d 61 67 65 6d 53 69 6d 70 6c 65 73 43 44 54 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 34 73 79 6e 63 2e 63 6f 6d 2f 77 65 62 2f 64 69 72 65 63 74 44 6f 77 6e 6c 6f 61 64 2f 67 45 6b 66 39 34 55 72 2f 65 6f 6a 46 64 4a 36 52 2e 61 36 63 30 36 33 38 62 33 38 32 39 37 32 33 39 37 31 62 35 32 39 35 37 38 31 65 31 61 62 63 34 22 } //1 ImagemSimplesCDT = "https://www.4sync.com/web/directDownload/gEkf94Ur/eojFdJ6R.a6c0638b3829723971b5295781e1abc4"
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 49 6d 61 67 65 6d 53 69 6d 70 6c 65 73 43 44 54 2c 20 4d 61 73 74 65 72 43 44 54 20 26 20 22 64 6f 63 75 6d 65 6e 74 2e 76 62 73 22 2c 20 30 2c 20 30 } //1 URLDownloadToFile 0, ImagemSimplesCDT, MasterCDT & "document.vbs", 0, 0
		$a_01_2 = {52 65 6e 61 20 3d 20 6f 62 6a 65 74 6f 5f 64 6f 77 6e 6c 6f 61 64 5f 31 20 2b 20 6f 62 6a 65 74 6f 5f 64 6f 77 6e 6c 6f 61 64 5f 32 20 2b 20 6f 62 6a 65 74 6f 5f 64 6f 77 6e 6c 6f 61 64 5f 33 20 2b 20 6f 62 6a 65 74 6f 5f 64 6f 77 6e 6c 6f 61 64 5f 34 20 2b 20 6f 62 6a 65 74 6f 5f 64 6f 77 6e 6c 6f 61 64 5f 35 } //1 Rena = objeto_download_1 + objeto_download_2 + objeto_download_3 + objeto_download_4 + objeto_download_5
		$a_01_3 = {53 65 74 20 61 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 49 4e 53 45 55 52 5f 43 44 46 29 } //1 Set a = CreateObject(INSEUR_CDF)
		$a_01_4 = {61 2e 52 75 6e 20 28 4d 5f 53 20 2b 20 54 4f 47 41 43 44 54 20 2b 20 4d 5f 53 31 20 2b 20 4d 5f 53 32 20 2b 20 4d 5f 53 33 29 2c 20 30 } //1 a.Run (M_S + TOGACDT + M_S1 + M_S2 + M_S3), 0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
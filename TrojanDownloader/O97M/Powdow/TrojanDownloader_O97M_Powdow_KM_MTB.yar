
rule TrojanDownloader_O97M_Powdow_KM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 6d 61 67 65 6d 53 69 6d 70 6c 65 73 43 44 54 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 34 73 79 6e 63 2e 63 6f 6d 2f 77 65 62 2f 64 69 72 65 63 74 44 6f 77 6e 6c 6f 61 64 2f 4e 52 72 4b 63 68 35 59 2f 63 6d 6c 55 58 72 45 78 2e 65 63 36 39 32 34 65 36 37 63 38 64 32 63 30 66 62 34 32 37 64 66 39 35 30 38 36 39 32 33 32 61 22 } //1 ImagemSimplesCDT = "https://www.4sync.com/web/directDownload/NRrKch5Y/cmlUXrEx.ec6924e67c8d2c0fb427df950869232a"
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 49 6d 61 67 65 6d 53 69 6d 70 6c 65 73 43 44 54 2c 20 52 65 6e 61 6e 43 44 54 20 26 20 22 64 6f 63 75 6d 65 6e 74 2e 65 78 65 22 2c 20 30 2c 20 30 } //1 URLDownloadToFile 0, ImagemSimplesCDT, RenanCDT & "document.exe", 0, 0
		$a_01_2 = {4d 5f 53 20 3d 20 50 44 66 5f 31 20 2b 20 50 44 66 5f 43 44 54 } //1 M_S = PDf_1 + PDf_CDT
		$a_01_3 = {49 4e 47 52 49 44 43 44 54 20 3d 20 50 44 66 5f 32 20 2b 20 50 44 66 5f 33 } //1 INGRIDCDT = PDf_2 + PDf_3
		$a_01_4 = {53 68 65 6c 6c 20 28 4d 5f 53 20 2b 20 49 4e 47 52 49 44 43 44 54 20 2b 20 4d 5f 53 31 20 2b 20 4d 5f 53 32 20 2b 20 4d 5f 53 33 29 2c 20 30 } //1 Shell (M_S + INGRIDCDT + M_S1 + M_S2 + M_S3), 0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
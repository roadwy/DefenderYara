
rule TrojanDownloader_O97M_Obfuse_BBC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BBC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 20 3d 20 53 68 65 6c 6c 28 73 46 69 6c 65 50 61 74 68 20 2b 20 73 46 69 6c 65 4e 61 6d 65 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //1 co = Shell(sFilePath + sFileName, vbNormalFocus)
		$a_01_1 = {68 20 3d 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 50 49 28 73 46 69 6c 65 55 52 4c 2c 20 73 46 69 6c 65 50 61 74 68 20 26 20 73 46 69 6c 65 4e 61 6d 65 29 } //1 h = DownloadFileAPI(sFileURL, sFilePath & sFileName)
		$a_01_2 = {68 20 3d 20 28 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 73 46 69 6c 65 55 52 4c 2c 20 54 6f 50 61 74 68 4e 61 6d 65 2c 20 30 2c 20 30 29 20 3d 20 30 29 } //1 h = (URLDownloadToFile(0, sFileURL, ToPathName, 0, 0) = 0)
		$a_01_3 = {76 62 43 72 69 74 69 63 61 6c 2c 20 22 77 77 77 2e 65 78 63 65 6c 2d 76 62 61 2e 72 75 } //1 vbCritical, "www.excel-vba.ru
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
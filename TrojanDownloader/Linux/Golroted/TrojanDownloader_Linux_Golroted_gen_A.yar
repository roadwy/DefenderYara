
rule TrojanDownloader_Linux_Golroted_gen_A{
	meta:
		description = "TrojanDownloader:Linux/Golroted.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 28 30 2c 20 55 52 4c 2c 20 73 7a 46 69 6c 65 4e 61 6d 65 2c 20 4c 65 6e 28 73 7a 46 69 6c 65 4e 61 6d 65 29 2c 20 30 2c 20 30 29 20 3d 20 30 20 54 68 65 6e } //1 If URLDownloadToCacheFile(0, URL, szFileName, Len(szFileName), 0, 0) = 0 Then
		$a_01_1 = {54 65 6d 70 50 61 74 68 20 3d 20 52 65 70 6c 61 63 65 28 54 65 6d 70 50 61 74 68 2c 20 43 68 72 24 28 30 29 2c 20 22 22 29 } //1 TempPath = Replace(TempPath, Chr$(0), "")
		$a_01_2 = {3d 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 22 68 74 74 70 } //1 = DownloadFile("http
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
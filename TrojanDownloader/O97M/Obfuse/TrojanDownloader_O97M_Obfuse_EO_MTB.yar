
rule TrojanDownloader_O97M_Obfuse_EO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 44 6f 77 6e 6c 6f 61 64 55 70 64 61 74 65 46 69 6c 65 46 72 6f 6d 53 69 74 65 28 29 } //1 Sub DownloadUpdateFileFromSite()
		$a_03_1 = {6d 79 55 52 4c 20 3d 20 22 [0-05] 3a 2f 2f 77 77 77 2e 65 6d 6f 6a 69 66 6f 72 6f 75 74 6c 6f 6f 6b 2e 63 6f 6d 2f 45 6d 6f 6a 69 2f 56 65 72 73 69 6f 6e 73 2f 22 20 26 20 57 65 62 56 65 72 73 69 6f 6e 4e 61 6d 65 } //1
		$a_01_2 = {57 69 6e 48 74 74 70 52 65 71 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 6d 79 55 52 4c 2c 20 46 61 6c 73 65 } //1 WinHttpReq.Open "GET", myURL, False
		$a_01_3 = {6f 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 28 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 50 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 44 6f 77 6e 6c 6f 61 64 73 5c 22 20 26 20 57 65 62 56 65 72 73 69 6f 6e 4e 61 6d 65 29 } //1 oStream.SaveToFile (Environ("UserProfile") & "\Downloads\" & WebVersionName)
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
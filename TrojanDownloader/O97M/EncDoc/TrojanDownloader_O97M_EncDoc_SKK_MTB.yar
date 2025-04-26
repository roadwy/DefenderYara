
rule TrojanDownloader_O97M_EncDoc_SKK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SKK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 73 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 73 61 76 65 54 6f 2c 20 32 } //1 filestream.SaveToFile saveTo, 2
		$a_01_1 = {53 65 74 20 68 74 74 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //1 Set http = CreateObject("Microsoft.XMLHTTP")
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 55 52 4c 20 3d 20 68 74 74 70 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //1 DownloadURL = http.responseBody
		$a_01_3 = {53 65 74 20 53 68 65 6c 6c 41 70 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 Set ShellApp = CreateObject("Shell.Application")
		$a_01_4 = {68 6f 73 74 20 3d 20 22 68 74 74 70 73 3a 2f 2f 31 39 39 30 7a 68 2e 63 6f 6d 2f 22 } //1 host = "https://1990zh.com/"
		$a_01_5 = {53 61 76 65 46 69 6c 65 20 44 6f 77 6e 6c 6f 61 64 55 52 4c 28 75 72 6c 29 2c 20 6c 69 62 46 69 6c 65 } //1 SaveFile DownloadURL(url), libFile
		$a_01_6 = {7a 46 69 6c 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 26 20 22 5c 71 2e 7a 69 70 22 } //1 zFile = Environ("TMP") & "\q.zip"
		$a_01_7 = {53 61 76 65 46 69 6c 65 20 44 6f 77 6e 6c 6f 61 64 55 52 4c 28 68 6f 73 74 20 26 20 22 31 2e 77 61 76 22 29 2c 20 7a 46 69 6c 65 } //1 SaveFile DownloadURL(host & "1.wav"), zFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
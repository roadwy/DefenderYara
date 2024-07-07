
rule Trojan_BAT_Downloader_CAH_MTB{
	meta:
		description = "Trojan:BAT/Downloader.CAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 35 38 30 31 64 66 62 39 2d 38 38 34 33 2d 34 37 65 61 2d 38 65 64 62 2d 66 34 61 33 63 66 30 39 34 39 39 61 } //1 $5801dfb9-8843-47ea-8edb-f4a3cf09499a
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 73 74 6f 72 65 32 2e 67 6f 66 69 6c 65 2e 69 6f 2f 64 6f 77 6e 6c 6f 61 64 } //1 https://store2.gofile.io/download
		$a_81_2 = {43 41 70 31 32 2e 65 78 65 } //1 CAp12.exe
		$a_01_3 = {49 6e 76 6f 6b 65 48 65 6c 70 65 72 } //1 InvokeHelper
		$a_81_4 = {45 75 63 78 66 79 71 63 76 77 2e 64 6c 6c } //1 Eucxfyqcvw.dll
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_7 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*1+(#a_81_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
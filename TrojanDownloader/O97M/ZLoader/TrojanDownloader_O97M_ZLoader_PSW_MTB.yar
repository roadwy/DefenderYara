
rule TrojanDownloader_O97M_ZLoader_PSW_MTB{
	meta:
		description = "TrojanDownloader:O97M/ZLoader.PSW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 70 75 72 65 66 69 6c 65 32 34 2e 74 6f 70 2f 34 33 35 32 77 65 64 66 6f 69 66 6f 6d 2e 70 68 70 } //1 https://purefile24.top/4352wedfoifom.php
		$a_01_1 = {43 3a 5c 75 71 71 70 75 66 59 5c 66 4b 6b 57 6d 70 73 5c 76 4d 73 79 53 61 50 2e 64 6c 6c } //1 C:\uqqpufY\fKkWmps\vMsySaP.dll
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
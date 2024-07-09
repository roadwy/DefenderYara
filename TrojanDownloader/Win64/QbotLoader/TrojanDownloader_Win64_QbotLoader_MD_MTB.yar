
rule TrojanDownloader_Win64_QbotLoader_MD_MTB{
	meta:
		description = "TrojanDownloader:Win64/QbotLoader.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {63 75 72 6c 20 68 ?? 74 70 3a 2f 2f 31 30 39 2e 31 37 32 2e 34 35 2e 39 2f 4c 65 71 2f 31 35 20 2d 6f 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 64 65 66 61 75 6c 74 2e 70 6e 67 } //1
		$a_01_1 = {72 75 6e 64 6c 6c 33 32 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 64 65 66 61 75 6c 74 2e 70 6e 67 2c 70 72 69 6e 74 } //1 rundll32 c:\users\public\default.png,print
		$a_00_2 = {64 6c 6c 6d 61 69 6e 36 34 2e 64 6c 6c } //1 dllmain64.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}

rule TrojanDownloader_Win32_Tiny_AR_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tiny.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 63 73 35 5c 63 73 35 2e 65 78 65 } //1 C:\Users\Public\cs5\cs5.exe
		$a_81_1 = {68 74 74 70 3a 2f 2f 31 37 38 2e 36 32 2e 31 39 2e 36 36 2f 63 61 6d 70 6f 2f 76 2f 76 } //1 http://178.62.19.66/campo/v/v
		$a_81_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_81_3 = {75 72 6c 6d 6f 6e 2e 64 6c 6c } //1 urlmon.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
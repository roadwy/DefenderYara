
rule TrojanDownloader_Win32_Small_AHL{
	meta:
		description = "TrojanDownloader:Win32/Small.AHL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {76 65 72 00 75 75 00 00 2e 6c 6f 67 00 00 00 00 47 6c 6f 62 61 6c 5c 5f 5f 73 74 6f 70 [0-10] 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 29 [0-10] 68 74 74 70 3a 2f 2f 64 2e 72 6f 62 69 6e 74 73 2e 75 73 2f } //1
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 41 } //1 URLDownloadToCacheFileA
		$a_00_2 = {47 65 74 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 53 74 72 69 6e 67 41 } //1 GetPrivateProfileStringA
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
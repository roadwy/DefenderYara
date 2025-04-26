
rule TrojanDownloader_Win32_Small_VE{
	meta:
		description = "TrojanDownloader:Win32/Small.VE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 73 25 64 25 64 2e 65 78 65 00 00 55 52 4c 00 25 64 00 00 63 3a 5c 7a 2e 62 69 6e } //1
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c 25 73 00 7b 25 73 2d 25 73 2d 25 73 2d 25 73 2d 25 73 7d 00 00 00 00 5c 6c 73 61 73 73 2e 65 78 65 } //1
		$a_00_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
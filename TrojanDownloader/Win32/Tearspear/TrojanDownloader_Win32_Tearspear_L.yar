
rule TrojanDownloader_Win32_Tearspear_L{
	meta:
		description = "TrojanDownloader:Win32/Tearspear.L,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 79 69 68 61 68 61 2e 6e 65 74 2f } //1 http://www.yihaha.net/
		$a_01_1 = {67 65 74 75 72 6c 69 70 2e 61 73 70 3f 67 6f } //1 geturlip.asp?go
		$a_01_2 = {62 64 61 6c 69 70 61 79 43 6c 69 63 6b } //1 bdalipayClick
		$a_01_3 = {4f 6e 44 6f 77 6e 6c 6f 61 64 43 6f 6d 70 6c 65 74 65 } //1 OnDownloadComplete
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
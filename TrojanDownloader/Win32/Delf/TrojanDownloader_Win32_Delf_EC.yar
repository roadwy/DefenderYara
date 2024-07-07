
rule TrojanDownloader_Win32_Delf_EC{
	meta:
		description = "TrojanDownloader:Win32/Delf.EC,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 62 6f 74 2e 68 74 6d 6c 29 } //1 http://www.google.com/bot.html)
		$a_00_1 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_00_2 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //1 HttpSendRequestA
		$a_01_3 = {97 8b 8b 8f c5 d0 d0 97 8a 92 9d 9a 8d 8b 90 9c 90 8c 8b 9e d1 8e 8a 90 8b 9e 93 9a 8c 8c d1 9c 90 92 d0 86 d1 8b 87 8b } //4
		$a_01_4 = {97 8b 8b 8f c5 d0 d0 8c 96 93 89 9e 91 9e 8c 85 cb cd d1 98 90 90 98 93 9a 8f 9e 98 9a 8c d1 9c 90 92 d0 86 d1 8b 87 8b } //4
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4) >=6
 
}
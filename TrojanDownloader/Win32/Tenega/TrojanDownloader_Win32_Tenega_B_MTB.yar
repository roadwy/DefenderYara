
rule TrojanDownloader_Win32_Tenega_B_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tenega.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 28 80 f1 80 88 0c 28 8b 4c 24 10 40 3b c1 72 ee } //1
		$a_01_1 = {8b 55 fc 8a 1c 11 80 c3 7a 88 1c 11 8b 55 fc 8a 1c 11 80 c3 fd 88 1c 11 8b 55 fc 80 04 11 03 90 8b 55 fc 8a 1c 11 80 f3 19 88 1c 11 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Tenega_B_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/Tenega.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {78 7a 2e 6a 75 7a 69 72 6c 2e 63 6f 6d } //1 xz.juzirl.com
		$a_81_1 = {64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 } //1 download_quiet
		$a_81_2 = {50 72 6f 78 79 45 6e 61 62 6c 65 } //1 ProxyEnable
		$a_81_3 = {63 72 65 61 74 69 6e 67 20 73 6f 63 6b 65 74 } //1 creating socket
		$a_81_4 = {65 6d 70 74 79 20 68 6f 73 74 6e 61 6d 65 } //1 empty hostname
		$a_02_5 = {63 3a 5c 74 65 6d 70 5c 6e 73 90 02 0f 2e 74 6d 70 5c 90 02 0f 2e 64 6c 6c 90 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}
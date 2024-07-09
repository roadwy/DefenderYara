
rule TrojanDownloader_Win32_OnLineGames_C{
	meta:
		description = "TrojanDownloader:Win32/OnLineGames.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 6c 65 72 74 65 72 20 43 4f 4d 2b 00 } //1
		$a_01_1 = {42 41 43 4b 54 49 4d 45 00 } //1
		$a_01_2 = {5c 57 69 6e 64 6f 77 73 78 70 2e 69 6e 69 00 } //1
		$a_03_3 = {6a 00 68 00 00 00 04 6a 00 6a 00 90 04 01 04 50 51 56 57 90 04 01 02 56 57 ff 90 04 01 02 d3 d5 8b d0 85 d2 } //1
		$a_01_4 = {8a 08 2a ca 32 ca 88 08 40 4e 75 f4 } //1
		$a_01_5 = {74 78 78 7c 42 2f 2f } //1 txx|B//
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
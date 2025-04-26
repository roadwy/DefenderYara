
rule TrojanDownloader_Win32_Upatre{
	meta:
		description = "TrojanDownloader:Win32/Upatre,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 05 48 ab 5a bb 08 59 7a 14 4a ad 2b c3 89 07 03 fa 49 75 f6 } //1
		$a_03_1 = {40 00 41 5f 41 89 07 51 47 47 58 47 47 6a 05 48 ab 5a bb ?? ?? ?? ?? 4a 90 09 04 00 54 b8 } //1
		$a_03_2 = {bb 10 a4 38 22 58 48 ab 8b c6 8b 00 83 c6 04 8b d3 2b c2 ab 49 75 f1 e8 ?? ?? ?? ?? bf ?? ?? ?? ?? 5e 68 10 65 00 00 } //1
		$a_01_3 = {bb 54 c1 13 1f 54 41 5f ab 41 51 58 48 ab 51 6a 04 8b c6 8b c8 8b 00 59 03 f1 59 2b c3 ab e2 ee } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}
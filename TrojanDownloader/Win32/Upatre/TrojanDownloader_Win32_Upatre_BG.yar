
rule TrojanDownloader_Win32_Upatre_BG{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 c6 04 8b d7 8b 06 4f 33 c2 [0-01] 89 06 49 75 } //1
		$a_01_1 = {ac 3c 2e 72 09 3c 39 77 05 04 14 aa e2 f2 } //1
		$a_03_2 = {b8 30 75 00 00 89 06 6a 04 56 6a 06 ff 75 ?? ff 55 } //1
		$a_01_3 = {6a 12 ab ab 59 ab 41 ab 41 b8 46 00 00 00 57 48 48 ab 33 c0 ab e2 fd } //1
		$a_01_4 = {fc f3 ab b8 46 00 00 00 59 57 48 48 ab 33 c0 ab e2 fd } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}
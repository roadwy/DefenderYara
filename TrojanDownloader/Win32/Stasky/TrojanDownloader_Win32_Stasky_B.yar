
rule TrojanDownloader_Win32_Stasky_B{
	meta:
		description = "TrojanDownloader:Win32/Stasky.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {8d 45 f0 64 a3 00 00 00 00 89 65 e8 c7 45 fc 00 00 00 00 e4 02 c7 45 fc fe ff ff ff 32 c0 } //1
		$a_01_1 = {84 c0 74 09 68 80 ee 36 00 ff d6 eb ee 68 60 ea 00 00 ff d6 eb e5 } //1
		$a_03_2 = {68 00 01 00 84 56 56 50 ?? e8 ?? ?? ?? ?? ff d0 8b ?? 3b ?? 74 ?? 8d 4d ?? 51 8d 55 ?? 52 8d 45 ?? 50 68 05 00 00 20 } //1
		$a_03_3 = {83 65 fc 00 e4 02 (c7 45 fc fe ff ff ff|83 4d fc ff) 32 c0 } //1
		$a_03_4 = {84 c0 74 07 68 80 ee 36 00 eb 05 68 60 ea 00 00 (ff d6|ff 15 ?? ?? ??) ?? eb } //1
		$a_01_5 = {c7 45 fc 00 00 00 00 e4 02 c7 45 fc fe ff ff ff 32 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}
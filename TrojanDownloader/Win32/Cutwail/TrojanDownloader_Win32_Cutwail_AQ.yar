
rule TrojanDownloader_Win32_Cutwail_AQ{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d0 64 a1 30 00 00 00 8f 40 08 b8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 2d } //1
		$a_03_1 = {c6 03 8b ff 25 90 09 18 00 0f b6 1b 81 f3 ?? ?? ?? ?? 90 90 81 fb ?? ?? ?? ?? 75 09 8b 1d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule TrojanDownloader_Win32_Cutwail_AQ_2{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 14 02 32 14 31 02 d1 47 3b fd 88 14 31 72 d3 } //1
		$a_01_1 = {b9 19 00 00 00 f7 f1 80 c2 61 eb 1b 3c 58 75 1a } //1
		$a_01_2 = {8a 50 51 33 c9 80 fa 7a 0f 94 c1 8b c1 } //1
		$a_01_3 = {74 20 80 78 50 69 75 1a } //1
		$a_01_4 = {80 38 4d 75 20 80 78 01 5a 75 1a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}
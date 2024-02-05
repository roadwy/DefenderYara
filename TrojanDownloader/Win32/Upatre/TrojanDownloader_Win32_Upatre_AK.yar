
rule TrojanDownloader_Win32_Upatre_AK{
	meta:
		description = "TrojanDownloader:Win32/Upatre.AK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c2 14 0f b7 02 8d 54 10 04 6a 28 58 49 03 d0 e2 fc } //01 00 
		$a_01_1 = {8b 75 00 03 f7 8b c2 31 06 42 e2 f7 } //01 00 
		$a_03_2 = {66 81 3f 4d 5a 74 90 01 01 8b 90 01 01 ec 8b 55 c4 90 02 0a 3c 05 77 90 00 } //01 00 
		$a_01_3 = {a5 66 ad ab e2 fa 5b 33 c0 b4 04 50 } //01 00 
		$a_03_4 = {8b 4c 03 04 66 81 c9 20 20 90 02 04 81 e9 65 6c 33 32 90 00 } //01 00 
		$a_03_5 = {ac 3c 01 74 0f 84 c0 74 02 34 90 01 01 66 ab 41 84 c0 75 ee 90 00 } //01 00 
		$a_01_6 = {57 56 ad 33 c7 5f ab 8b f7 5f 4f 49 75 } //01 00 
		$a_01_7 = {6a 34 58 66 ab b0 31 66 ab b0 2f 66 ab 8a c1 04 30 66 ab b0 2f 66 ab } //01 00 
		$a_01_8 = {6a 34 58 66 ab 6a 2f 6a 31 58 66 ab 58 50 66 ab 8a c1 04 2f 40 66 ab } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_Win32_Harnig_gen_G{
	meta:
		description = "TrojanDownloader:Win32/Harnig.gen!G,SIGNATURE_TYPE_PEHSTR,15 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 30 48 74 1a 48 0f 85 b0 00 00 00 68 26 80 ac c8 6a 01 e8 dc ff ff ff 68 18 40 40 00 eb 24 } //7
		$a_01_1 = {68 26 80 ac c8 6a 01 e8 c3 ff ff ff 68 24 40 40 00 eb 37 68 26 80 ac c8 6a 01 e8 b0 ff ff ff 68 18 40 40 00 eb 24 68 26 80 ac c8 } //7
		$a_01_2 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad 8b 40 08 8b c8 89 45 08 8b 41 3c 8b 74 08 78 8b 45 0c c1 e8 10 03 f1 66 85 c0 75 09 0f b7 45 0c 2b 46 10 eb 4f 83 65 fc 00 } //9
		$a_01_3 = {8b 5e 24 57 8b 7e 20 03 f9 03 f9 83 7e 18 00 76 20 8b 45 08 03 07 50 e8 3e 00 00 00 3b 45 0c 74 21 ff 45 fc 8b 45 fc 83 c7 04 43 43 3b 46 18 72 e0 } //7
		$a_01_4 = {8b 4d fc 3b 4e 18 5f 5b 75 09 33 c0 eb 13 0f b7 03 eb ed 8b 4d 08 8b 56 1c 8d 04 82 8b 04 08 03 c1 } //7
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*7+(#a_01_2  & 1)*9+(#a_01_3  & 1)*7+(#a_01_4  & 1)*7) >=18
 
}
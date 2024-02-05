
rule TrojanDownloader_Win32_Dalexis_F{
	meta:
		description = "TrojanDownloader:Win32/Dalexis.F,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 7c 24 10 00 88 0a 74 05 30 0c 3e eb 03 30 04 3e 47 83 ff 10 75 02 33 ff } //05 00 
		$a_03_1 = {68 60 ea 00 00 b8 c0 d4 01 00 e8 90 01 04 8b 35 90 01 04 59 50 ff d6 3b df 5b 74 27 6a 0a 90 00 } //01 00 
		$a_01_2 = {25 30 38 78 2e 6a 70 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Dalexis_F_2{
	meta:
		description = "TrojanDownloader:Win32/Dalexis.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 6c 69 70 6f 70 67 61 2e 70 64 62 } //01 00 
		$a_01_1 = {42 68 58 59 4a 6d 6c 65 6e 78 48 66 78 } //01 00 
		$a_01_2 = {b9 c6 78 3e 17 81 e9 f6 71 3e 17 51 b8 c6 78 3e 17 2d f6 71 3e 17 50 be f6 71 42 17 81 ee f6 71 3e 17 } //01 00 
		$a_01_3 = {f8 83 d0 04 83 c3 f7 f7 d3 29 fb 43 29 ff 4f 21 df c1 c7 03 c1 c7 05 89 1e f8 83 d6 04 8d 52 fc } //00 00 
		$a_00_4 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}
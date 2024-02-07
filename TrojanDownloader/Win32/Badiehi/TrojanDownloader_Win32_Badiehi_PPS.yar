
rule TrojanDownloader_Win32_Badiehi_PPS{
	meta:
		description = "TrojanDownloader:Win32/Badiehi!PPS,SIGNATURE_TYPE_PEHSTR,17 00 16 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 77 73 00 2d 00 75 00 3d 00 00 00 41 63 63 65 70 74 3a 20 2a 2f 2a } //01 00 
		$a_01_1 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //01 00  Accept-Language: zh-cn
		$a_01_2 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 77 67 65 74 } //0a 00  User-Agent: wget
		$a_01_3 = {71 71 70 63 6d 67 72 00 47 45 54 25 73 48 54 54 50 2f 31 2e 31 } //0a 00 
		$a_01_4 = {83 c4 08 85 c0 74 0b 68 40 77 1b 00 ff } //00 00 
		$a_01_5 = {00 5d 04 00 00 e9 72 03 80 5c 24 00 00 ea 72 03 80 00 00 01 } //00 04 
	condition:
		any of ($a_*)
 
}
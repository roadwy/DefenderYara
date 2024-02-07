
rule TrojanDownloader_Win32_Climetop_B{
	meta:
		description = "TrojanDownloader:Win32/Climetop.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 09 68 90 01 04 ff 35 90 01 04 ff 15 90 01 04 83 f8 09 0f 87 90 01 02 ff ff 6a 00 6a 04 90 00 } //01 00 
		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 83 c0 0c 8b 00 3b 70 18 75 f9 } //01 00 
		$a_03_2 = {74 63 89 c6 ff 35 90 01 04 ff 15 90 01 04 6a 04 68 00 30 00 00 50 6a 00 56 ff 15 90 01 04 85 c0 74 40 90 00 } //01 00 
		$a_03_3 = {89 c1 80 33 90 01 01 43 e2 fa 90 00 } //01 00 
		$a_01_4 = {7b 37 38 34 39 35 39 36 61 2d 34 38 65 61 2d 34 38 36 65 2d 38 39 33 37 2d 61 32 61 33 30 30 39 66 33 31 61 39 7d } //00 00  {7849596a-48ea-486e-8937-a2a3009f31a9}
	condition:
		any of ($a_*)
 
}
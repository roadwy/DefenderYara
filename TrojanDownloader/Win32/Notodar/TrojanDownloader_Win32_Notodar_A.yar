
rule TrojanDownloader_Win32_Notodar_A{
	meta:
		description = "TrojanDownloader:Win32/Notodar.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 72 6c 23 25 64 00 00 64 61 74 61 00 00 00 00 70 6b 00 00 63 66 67 00 77 65 76 74 61 70 69 2e 64 6c 6c } //01 00 
		$a_03_1 = {3b c3 75 16 ff 74 24 18 8b 44 24 28 e8 49 fc ff ff ff 74 24 24 e8 90 01 04 ff 74 24 1c e8 90 00 } //01 00 
		$a_03_2 = {2d f3 f2 2f 2f 50 e8 90 01 04 68 90 01 04 68 90 01 04 ff 75 08 89 44 24 24 ff 15 90 01 04 85 c0 74 15 50 ff 75 08 8d 44 24 1c 50 8d 44 24 34 50 90 00 } //01 00 
		$a_03_3 = {39 5c 24 20 75 07 68 90 01 04 eb 05 68 80 ee 36 00 ff 15 90 00 } //01 00 
		$a_03_4 = {eb 09 8b f3 8b 1b e8 90 01 04 3b df 75 f3 e8 90 00 } //01 00 
		$a_03_5 = {8b f0 85 f6 74 12 56 68 90 01 04 e8 90 01 04 2b f7 59 03 c6 ff d0 5f 33 c0 5e 90 00 } //00 00 
		$a_00_6 = {87 10 00 } //00 17 
	condition:
		any of ($a_*)
 
}
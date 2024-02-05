
rule TrojanDownloader_Win32_Cutwail{
	meta:
		description = "TrojanDownloader:Win32/Cutwail,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 25 73 2f } //01 00 
		$a_00_1 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 } //01 00 
		$a_01_2 = {00 00 00 00 37 37 52 54 } //01 00 
		$a_00_3 = {00 2e 6b 7a 00 } //05 00 
		$a_03_4 = {88 01 0f b6 c3 33 d2 f7 f7 fe c3 8a 90 02 10 88 41 01 80 79 01 65 58 75 17 f6 c3 08 74 12 0f b6 c3 6a 03 33 d2 5f f7 f7 8a 90 00 } //05 00 
		$a_03_5 = {83 c4 04 69 c0 0d 66 19 00 8b 95 90 01 04 8b 8c 95 90 01 04 8d 90 01 02 5f f3 6e 3c 8b 85 90 00 } //05 00 
		$a_00_6 = {71 7a 6c 62 74 67 72 6e 6b 78 73 66 64 63 6d 70 } //00 00 
		$a_00_7 = {7e 15 00 00 bc } //8c b9 
	condition:
		any of ($a_*)
 
}
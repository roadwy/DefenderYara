
rule TrojanDownloader_Win32_Putabmow_A{
	meta:
		description = "TrojanDownloader:Win32/Putabmow.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 5d 14 8a cc f6 d3 f6 d1 22 4d 14 8a c3 22 c4 0a c8 88 0c 17 8b 7e 14 83 ff 10 72 04 8b 06 eb 02 8b c6 8a 0c 10 8a d1 22 d9 f6 d2 22 55 14 0a d3 88 55 14 8b 55 f0 42 89 55 f0 3b 56 10 72 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 57 6f 6d 62 61 74 55 70 64 61 74 65 72 5c 00 } //01 00 
		$a_01_2 = {66 63 00 00 38 61 00 00 } //01 00 
		$a_01_3 = {8a 14 78 8b 45 0c 8a ca 8a d8 f6 d1 22 c8 f6 d3 8a c3 22 c2 0a c8 0f b6 c1 66 89 04 7e } //01 00 
		$a_03_4 = {68 a0 00 00 00 6a 20 68 90 01 04 50 e8 90 01 04 83 c4 10 c6 84 24 90 00 } //00 00 
		$a_00_5 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_Win32_Injranluder_A{
	meta:
		description = "TrojanDownloader:Win32/Injranluder.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 5c 58 66 89 43 10 8d 43 12 6a 08 50 e8 90 01 04 6a 2e 58 6a 65 59 6a 78 90 00 } //01 00 
		$a_01_1 = {6b 4d 08 06 6a 64 66 89 45 f6 58 66 89 45 fa 6a 6c } //01 00 
		$a_03_2 = {74 11 8b 35 90 01 04 53 57 ff d6 8d 45 d8 50 57 ff d6 90 00 } //01 00 
		$a_03_3 = {ff 51 14 85 c0 75 31 ff 75 90 01 01 e8 90 01 02 ff ff 8b f8 85 ff 74 90 00 } //01 00 
		$a_03_4 = {8a 02 42 89 55 90 01 01 3c c3 75 f6 6a 00 6a 5c 8d 45 90 01 01 4a 50 53 ff 75 90 01 01 89 55 90 01 01 ff 15 90 00 } //01 00 
		$a_03_5 = {83 f8 66 7f 1a 74 90 01 01 83 f8 22 74 90 01 01 83 f8 2f 74 90 01 01 83 f8 5c 74 90 01 01 83 f8 62 74 90 01 01 6a fe eb 90 01 01 83 e8 6e 90 00 } //01 00 
		$a_01_6 = {81 f1 c8 47 5d 2e 3b c8 0f 94 c3 83 c7 04 3b c8 75 cc } //01 00 
		$a_03_7 = {74 1f ff 75 10 ff 15 90 01 04 85 c0 74 0b 68 b8 0b 00 00 ff 15 90 01 04 53 57 e8 90 01 02 ff ff 56 e8 90 01 02 ff ff 90 00 } //00 00 
		$a_00_8 = {5d 04 00 } //00 fa 
	condition:
		any of ($a_*)
 
}
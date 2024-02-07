
rule TrojanDownloader_Win32_Upatre_gen_F{
	meta:
		description = "TrojanDownloader:Win32/Upatre.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 ff 55 6c 85 c0 75 0d 6a 01 68 e8 03 00 00 ff 55 50 4e 75 eb } //01 00 
		$a_01_1 = {ff 55 78 33 f6 56 56 56 6a 00 6a 0a b9 06 00 00 00 ff 55 78 50 ff 55 3c 85 c0 74 dd } //01 00 
		$a_01_2 = {ff 55 78 8a cc 51 b9 06 00 00 00 ff 55 78 50 ff 75 10 ff 55 38 59 85 c0 e1 9c } //01 00 
		$a_01_3 = {85 c0 e1 f2 0f 84 46 ff ff ff b8 00 09 3d 00 } //01 00 
		$a_01_4 = {57 56 ad 33 c7 5f ab 8b f7 5f 4f 49 75 f2 } //01 00 
		$a_01_5 = {66 3d 4c 5b 74 38 8b 45 e4 8b c8 8b 55 c4 c1 e0 02 03 d0 8b 02 83 f8 05 0f 87 1b 01 00 00 } //01 00 
		$a_01_6 = {89 02 51 68 04 29 00 00 b9 0a 00 00 00 ff 55 78 6a 01 68 d0 07 00 00 ff 55 50 e9 c3 fc ff ff } //00 00 
		$a_00_7 = {7e 15 } //00 00  ᕾ
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Upatre_gen_F_2{
	meta:
		description = "TrojanDownloader:Win32/Upatre.gen.F!!Upatre.gen!F,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 07 51 8b c8 33 0e 40 40 46 40 40 88 0f 59 47 4b 75 04 5b 2b f3 53 e2 e7 } //01 00 
		$a_01_1 = {67 e3 03 ff 55 e8 8b 55 14 8b 4a 04 ff 55 e8 55 59 ff d0 } //01 00 
		$a_03_2 = {89 68 03 6a 09 59 ff 75 08 58 55 bd 90 01 04 50 8b 45 10 90 00 } //01 00 
		$a_01_3 = {67 e3 03 ff 55 e8 8b 55 14 8b 72 10 8b 7a 14 58 33 c9 ff 32 8b 6a 08 c3 } //01 00 
		$a_01_4 = {6a 2e 8b 75 d4 59 ac 3a c1 72 0a 3c 39 77 06 83 c0 14 aa e2 f1 } //01 00 
		$a_03_5 = {89 29 8b 4d 7c 8b 41 08 8b c8 05 90 01 04 50 81 c1 90 01 04 33 c0 89 29 50 50 ff 55 44 fc 90 00 } //01 00 
		$a_01_6 = {57 ff 55 6c 85 c0 75 0d 6a 01 68 e8 03 00 00 ff 55 50 4e 75 eb } //01 00 
		$a_01_7 = {ff 55 78 33 f6 56 56 56 6a 00 6a 0a b9 06 00 00 00 ff 55 78 50 ff 55 3c 85 c0 74 dd } //01 00 
		$a_01_8 = {ff 55 78 8a cc 51 b9 06 00 00 00 ff 55 78 50 ff 75 10 ff 55 38 59 85 c0 e1 9c } //01 00 
		$a_01_9 = {85 c0 e1 f2 0f 84 46 ff ff ff b8 00 09 3d 00 } //01 00 
		$a_01_10 = {57 56 ad 33 c7 5f ab 8b f7 5f 4f 49 75 f2 } //01 00 
		$a_01_11 = {66 3d 4c 5b 74 38 8b 45 e4 8b c8 8b 55 c4 c1 e0 02 03 d0 8b 02 83 f8 05 0f 87 1b 01 00 00 } //01 00 
		$a_01_12 = {89 02 51 68 04 29 00 00 b9 0a 00 00 00 ff 55 78 6a 01 68 d0 07 00 00 ff 55 50 e9 c3 fc ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
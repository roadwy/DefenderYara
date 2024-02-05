
rule TrojanDownloader_Win32_Upatre_G{
	meta:
		description = "TrojanDownloader:Win32/Upatre.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e } //01 00 
		$a_01_1 = {8b 4e 24 03 c8 03 c8 8b 45 fc 03 c8 0f b7 01 8b 4e 1c 8d 04 81 8b 4d fc 8b 04 01 } //01 00 
		$a_01_2 = {8b 4d d4 8b 7d e4 8b 45 e8 03 f8 8b 75 f4 fc f3 a4 5e 6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 ff 75 f0 ff 55 58 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Upatre_G_2{
	meta:
		description = "TrojanDownloader:Win32/Upatre.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 17 00 00 01 00 "
		
	strings :
		$a_01_0 = {60 8b d8 53 4b ad 51 8b c8 8b 07 33 c8 88 0f 83 c7 01 59 83 ee 03 83 fb 00 } //01 00 
		$a_01_1 = {60 50 8b d8 51 ad 4b 4e 4e 53 8b c8 8b 07 33 c1 4e aa 58 59 } //01 00 
		$a_01_2 = {8b d8 53 51 ac 4b 8b c8 8b 07 33 c1 88 07 47 59 83 fb 00 } //01 00 
		$a_01_3 = {51 53 8b c8 8b 07 33 c8 4e 88 0f 4e 47 58 4e 59 83 f8 00 } //01 00 
		$a_01_4 = {51 53 8b c8 8b 07 33 c8 4e 8b c1 aa 4e 58 4e 59 83 f8 00 } //01 00 
		$a_01_5 = {8b d8 53 8b 07 33 06 46 88 07 47 4b } //01 00 
		$a_03_6 = {50 8b d8 ac 33 07 aa 4b 0f 84 90 01 04 49 75 f2 58 8b c1 90 00 } //01 00 
		$a_03_7 = {50 8b d8 8b 17 8b 06 46 33 c2 aa 4b 0f 84 90 01 02 00 00 49 75 ee 58 8b c1 90 00 } //01 00 
		$a_01_8 = {8b d9 ac 8a 0f 32 c8 4a 75 06 58 2b f0 50 8b d0 8b c1 aa 8b cb e2 e9 } //01 00 
		$a_01_9 = {8b d0 50 51 8b 07 50 ad 59 33 c1 4a 75 06 59 5a 2b f2 52 51 59 4e 4e aa 4e 49 75 e7 } //01 00 
		$a_01_10 = {8b d0 50 51 ad 50 8b 07 59 33 c8 4a 75 06 58 5a 2b f2 52 50 88 0f 59 4e 4e 47 4e 49 } //01 00 
		$a_01_11 = {51 8b 0f ad 4e 4e 4e 33 c1 4a 59 75 04 5a 2b f2 52 aa 49 75 eb } //01 00 
		$a_01_12 = {8b d0 50 ad 51 8b c8 4e 4e 8b 07 4e 33 c8 4a 75 08 8b 44 24 04 2b f0 8b d0 8b c1 59 aa 49 75 e3 } //01 00 
		$a_01_13 = {33 d2 52 50 92 51 ad 4e 91 4e 4e 33 0f 4a 75 08 8b 44 24 04 8b d0 2b f0 8b c1 aa 59 e2 e7 59 } //01 00 
		$a_01_14 = {8b d8 33 c0 50 53 51 33 c9 ac 0b c8 87 f7 ac 4b 33 c1 87 f7 8b cb e3 17 4f aa 59 e2 e9 } //01 00 
		$a_01_15 = {51 33 c9 ac 0b c8 87 f7 ac 4b 33 c1 87 f7 8b cb e3 0b 4f aa 59 e2 e9 59 58 5b c3 } //01 00 
		$a_03_16 = {50 51 33 c9 ac 56 8b f7 0b c8 ac 4b 8b fe 33 c1 8b cb 5e e3 90 01 01 4f aa 59 e2 90 00 } //01 00 
		$a_01_17 = {8b 55 14 8b 4d 0c ac 33 07 aa 4a 75 06 8b 75 10 8b 55 14 e2 f1 } //01 00 
		$a_01_18 = {ac 8b 0f 23 cb 33 c1 88 07 4a 75 06 8b 75 10 8b 55 14 47 59 e2 e4 } //01 00 
		$a_01_19 = {ac 4a 23 cb 33 c1 88 07 85 d2 75 06 8b 55 14 8b 75 10 59 47 e2 e7 } //01 00 
		$a_03_20 = {8b 4d 0c 4a 51 ad 8b 0f 4e 33 c1 4e 88 07 4e 85 90 01 01 75 06 8b 55 14 8b 75 10 59 47 e2 90 00 } //01 00 
		$a_01_21 = {8b 07 8b d0 ad 32 e2 5a c1 e8 08 4e 4e 4a 52 aa 58 85 c0 75 08 8b 45 10 8b 55 14 8b f0 } //01 00 
		$a_00_22 = {8b 75 ce 89 f7 8b 45 e2 bb 04 00 00 00 f6 f3 89 c1 8b 5d f2 ad 31 d8 ab e2 fa ff 65 ce } //00 00 
	condition:
		any of ($a_*)
 
}
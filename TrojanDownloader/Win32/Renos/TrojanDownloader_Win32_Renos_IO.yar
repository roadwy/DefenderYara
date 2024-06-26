
rule TrojanDownloader_Win32_Renos_IO{
	meta:
		description = "TrojanDownloader:Win32/Renos.IO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 13 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 00 00 00 68 74 74 70 3a 2f 2f 00 } //01 00 
		$a_03_1 = {6a 40 59 33 c0 8d bd 90 01 02 ff ff f3 ab 66 ab aa 90 00 } //01 00 
		$a_01_2 = {59 0f b6 c0 83 c0 03 59 24 fc e8 } //01 00 
		$a_01_3 = {64 a1 30 00 00 00 8a 40 02 0f b6 c0 89 85 } //01 00 
		$a_03_4 = {88 04 3e 46 eb 90 09 03 00 83 f0 90 00 } //01 00 
		$a_03_5 = {0f b6 c0 83 c0 03 24 fc e8 90 09 04 00 8a 06 90 03 01 01 04 2c 90 00 } //01 00 
		$a_03_6 = {8a 04 3e 34 90 01 01 88 07 47 4b 75 90 00 } //01 00 
		$a_03_7 = {68 e0 01 00 00 68 58 02 00 00 90 02 10 6a 0a 90 00 } //01 00 
		$a_03_8 = {74 05 83 f8 02 75 90 01 01 6a 0f 68 03 04 00 00 90 00 } //01 00 
		$a_03_9 = {6a 04 50 56 ff 15 90 01 04 85 c0 74 90 01 01 83 7d 90 01 01 04 75 90 00 } //01 00 
		$a_03_10 = {8a 0e 80 f1 90 01 01 88 0c 37 74 06 46 80 3e 00 75 f0 90 00 } //01 00 
		$a_03_11 = {6a 04 50 e8 90 01 04 59 59 8b 7d 90 01 01 83 65 90 01 01 00 83 ff 04 0f 86 90 00 } //01 00 
		$a_01_12 = {3b de 74 12 83 fb 68 74 0d 83 fb 65 74 08 81 fb fc 00 00 00 75 04 } //01 00 
		$a_03_13 = {83 c7 04 83 7d f0 0a 90 02 04 0f 82 90 00 } //01 00 
		$a_03_14 = {81 ff 00 00 00 d0 a2 90 01 04 77 08 81 ff 00 00 00 80 73 90 01 01 ff 15 90 00 } //01 00 
		$a_03_15 = {ff 45 f4 8b 73 04 83 c3 04 89 07 83 c7 04 ff 45 fc 85 f6 75 90 01 01 83 45 f8 04 ff 45 fc 81 7d f8 90 00 } //01 00 
		$a_03_16 = {2b ca 83 f9 33 0f 84 90 01 04 83 f9 42 0f 84 90 01 04 83 f9 4d 0f 85 90 00 } //01 00 
		$a_00_17 = {45 32 34 32 31 31 42 33 2d 41 37 38 41 2d 43 36 41 39 2d 44 33 31 37 2d 37 30 39 37 39 41 43 45 35 30 35 38 } //01 00  E24211B3-A78A-C6A9-D317-70979ACE5058
		$a_03_18 = {83 f1 59 83 f9 62 0f 84 90 01 04 83 f9 75 0f 84 90 01 04 83 f9 78 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
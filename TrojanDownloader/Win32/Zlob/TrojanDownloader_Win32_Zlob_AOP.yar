
rule TrojanDownloader_Win32_Zlob_AOP{
	meta:
		description = "TrojanDownloader:Win32/Zlob.AOP,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 2d 44 33 35 38 2d 34 38 41 33 } //01 00  6-D358-48A3
		$a_01_1 = {41 44 39 43 41 36 38 42 35 32 43 59 } //01 00  AD9CA68B52CY
		$a_01_2 = {31 37 43 36 39 2d 42 46 35 35 2d 36 42 } //01 00  17C69-BF55-6B
		$a_01_3 = {67 65 74 2e 70 68 70 3f 69 64 3d 38 30 33 34 36 36 34 31 37 } //01 00  get.php?id=803466417
		$a_01_4 = {51 75 69 63 6b 54 69 6d 65 20 54 61 73 6b 67 53 4f 46 54 57 } //01 00  QuickTime TaskgSOFTW
		$a_01_5 = {64 20 77 69 74 68 20 61 64 77 61 } //01 00  d with adwa
		$a_00_6 = {47 00 4f 00 4d 00 4f 00 44 00 52 00 49 00 4c 00 } //01 00  GOMODRIL
		$a_00_7 = {5a 00 56 00 45 00 52 00 55 00 53 00 48 00 4b 00 41 00 } //01 00  ZVERUSHKA
		$a_00_8 = {53 00 41 00 41 00 4b 00 41 00 53 00 48 00 56 00 } //0a 00  SAAKASHV
		$a_01_9 = {74 15 8b 77 40 03 f0 eb 09 8b 1e 03 d8 01 03 83 c6 04 83 3e 00 75 f2 8b 74 24 24 8b de 03 f0 b9 01 00 00 00 33 c0 f0 0f b1 4f 30 75 f7 ac } //00 00 
	condition:
		any of ($a_*)
 
}
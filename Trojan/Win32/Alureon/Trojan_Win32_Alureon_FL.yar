
rule Trojan_Win32_Alureon_FL{
	meta:
		description = "Trojan:Win32/Alureon.FL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 25 73 2d 4d 00 } //01 00 
		$a_01_1 = {47 6c 6f 62 61 6c 5c 25 73 2d 45 00 } //01 00 
		$a_01_2 = {62 69 64 00 6d 62 72 } //01 00 
		$a_01_3 = {50 00 41 00 54 00 43 00 48 00 03 00 4d 00 42 00 52 00 } //01 00 
		$a_01_4 = {46 00 49 00 4c 00 45 00 04 00 42 00 4f 00 4f 00 54 00 } //01 00 
		$a_03_5 = {83 f9 2c 76 13 80 7d 90 01 01 00 74 0d 68 67 04 00 00 90 00 } //01 00 
		$a_00_6 = {6a 0c 89 45 f8 89 45 f4 8d 45 f0 50 68 00 14 2d 00 56 c7 45 f0 01 00 00 00 ff d3 83 f8 01 } //01 00 
		$a_03_7 = {53 85 f6 75 90 01 01 b8 90 01 01 00 00 c0 90 09 0f 00 c6 45 90 01 01 42 c6 45 90 01 01 4b c6 45 90 01 01 46 c6 45 90 00 } //01 00 
		$a_01_8 = {8b 70 18 8b 40 14 c1 e0 09 c1 ee 05 c1 e8 05 3b f0 72 0b b8 7f 00 00 c0 } //01 00 
		$a_02_9 = {59 66 83 c9 ff 66 41 66 8b 11 66 81 f2 90 01 02 66 81 fa 90 01 02 74 0e 81 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
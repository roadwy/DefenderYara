
rule Trojan_Win32_Koutodoor_A{
	meta:
		description = "Trojan:Win32/Koutodoor.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 03 00 "
		
	strings :
		$a_03_0 = {8b c1 99 f7 7d 0c 90 02 03 8a 14 90 01 01 90 02 08 32 90 03 01 01 c2 d0 32 90 03 01 01 c3 d3 90 02 03 41 3b cb 90 02 03 7c 90 00 } //01 00 
		$a_01_1 = {53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 e4 } //01 00 
		$a_00_2 = {69 64 3d 25 64 26 6d 61 63 3d 25 73 26 74 79 70 65 3d 25 64 26 73 65 74 75 70 64 61 74 65 3d 25 64 25 30 32 64 25 30 32 64 26 68 6f 6d 65 70 61 67 65 3d 25 73 } //01 00  id=%d&mac=%s&type=%d&setupdate=%d%02d%02d&homepage=%s
		$a_00_3 = {69 64 3d 25 64 26 75 70 64 61 74 65 76 65 72 73 69 6f 6e 3d 25 64 } //01 00  id=%d&updateversion=%d
		$a_00_4 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 72 6b 64 6f 6f 72 } //01 00  \\.\Global\rkdoor
		$a_00_5 = {25 73 5c 25 73 20 25 73 5c 25 73 2e 64 6c 6c 2c 25 73 } //02 00  %s\%s %s\%s.dll,%s
		$a_03_6 = {4d fc 6a 36 68 90 01 04 8d 55 98 51 52 e8 90 00 } //01 00 
		$a_03_7 = {45 fc 6a 17 68 90 01 04 8d 4d 98 50 51 e8 90 00 } //01 00 
		$a_03_8 = {55 fc 6a 0b 68 90 01 04 8d 4d 98 52 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
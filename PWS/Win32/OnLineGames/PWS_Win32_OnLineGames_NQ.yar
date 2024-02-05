
rule PWS_Win32_OnLineGames_NQ{
	meta:
		description = "PWS:Win32/OnLineGames.NQ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 69 6e 6e 74 37 2d 62 43 43 37 36 00 } //01 00 
		$a_01_1 = {64 6f 6d 70 61 67 65 2e 63 6f 2e 6b 72 2f 62 6f 61 72 64 2f 64 61 74 61 2f 6c 6f 67 2f 74 65 73 74 2e 70 68 70 } //01 00 
		$a_01_2 = {63 3a 5c 61 2e 64 61 74 00 } //01 00 
		$a_01_3 = {8a 0e 80 e9 03 80 f1 03 88 0e 46 48 75 f2 8b c6 5e c3 } //01 00 
		$a_01_4 = {6d 69 7e 76 72 6f 74 69 30 69 7e 69 } //01 00 
		$a_03_5 = {36 8b 45 14 a3 90 01 04 36 8b 45 18 a3 90 01 04 58 60 e8 90 01 04 61 61 83 ec 44 56 57 ff 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
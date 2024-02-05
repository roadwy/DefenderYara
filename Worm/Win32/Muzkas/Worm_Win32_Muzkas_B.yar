
rule Worm_Win32_Muzkas_B{
	meta:
		description = "Worm:Win32/Muzkas.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 fa 04 72 12 8b 5c 02 fc 0f cb c1 c3 04 89 5c 02 fc 83 ea 04 eb e9 } //01 00 
		$a_01_1 = {74 b7 46 54 56 f6 27 96 15 36 47 26 46 57 46 17 } //01 00 
		$a_01_2 = {74 c7 46 54 f6 36 96 76 17 24 46 c6 97 36 57 66 } //01 00 
		$a_01_3 = {96 57 46 e4 27 46 56 e7 f6 e6 57 04 54 16 c7 25 } //01 00 
		$a_01_4 = {37 46 66 f5 76 57 26 17 c6 36 94 d5 26 f7 36 f7 64 95 c7 46 e7 26 57 46 e2 07 46 56 56 c7 07 84 f7 26 57 26 00 00 00 00 55 8b ec 6a 00 53 8b d8 } //00 00 
	condition:
		any of ($a_*)
 
}
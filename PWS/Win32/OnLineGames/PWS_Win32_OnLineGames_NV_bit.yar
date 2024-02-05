
rule PWS_Win32_OnLineGames_NV_bit{
	meta:
		description = "PWS:Win32/OnLineGames.NV!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 25 73 2e 65 78 65 } //01 00 
		$a_01_2 = {61 74 74 72 69 62 20 2b 73 20 2b 68 20 22 25 73 22 } //02 00 
		$a_03_3 = {8a 07 b1 1a f6 e9 8a 4f 01 83 c7 02 02 c1 04 90 01 01 88 44 34 90 01 01 46 3b f5 7c 90 00 } //02 00 
		$a_03_4 = {8a 02 33 c9 8a cf 32 c8 66 0f b6 c0 03 c3 88 0c 16 bb 90 01 04 8d 0c 40 c1 e1 04 2b c8 8d 0c 49 8d 0c 89 8d 0c c9 8d 04 48 2b d8 42 4f 75 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule PWS_Win32_OnLineGames_JL{
	meta:
		description = "PWS:Win32/OnLineGames.JL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 27 53 8b 54 24 90 01 01 8a 1c 11 80 c3 90 01 01 88 1c 11 8b 54 24 90 01 01 8a 1c 11 80 f3 90 01 01 88 1c 11 41 3b c8 7c e1 90 00 } //01 00 
		$a_03_1 = {ba 4f 70 65 6e 50 c7 44 24 90 01 01 77 69 6e 69 c7 44 24 90 01 01 6e 65 74 2e c7 44 24 90 01 01 64 6c 6c 00 90 00 } //01 00 
		$a_03_2 = {68 e0 93 04 00 ff 15 90 01 04 6a 00 ff 15 90 01 04 b9 ff 01 00 00 33 c0 8d bd 90 01 04 c6 85 90 01 04 00 f3 ab 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
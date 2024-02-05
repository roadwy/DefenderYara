
rule PWS_Win32_OnLineGames_LM{
	meta:
		description = "PWS:Win32/OnLineGames.LM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 44 24 14 5c c6 44 24 15 6d c6 44 24 16 70 c6 44 24 17 63 c6 44 24 18 6f c6 44 24 19 72 c6 44 24 1a 65 c6 44 24 1b 2e } //01 00 
		$a_01_1 = {4b 69 63 6b 55 73 65 72 4f 75 74 47 61 6d 65 3a 25 75 2c 25 75 } //01 00 
		$a_01_2 = {57 54 46 5c 43 6f 6e 66 69 67 2e 77 74 66 } //01 00 
		$a_01_3 = {72 65 61 6c 6d 4e 61 6d 65 20 22 00 22 } //00 00 
	condition:
		any of ($a_*)
 
}
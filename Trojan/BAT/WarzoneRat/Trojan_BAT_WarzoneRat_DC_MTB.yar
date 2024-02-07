
rule Trojan_BAT_WarzoneRat_DC_MTB{
	meta:
		description = "Trojan:BAT/WarzoneRat.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 33 42 38 45 31 35 44 33 2d 44 34 30 46 2d 34 45 32 31 2d 38 41 30 45 2d 41 42 41 32 36 32 38 33 46 30 32 45 } //01 00  $3B8E15D3-D40F-4E21-8A0E-ABA26283F02E
		$a_81_1 = {57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 42 75 72 79 41 6c 69 76 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  WindowsApplication1.BuryAlive.resources
		$a_81_2 = {55 73 65 20 6c 65 74 74 65 72 73 20 64 75 6d 6d 79 21 } //01 00  Use letters dummy!
		$a_81_3 = {41 6c 69 65 6e 20 47 61 6d 65 } //01 00  Alien Game
		$a_81_4 = {48 61 6e 67 6d 61 6e } //01 00  Hangman
		$a_81_5 = {6c 6f 73 65 2e 70 6e 67 } //01 00  lose.png
		$a_81_6 = {77 69 6e 2e 70 6e 67 } //00 00  win.png
	condition:
		any of ($a_*)
 
}
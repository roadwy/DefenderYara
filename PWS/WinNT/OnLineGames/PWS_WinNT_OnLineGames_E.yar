
rule PWS_WinNT_OnLineGames_E{
	meta:
		description = "PWS:WinNT/OnLineGames.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 00 1f 00 00 00 56 8b 01 03 c2 0f b6 50 03 0f b6 70 02 } //01 00 
		$a_01_1 = {8d 34 70 81 fe 02 00 00 01 0f } //01 00 
		$a_01_2 = {77 73 68 74 63 70 69 70 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_WinNT_OnLineGames_E_2{
	meta:
		description = "PWS:WinNT/OnLineGames.E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 00 4d c6 05 90 01 02 01 00 41 c6 05 90 01 02 01 00 50 c6 05 90 01 02 01 00 44 c6 05 90 01 02 01 00 4e c6 05 90 01 02 01 00 46 c6 05 90 01 02 01 00 77 c6 05 90 01 02 01 00 77 90 00 } //01 00 
		$a_03_1 = {01 00 56 c6 05 90 01 02 01 00 33 c6 05 90 01 02 01 00 41 c6 05 90 01 02 01 00 56 c6 05 90 01 02 01 00 56 c6 05 90 01 02 01 00 33 90 00 } //01 00 
		$a_01_2 = {4d 41 50 6c 65 73 74 6f 72 79 2e 65 78 65 } //01 00 
		$a_01_3 = {56 33 6c 74 72 61 79 2e 65 78 65 } //01 00 
		$a_01_4 = {41 56 70 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}

rule PWS_Win32_OnLineGames_HW{
	meta:
		description = "PWS:Win32/OnLineGames.HW,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 73 74 61 72 74 5c 44 4e 46 63 68 69 6e 61 2e 65 78 65 } //01 00 
		$a_01_1 = {63 6d 64 20 2f 63 20 65 72 61 73 65 20 2f 46 } //01 00 
		$a_01_2 = {5c 73 74 61 72 74 5c 44 4e 46 43 6f 6d 70 6f 6e 65 6e 74 2e 44 4c 4c } //01 00 
		$a_01_3 = {44 4e 46 2e 65 78 65 } //01 00 
		$a_01_4 = {51 51 4c 6f 67 69 6e 2e 65 78 65 } //01 00 
		$a_01_5 = {71 71 2e 75 70 64 61 74 65 2e 73 6f 75 73 75 6f 31 30 30 2e 63 6f 6d 3a } //00 00 
	condition:
		any of ($a_*)
 
}

rule PWS_Win32_OnLineGames_MY{
	meta:
		description = "PWS:Win32/OnLineGames.MY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 00 4d c6 05 90 01 02 01 00 41 c6 05 90 01 02 01 00 50 68 90 01 02 01 00 c6 05 90 01 02 01 00 44 c6 05 90 01 02 01 00 4e c6 05 90 01 02 01 00 46 90 09 04 00 c6 05 90 00 } //01 00 
		$a_00_1 = {41 48 4e 4c 45 53 54 4f 52 59 2e 45 58 45 } //01 00 
		$a_00_2 = {57 4f 57 2e 45 58 45 } //01 00 
		$a_00_3 = {44 49 41 42 4c 4f 20 49 49 49 2e 45 58 45 } //00 00 
	condition:
		any of ($a_*)
 
}
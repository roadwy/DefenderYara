
rule PWS_Win32_OnLineGames_GD{
	meta:
		description = "PWS:Win32/OnLineGames.GD,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 78 65 00 77 2b 62 } //01 00 
		$a_02_1 = {49 44 52 5f 51 51 47 41 4d 45 90 02 04 42 49 4e 00 25 73 90 00 } //01 00 
		$a_02_2 = {64 6f 77 6e 6c 6f 61 64 90 02 04 75 72 6c 25 64 90 02 04 25 73 5c 25 73 2e 65 78 65 90 00 } //0a 00 
		$a_02_3 = {50 56 c7 44 24 18 28 01 90 01 02 e8 90 01 04 85 c0 0f 84 90 01 04 8b 3d 90 01 04 8b 2d 90 01 04 8d 4c 24 34 8d 54 24 0c 51 68 90 01 04 52 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
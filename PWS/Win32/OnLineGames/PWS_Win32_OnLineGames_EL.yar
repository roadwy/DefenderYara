
rule PWS_Win32_OnLineGames_EL{
	meta:
		description = "PWS:Win32/OnLineGames.EL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 20 8d 4c 24 28 89 5c 24 28 51 8b 10 50 ff 52 1c } //01 00 
		$a_00_1 = {25 73 3f 75 73 65 72 3d 25 73 26 70 61 73 73 3d 25 73 26 } //01 00  %s?user=%s&pass=%s&
		$a_00_2 = {77 6f 77 2e 65 78 65 } //00 00  wow.exe
	condition:
		any of ($a_*)
 
}
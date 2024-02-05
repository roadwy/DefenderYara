
rule PWS_Win32_OnLineGames_MX{
	meta:
		description = "PWS:Win32/OnLineGames.MX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 47 39 72 5a 58 49 33 4c 6e 78 6b 64 57 56 73 55 47 39 72 } //01 00 
		$a_01_1 = {59 32 31 6b 4c 69 77 77 4c 44 41 73 4e 44 55 77 4c 44 49 77 } //01 00 
		$a_01_2 = {77 6d 71 74 73 4d 75 74 65 78 00 } //01 00 
		$a_01_3 = {25 39 39 5b 5e 2c 5d 2c 25 64 2c 25 64 2c 25 64 2c 25 64 2c 25 64 2c } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}
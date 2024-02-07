
rule PWS_Win32_OnLineGames_MW{
	meta:
		description = "PWS:Win32/OnLineGames.MW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 68 68 66 64 2a 00 00 55 53 } //01 00 
		$a_03_1 = {77 69 6e 30 90 04 01 02 36 37 25 30 38 78 2e 64 6c 6c 00 90 00 } //01 00 
		$a_03_2 = {ff 2e c6 85 90 01 02 ff ff 65 c6 85 90 01 02 ff ff 78 c6 85 90 01 02 ff ff 65 90 02 06 90 03 04 04 6a 3e f3 ab f3 ab 6a 3e 90 00 } //01 00 
		$a_00_3 = {8a 0e 57 33 ff 88 08 84 c9 74 } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}
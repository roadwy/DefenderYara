
rule PWS_Win32_OnLineGames_CK{
	meta:
		description = "PWS:Win32/OnLineGames.CK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 38 20 75 03 c6 00 5f 40 } //01 00 
		$a_01_1 = {5f 58 5a 5f 00 } //01 00 
		$a_01_2 = {6a 1a 2b c1 59 83 c0 0d 99 f7 f9 } //00 00 
	condition:
		any of ($a_*)
 
}
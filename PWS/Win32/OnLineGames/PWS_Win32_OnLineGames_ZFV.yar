
rule PWS_Win32_OnLineGames_ZFV{
	meta:
		description = "PWS:Win32/OnLineGames.ZFV,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 1c 10 80 c3 90 01 01 88 1c 10 40 3b c1 7c f2 5b c3 90 00 } //01 00 
		$a_01_1 = {65 64 76 6c 66 6c 71 69 72 31 64 76 73 } //00 00 
	condition:
		any of ($a_*)
 
}
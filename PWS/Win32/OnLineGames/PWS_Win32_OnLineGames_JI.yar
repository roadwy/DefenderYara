
rule PWS_Win32_OnLineGames_JI{
	meta:
		description = "PWS:Win32/OnLineGames.JI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 56 c6 45 90 01 01 6d c6 45 90 01 01 69 c6 45 90 01 01 62 c6 45 90 01 01 61 c6 45 90 01 01 6f c6 45 90 01 01 2e c6 45 90 01 01 61 c6 45 90 01 01 73 c6 45 90 01 01 70 90 00 } //01 00 
		$a_03_1 = {3f 50 8d 85 90 01 04 50 c6 90 02 05 61 c6 90 02 05 63 c6 90 02 05 74 c6 90 02 05 69 c6 90 02 05 6f c6 90 02 05 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
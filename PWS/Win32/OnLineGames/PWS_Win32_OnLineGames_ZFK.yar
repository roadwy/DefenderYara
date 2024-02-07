
rule PWS_Win32_OnLineGames_ZFK{
	meta:
		description = "PWS:Win32/OnLineGames.ZFK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 f0 57 50 53 c6 45 f1 6f c6 45 f2 72 c6 45 f3 6c c6 45 f4 64 } //01 00 
		$a_00_1 = {25 73 3f 61 63 74 69 6f 6e 3d 70 6f 73 74 6d 62 26 75 3d 25 73 26 6d 62 3d 25 73 } //00 00  %s?action=postmb&u=%s&mb=%s
	condition:
		any of ($a_*)
 
}
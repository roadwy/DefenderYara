
rule PWS_Win32_OnLineGames_DD{
	meta:
		description = "PWS:Win32/OnLineGames.DD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c2 81 64 cc 0f c1 6a 80 30 56 eb 0f 89 ef 4d } //01 00 
		$a_03_1 = {3b c3 0f 85 a3 00 00 00 c7 05 90 01 02 00 10 79 3a 40 00 eb 21 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule PWS_Win32_OnLineGames_ZDQ{
	meta:
		description = "PWS:Win32/OnLineGames.ZDQ,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 03 00 "
		
	strings :
		$a_02_0 = {b9 66 06 00 00 8d bc 24 90 01 02 00 00 f3 ab 66 ab aa 90 00 } //03 00 
		$a_00_1 = {f3 ab 66 ab b9 66 06 00 00 33 c0 8d } //02 00 
		$a_02_2 = {53 65 72 76 65 72 49 50 2d 2d 3e 90 02 10 53 65 72 76 65 72 4e 61 6d 65 2d 2d 3e 90 00 } //02 00 
		$a_01_3 = {d1 d5 c9 ab 2e 74 78 74 } //02 00 
		$a_02_4 = {72 65 63 76 3a 3e 20 25 73 90 02 07 73 65 6e 64 3a 3e 20 25 73 90 02 07 51 55 49 54 90 00 } //02 00 
		$a_02_5 = {46 72 6f 6d 3a 20 22 3d 3f 67 62 32 33 31 32 3f 42 3f 25 73 3d 3f 3d 22 20 3c 25 73 3e 90 02 10 44 41 54 41 90 02 07 52 43 50 54 20 54 4f 3a 20 3c 25 73 3e 90 02 07 4d 41 49 4c 20 46 52 4f 4d 3a 20 3c 25 73 3e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
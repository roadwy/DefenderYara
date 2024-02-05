
rule PWS_Win32_OnLineGames_MR{
	meta:
		description = "PWS:Win32/OnLineGames.MR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b c6 74 2c 83 e8 65 74 07 2d c7 00 00 00 eb 1b ff 74 24 10 8b cf 68 } //01 00 
		$a_01_1 = {3d 96 00 00 00 74 05 83 c8 ff eb 5a 6a 00 8d 85 00 f0 ff ff 68 00 10 00 00 50 a1 } //01 00 
		$a_01_2 = {3d e3 00 00 00 5e 0f 85 c3 00 00 00 6a 28 ff 35 cc 6e 00 10 ff 15 } //01 00 
		$a_01_3 = {83 7d 08 78 59 59 75 0f 8d 45 e8 50 8d 45 a8 50 e8 } //01 00 
		$a_01_4 = {8b d8 c1 e2 10 23 de 89 45 0c 03 d3 33 db 8a 7d 0e c1 e2 08 03 d3 c1 e8 18 03 d0 89 11 83 c1 04 ff 4d 08 75 d6 } //01 00 
		$a_01_5 = {65 73 63 6b 40 74 65 61 6d } //01 00 
		$a_03_6 = {25 64 2c 25 64 2c 25 64 2c 25 64 2c 25 64 2c 25 64 00 00 00 50 41 53 56 90 02 04 52 45 54 52 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule PWS_Win32_OnLineGames_BD{
	meta:
		description = "PWS:Win32/OnLineGames.BD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 45 ec c7 45 ec 47 61 6d 65 c7 45 f0 2e 65 78 65 89 45 f8 } //01 00 
		$a_01_1 = {c7 45 d4 7b 32 43 42 c7 45 d8 37 37 37 34 c7 45 dc 36 2d 38 45 c7 45 e0 43 43 2d 34 c7 45 e4 30 63 61 2d c7 45 e8 38 32 31 37 c7 45 ec 2d 31 30 43 c7 45 f0 41 38 42 45 c7 45 f4 35 45 46 43 c7 45 f8 38 7d 00 00 } //01 00 
		$a_01_2 = {c7 45 88 6e 5c 45 78 c7 45 8c 70 6c 6f 72 c7 45 90 65 72 5c 53 c7 45 94 68 65 6c 6c c7 45 98 45 78 65 63 c7 45 9c 75 74 65 48 c7 45 a0 6f 6f 6b 73 } //00 00 
	condition:
		any of ($a_*)
 
}
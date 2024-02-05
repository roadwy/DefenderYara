
rule PWS_Win32_OnLineGames_BG{
	meta:
		description = "PWS:Win32/OnLineGames.BG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 18 56 6a 32 6a 01 ff 90 01 02 ff 15 90 00 } //01 00 
		$a_03_1 = {6a 2f 57 ff 15 90 01 04 40 68 90 01 04 50 e8 90 01 04 6a 32 90 00 } //01 00 
		$a_01_2 = {25 73 25 73 25 73 } //01 00 
		$a_00_3 = {6d 69 62 61 6f 2e 61 73 70 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_OnLineGames_BG_2{
	meta:
		description = "PWS:Win32/OnLineGames.BG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 fc e8 90 01 02 ff ff 8b 55 fc 8a 54 1a ff 80 ea 90 01 01 88 54 18 ff 43 4e 75 e6 90 00 } //01 00 
		$a_03_1 = {be 65 00 00 00 6a 0a e8 90 01 02 ff ff 6a 00 6a 00 6a 00 6a 08 e8 90 01 02 ff ff 6a 00 6a 02 6a 00 6a 08 e8 90 01 02 ff ff 4e 75 dc 90 00 } //01 00 
		$a_03_2 = {81 fb c8 00 00 00 7e 07 6a 00 e8 90 01 04 6a 64 e8 90 01 15 74 0a 90 01 08 75 03 43 eb ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule PWS_Win32_OnLineGames_ZFL{
	meta:
		description = "PWS:Win32/OnLineGames.ZFL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 53 6a 10 57 ff d6 53 53 6a 12 57 ff d6 53 53 } //01 00 
		$a_02_1 = {64 62 72 25 30 32 78 2a 2e 90 01 03 00 90 00 } //01 00 
		$a_00_2 = {00 5f 5f 25 73 5f 25 73 5f 25 64 5f 00 } //01 00 
		$a_00_3 = {00 5f 5f 25 73 5f 25 64 5f 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_OnLineGames_ZFL_2{
	meta:
		description = "PWS:Win32/OnLineGames.ZFL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 6e 66 2e 65 78 65 } //01 00 
		$a_00_1 = {64 73 6f 75 6e 64 30 31 30 2e 44 69 72 65 63 74 53 6f 75 6e 64 43 61 70 74 75 72 65 43 72 65 61 74 65 } //01 00 
		$a_03_2 = {f2 ae f7 d1 49 51 8d 8c 24 90 01 04 68 90 01 02 00 10 51 ff 15 90 01 02 00 10 5f 5e 85 c0 75 0b 68 90 01 02 00 10 ff 15 90 01 02 00 10 33 c0 81 c4 08 02 00 00 c2 04 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
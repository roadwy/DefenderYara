
rule PWS_Win32_OnLineGames_ID_dll{
	meta:
		description = "PWS:Win32/OnLineGames.ID!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 63 74 3d 6f 6e 6c 69 6e 65 26 4e 61 6d 65 3d 25 73 } //01 00  act=online&Name=%s
		$a_01_1 = {25 73 4a 61 63 6b 73 6f 6e 2e 62 61 74 } //01 00  %sJackson.bat
		$a_01_2 = {64 6e 66 2e 65 78 65 00 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 5c 50 72 65 6c 6f 61 64 } //01 00 
		$a_01_3 = {71 71 6c 6f 67 69 6e 2e 65 78 65 00 25 73 5c 73 6f 73 6f 2e 62 6d 70 00 25 73 5c 73 6f 73 6f 2e 64 61 74 00 73 35 61 6d } //00 00 
	condition:
		any of ($a_*)
 
}
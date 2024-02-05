
rule PWS_Win32_OnLineGames_JK{
	meta:
		description = "PWS:Win32/OnLineGames.JK,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 3f 61 63 74 69 6f 6e 3d 70 6f 73 74 6d 62 26 75 3d 25 73 26 6d 62 3d 25 73 } //01 00 
		$a_01_1 = {25 73 3f 61 63 74 69 6f 6e 3d 74 65 73 74 6c 6f 63 6b 32 26 75 3d 25 73 } //01 00 
		$a_01_2 = {51 51 4c 6f 67 69 6e 2e 65 78 65 } //01 00 
		$a_01_3 = {4c 6f 61 64 44 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}
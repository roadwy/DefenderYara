
rule PWS_Win32_OnLineGames_CQ{
	meta:
		description = "PWS:Win32/OnLineGames.CQ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {26 5a 6f 6e 65 3d 25 73 26 73 65 72 76 65 72 3d 25 73 26 4e 61 6d 65 3d 25 73 26 50 61 73 73 3d 25 73 26 } //01 00 
		$a_01_1 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00 
		$a_00_2 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 20 } //01 00 
		$a_00_3 = {33 36 30 74 72 61 79 2e 65 78 65 } //01 00 
		$a_00_4 = {33 36 30 53 61 66 65 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}
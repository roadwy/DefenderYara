
rule PWS_Win32_OnLineGames_FB{
	meta:
		description = "PWS:Win32/OnLineGames.FB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {26 7a 74 3d 77 61 69 90 02 04 61 63 74 69 6f 6e 3d 75 70 26 75 3d 90 02 08 26 7a 74 3d 73 75 63 63 6d 62 68 90 00 } //0a 00 
		$a_01_1 = {53 47 43 51 } //01 00 
		$a_00_2 = {77 6d 67 6d 62 2e 61 73 70 } //01 00 
		$a_00_3 = {63 67 61 6d 65 61 73 64 66 67 68 } //01 00 
		$a_00_4 = {67 61 6d 65 71 77 65 72 74 79 } //00 00 
	condition:
		any of ($a_*)
 
}
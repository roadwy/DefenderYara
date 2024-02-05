
rule PWS_Win32_OnLineGames_ABE{
	meta:
		description = "PWS:Win32/OnLineGames.ABE,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 72 78 6a 68 2e 63 6f 6d 2e 63 6e } //01 00 
		$a_01_1 = {55 73 65 72 3d 25 73 26 50 61 73 73 3d 25 73 26 53 65 72 76 65 72 3d 25 73 2d 25 73 2d 25 64 26 52 6f 6c 65 3d 25 73 } //01 00 
		$a_01_2 = {79 62 5f 6d 65 6d 2e 64 6c 6c } //01 00 
		$a_01_3 = {25 73 28 25 73 2d 25 64 29 } //00 00 
	condition:
		any of ($a_*)
 
}
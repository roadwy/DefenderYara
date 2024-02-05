
rule PWS_Win32_OnLineGames_GU_dll{
	meta:
		description = "PWS:Win32/OnLineGames.GU!dll,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 2f 63 2e 61 73 70 3f 64 6f 3d 74 72 26 63 3d 71 26 69 3d 25 73 26 61 3d 25 73 26 73 3d 25 73 26 6d 3d 25 73 } //01 00 
		$a_01_1 = {2f 75 70 6c 6f 61 64 69 6d 67 2e 61 73 70 3f 46 69 6c 65 4e 61 6d 65 3d } //01 00 
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 20 73 68 65 6c 6c 33 32 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 22 25 73 22 } //01 00 
		$a_01_3 = {69 64 6c 65 70 72 6f 63 6d 75 74 65 78 } //00 00 
	condition:
		any of ($a_*)
 
}
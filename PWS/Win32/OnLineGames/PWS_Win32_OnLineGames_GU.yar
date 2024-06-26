
rule PWS_Win32_OnLineGames_GU{
	meta:
		description = "PWS:Win32/OnLineGames.GU,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7b 25 73 7d 00 00 00 00 50 41 53 53 5f 4e 4f 44 33 32 5f 4f 4b 00 00 00 5f 4c 4f 41 44 4c 49 42 52 41 52 59 5f 44 55 4d 4d 59 00 00 25 73 2e 66 6f 6e 00 00 25 73 5c 66 6f 6e 74 73 5c 25 73 2e 66 6f 6e 00 25 73 5c 73 79 73 74 65 6d 00 00 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //00 00  CreateMutexA
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_OnLineGames_GU_2{
	meta:
		description = "PWS:Win32/OnLineGames.GU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {26 62 61 6e 6b 70 61 73 73 77 6f 72 64 3d 90 02 05 62 61 6e 6b 70 61 73 73 77 6f 72 64 2e 61 73 70 78 3f 75 73 65 72 6e 61 6d 65 3d 90 00 } //01 00 
		$a_01_1 = {26 66 69 72 73 74 3d 00 6d 69 62 61 6f 2e 61 73 70 78 3f 75 73 65 72 6e 61 6d 65 3d } //01 00 
		$a_03_2 = {26 72 61 6e 6b 3d 90 02 05 26 70 77 64 3d 90 02 05 26 75 73 65 72 6e 61 6d 65 3d 90 02 05 26 73 65 72 76 65 72 3d 90 00 } //01 00 
		$a_01_3 = {6b 69 63 6b 2e 61 73 68 78 3f 75 73 65 72 6e 61 6d 65 3d } //01 00  kick.ashx?username=
		$a_03_4 = {79 6f 75 20 61 72 65 20 6b 69 63 6b 65 64 90 02 05 79 6f 75 20 61 72 65 20 70 72 65 70 6f 62 61 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
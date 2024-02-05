
rule PWS_Win32_OnLineGames_CP{
	meta:
		description = "PWS:Win32/OnLineGames.CP,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 73 68 65 6c 6c 65 78 65 63 75 74 65 68 6f 6f 6b 73 } //01 00 
		$a_01_1 = {3d 25 73 26 50 49 4e 3d 25 73 26 } //01 00 
		$a_01_2 = {3d 25 73 26 52 3d 25 73 26 52 47 3d 25 64 26 4d 3d 25 64 26 } //01 00 
		$a_01_3 = {2f 6d 69 62 61 6f 2e 61 73 70 } //01 00 
		$a_01_4 = {2f 6d 62 2e 61 73 70 } //00 00 
	condition:
		any of ($a_*)
 
}
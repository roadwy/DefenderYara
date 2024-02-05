
rule PWS_Win32_OnLineGames_gen_G{
	meta:
		description = "PWS:Win32/OnLineGames.gen!G,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {65 6c 65 6d 65 6e 74 77 64 61 6f 2e 64 6c 6c 00 } //01 00 
		$a_01_1 = {6f 6e 6c 69 6e 65 00 00 69 73 6f 6e 6c 69 6e 65 } //01 00 
		$a_01_2 = {61 63 74 69 6f 6e 3d 75 70 26 75 3d } //01 00 
		$a_01_3 = {63 6f 6e 74 72 6f 6c 00 73 65 72 76 65 72 3d 00 43 6f 6e 66 69 67 5c 63 6f 6e 66 69 67 2e 78 6d 6c } //01 00 
		$a_01_4 = {63 67 61 6d 65 61 73 64 66 67 68 } //00 00 
	condition:
		any of ($a_*)
 
}

rule PWS_Win32_OnLineGames_LB{
	meta:
		description = "PWS:Win32/OnLineGames.LB,SIGNATURE_TYPE_PEHSTR,ffffffd2 00 ffffffd2 00 07 00 00 64 00 "
		
	strings :
		$a_01_0 = {44 4e 46 63 68 69 6e 61 2e 65 78 65 } //64 00 
		$a_01_1 = {2e 64 61 74 61 32 31 } //0a 00 
		$a_01_2 = {71 71 6c 6f 67 69 6e 2e 65 78 65 } //0a 00 
		$a_01_3 = {5c 73 74 61 72 74 5c 75 73 65 72 73 65 74 74 69 6e 67 2e 69 6e 69 } //0a 00 
		$a_01_4 = {44 4e 46 54 68 72 65 61 64 53 65 6e 64 50 61 72 61 6d } //01 00 
		$a_01_5 = {c6 45 cc 6f c6 45 cd 6c c6 45 ce 68 c6 45 cf 65 } //01 00 
		$a_01_6 = {c6 45 a9 72 c6 45 aa 65 c6 45 ab 72 c6 45 ac 2e c6 45 ad 65 c6 45 ae 78 } //00 00 
	condition:
		any of ($a_*)
 
}
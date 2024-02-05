
rule Backdoor_MacOS_GetShell_A{
	meta:
		description = "Backdoor:MacOS/GetShell.A,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {b8 61 00 00 02 6a 02 5f 6a 01 5e 48 31 d2 0f 05 49 89 c4 48 89 c7 b8 62 00 00 02 48 31 f6 56 48 be 90 01 08 56 48 89 e6 6a 10 5a 0f 05 4c 89 e7 b8 5a 00 00 02 48 31 f6 0f 05 b8 5a 00 00 02 48 ff c6 0f 05 48 31 c0 b8 3b 00 00 02 e8 08 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_MacOS_GetShell_A_2{
	meta:
		description = "Backdoor:MacOS/GetShell.A,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 00 00 61 44 00 00 02 7c 00 02 78 7c 7e 1b 78 48 00 00 0d 00 02 1f 90 ba 57 45 f9 } //01 00 
		$a_01_1 = {7c 00 02 78 38 00 00 03 7f c3 f3 78 38 81 e0 00 38 a0 20 00 } //01 00 
		$a_01_2 = {38 00 00 61 44 00 00 02 7c 00 02 78 7c 7e 1b 78 48 00 00 0d 00 02 } //01 00 
		$a_01_3 = {2f 62 69 6e 2f 63 73 68 00 41 41 41 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 } //01 00 
		$a_01_4 = {50 6a 01 6a 02 6a 10 b0 61 cd 80 57 50 50 6a } //01 00 
		$a_03_5 = {6a 5a 58 cd 80 ff 90 01 02 79 90 02 02 68 2f 2f 73 68 68 2f 62 69 6e 90 00 } //01 00 
		$a_03_6 = {50 40 50 40 50 52 b0 61 cd 80 0f 90 02 05 89 c6 52 52 52 68 00 02 11 5c 90 00 } //01 00 
		$a_01_7 = {66 b8 02 10 50 31 c0 b0 07 50 56 52 52 b0 c5 cd 80 72 1c } //00 00 
		$a_00_8 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}

rule Backdoor_Win32_Reyds_A{
	meta:
		description = "Backdoor:Win32/Reyds.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6c 6a 07 59 33 c0 8d 7d ac f3 ab 6a 0a 66 ab 59 33 c0 68 a0 00 00 00 8d 7d cc 50 f3 ab } //01 00 
		$a_01_1 = {80 3e 00 75 1a 69 d2 04 01 00 00 81 c2 } //01 00 
		$a_01_2 = {3c e8 74 04 3c e9 75 08 8b cb } //01 00 
		$a_01_3 = {33 db f3 a6 74 15 83 c2 28 ff 45 fc 66 39 45 fc 72 e4 33 c0 } //02 00 
		$a_01_4 = {25 73 3f 69 64 3d 25 73 26 75 69 64 3d 25 73 26 6f 73 3d 25 73 00 } //01 00 
		$a_00_5 = {58 48 46 48 47 45 42 44 } //00 00 
	condition:
		any of ($a_*)
 
}
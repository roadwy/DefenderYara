
rule Backdoor_Win32_Boomie_A{
	meta:
		description = "Backdoor:Win32/Boomie.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {e9 70 02 00 00 c6 45 d0 01 89 75 dc c7 45 e0 f8 24 01 00 c7 45 e4 e8 03 00 00 } //01 00 
		$a_01_1 = {88 4c 24 27 88 4c 24 37 b3 5c b2 72 b0 6e 8d 4c 24 54 c6 44 24 10 53 } //01 00 
		$a_01_2 = {2f 73 68 6f 77 61 72 74 69 63 6c 65 2e 61 73 70 3f 69 64 3d 25 64 00 } //01 00 
		$a_01_3 = {43 3a 5c 58 2e 65 78 65 00 } //01 00 
		$a_01_4 = {5a 7a 68 00 25 75 4d 42 00 } //01 00 
		$a_01_5 = {25 73 25 58 25 69 25 58 25 69 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Backdoor_Win32_Zegost_R{
	meta:
		description = "Backdoor:Win32/Zegost.R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 44 24 14 66 8b 07 8b d0 81 e2 00 f0 00 00 66 81 fa 00 a0 74 90 01 01 66 81 fa 00 30 75 90 01 01 8b 16 25 ff 0f 00 00 03 c2 90 00 } //01 00 
		$a_03_1 = {83 c4 08 8d 45 d0 6a 00 50 6a 08 68 90 01 04 56 ff 15 90 01 04 81 3d 90 01 04 52 41 52 21 74 11 90 00 } //01 00 
		$a_01_2 = {00 25 73 4b 42 25 64 5c 00 } //01 00 
		$a_03_3 = {8b 4c 24 14 6a 00 68 00 00 00 02 6a 00 6a 00 6a 00 51 ff d0 8b f0 85 f6 0f 84 80 00 00 00 56 ff 15 90 01 04 b9 11 00 00 00 33 c0 8d 7c 24 64 50 f3 ab 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
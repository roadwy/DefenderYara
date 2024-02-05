
rule Backdoor_Win32_Zegost_CI_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CI!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10 } //02 00 
		$a_03_1 = {4b c6 44 24 90 01 01 52 c6 44 24 90 01 01 4e c6 44 24 90 01 01 4c c6 44 24 90 01 01 33 c6 44 24 90 01 01 32 c6 44 24 90 01 01 2e 90 00 } //01 00 
		$a_03_2 = {8b 03 8b c8 8b d0 c1 e9 90 01 01 c1 ea 90 01 01 8b f0 83 e1 01 83 e2 01 c1 ee 90 01 01 a9 90 01 04 74 15 90 00 } //01 00 
		$a_01_3 = {56 57 8b 78 3c 89 65 f0 03 f8 89 7d e4 81 3f 50 45 00 00 74 } //00 00 
		$a_00_4 = {78 98 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Zegost_CI_bit_2{
	meta:
		description = "Backdoor:Win32/Zegost.CI!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 11 80 ea 90 01 01 8b 45 fc 03 45 f8 88 10 8b 4d fc 03 4d f8 8a 11 80 f2 90 01 01 8b 45 fc 03 45 f8 88 10 eb 90 00 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 65 78 00 } //01 00 
		$a_01_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //01 00 
		$a_01_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}
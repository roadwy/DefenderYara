
rule Trojan_Win32_Waski_A_MTB{
	meta:
		description = "Trojan:Win32/Waski.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {b8 77 07 00 00 57 50 ba 24 24 40 00 52 ff 15 } //01 00 
		$a_00_1 = {4f 66 8b 07 8a cc 47 33 c0 e8 de 01 00 00 } //01 00 
		$a_02_2 = {8b 06 33 c1 e8 0b 00 00 00 c3 90 02 15 8b c8 88 07 83 c6 01 c3 90 00 } //01 00 
		$a_00_3 = {6a 00 68 ff 00 00 00 68 00 da 55 00 68 18 21 55 00 68 18 21 55 00 6a 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Waski_A_MTB_2{
	meta:
		description = "Trojan:Win32/Waski.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 4c 24 08 8a 0c 08 8b 54 24 04 88 0c 10 40 3b 44 24 0c } //01 00 
		$a_00_1 = {8b 4d e8 8b 41 3c ff 75 f0 03 c1 0f b7 50 06 6b d2 28 8d 84 02 d0 00 00 00 8b 70 14 03 70 10 03 f1 } //01 00 
		$a_00_2 = {31 0c 96 8b 45 f8 42 c1 e8 02 } //01 00 
		$a_01_3 = {62 00 75 00 64 00 68 00 61 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_4 = {6b 00 69 00 6c 00 66 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
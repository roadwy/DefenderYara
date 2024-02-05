
rule Trojan_Win32_Dimnie_B{
	meta:
		description = "Trojan:Win32/Dimnie.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {c7 45 f0 49 6b 7a 5e c7 45 f4 7c 61 6d 6b c7 45 f8 7d 7d 46 6b 66 c7 45 fc 6f 7e } //01 00 
		$a_01_1 = {80 74 05 f0 0e 40 83 f8 0e 7c f5 e8 } //02 00 
		$a_01_2 = {c7 45 f4 64 7b 7c 7a c7 45 f8 6b 69 7c 5f } //01 00 
		$a_01_3 = {88 45 fc 80 74 05 f4 08 40 83 f8 08 7c f5 e8 } //02 00 
		$a_01_4 = {c7 45 ec 44 72 7a 67 c7 45 f0 55 7c 61 40 c7 45 f4 7a 7d 74 7f } //01 00 
		$a_01_5 = {80 74 05 ec 13 40 83 f8 13 7c f5 e8 } //01 00 
		$a_01_6 = {5f 44 4d 4e 42 45 47 5f 31 32 33 34 } //01 00 
		$a_01_7 = {6e 76 70 6e 2e 70 77 58 58 58 } //01 00 
		$a_01_8 = {0f b6 d1 c1 e2 18 89 10 8a d1 80 e2 80 83 c0 04 f6 da 1a d2 80 e2 1b } //00 00 
		$a_00_9 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}
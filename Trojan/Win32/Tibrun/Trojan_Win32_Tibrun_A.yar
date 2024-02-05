
rule Trojan_Win32_Tibrun_A{
	meta:
		description = "Trojan:Win32/Tibrun.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 77 77 77 2f 63 6d 64 2e 70 68 70 20 48 54 54 } //01 00 
		$a_00_1 = {22 67 6f 6f 64 73 6c 69 73 74 22 20 3a 20 22 00 2c 20 22 70 70 73 22 20 3a } //01 00 
		$a_00_2 = {22 62 72 75 74 69 6e 67 22 20 3a 20 } //01 00 
		$a_02_3 = {00 31 2e 62 61 74 90 02 04 00 69 70 2e 73 79 73 90 02 04 00 31 2e 65 78 65 90 00 } //00 00 
		$a_00_4 = {78 } //7a 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Tibrun_A_2{
	meta:
		description = "Trojan:Win32/Tibrun.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {22 62 61 64 22 20 3a 20 00 2c 20 22 62 72 75 74 69 6e 67 22 20 3a } //0a 00 
		$a_01_1 = {62 72 75 74 2e 6c 6f 63 2f 77 77 77 } //0a 00 
		$a_01_2 = {b9 19 00 00 00 f3 a4 b8 64 65 6c 20 ab b8 2f 41 3a 53 ab 66 b8 2f 41 66 ab 66 b8 20 22 } //01 00 
		$a_01_3 = {b8 41 63 63 65 } //01 00 
		$a_01_4 = {b8 70 74 2d 45 } //01 00 
		$a_01_5 = {b8 20 67 7a 69 } //01 00 
		$a_01_6 = {b8 69 6e 67 3a } //00 00 
		$a_00_7 = {5d 04 00 00 c9 15 03 80 5c 25 } //00 00 
	condition:
		any of ($a_*)
 
}
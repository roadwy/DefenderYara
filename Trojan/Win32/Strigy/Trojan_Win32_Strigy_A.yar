
rule Trojan_Win32_Strigy_A{
	meta:
		description = "Trojan:Win32/Strigy.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {6f 64 62 63 5f 79 65 6b 2e 6e 6c 73 } //02 00 
		$a_01_1 = {45 6e 74 65 72 20 4d 79 57 6f 72 6b 2e 2e 2e } //01 00 
		$a_01_2 = {20 73 74 6f 70 20 77 75 61 75 73 65 72 76 } //02 00 
		$a_01_3 = {3a 20 4d 79 41 70 70 2f 30 2e 31 0d 0a 0d 0a } //02 00 
		$a_01_4 = {4c 6f 6f 6b 4e 6f 64 5e 5f 5e } //01 00 
		$a_01_5 = {57 61 72 6e 69 6e 67 3a 20 44 61 74 65 20 45 72 72 6f 72 21 } //02 00 
		$a_01_6 = {45 6e 74 65 72 20 53 74 61 72 74 57 6f 72 6b 2e 2e 2e } //00 00 
	condition:
		any of ($a_*)
 
}
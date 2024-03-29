
rule Trojan_Win32_Mustrat_A{
	meta:
		description = "Trojan:Win32/Mustrat.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 6d 69 6e 65 72 64 2e 65 78 65 00 6c 69 62 63 75 72 6c 2d 34 2e 64 6c 6c 00 } //01 00 
		$a_01_1 = {73 74 72 61 74 75 6d 2b 74 63 70 3a } //01 00  stratum+tcp:
		$a_01_2 = {25 54 45 4d 50 25 5c 77 69 6e 64 6f 77 73 00 5c 77 69 6e 73 79 73 2e 65 78 65 00 } //03 00 
		$a_03_3 = {c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 8b 95 90 01 04 8b 42 50 89 44 24 08 8b 42 34 89 44 24 04 8b 85 90 01 04 89 04 24 e8 90 00 } //00 00 
		$a_00_4 = {87 10 00 } //00 c3 
	condition:
		any of ($a_*)
 
}
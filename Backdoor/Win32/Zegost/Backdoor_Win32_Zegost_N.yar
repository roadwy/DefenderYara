
rule Backdoor_Win32_Zegost_N{
	meta:
		description = "Backdoor:Win32/Zegost.N,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {53 c6 44 24 90 01 01 70 c6 44 24 90 01 01 69 c6 44 24 90 01 01 64 8b 54 24 90 01 01 8d 8e 90 01 04 c6 44 24 90 01 01 65 c6 44 24 90 01 01 72 90 00 } //02 00 
		$a_03_1 = {7e 1a 53 8b 54 24 90 01 01 8a 1c 11 80 f3 90 01 01 88 1c 11 41 3b c8 7c ee 90 00 } //01 00 
		$a_00_2 = {53 70 69 64 65 72 20 25 64 } //01 00 
		$a_00_3 = {5c 63 6f 6d 5c 73 79 73 6c 6f 67 2e 64 61 74 00 25 73 5c 25 64 2e 62 61 6b } //00 00 
	condition:
		any of ($a_*)
 
}
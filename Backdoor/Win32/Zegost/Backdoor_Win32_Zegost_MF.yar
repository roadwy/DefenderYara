
rule Backdoor_Win32_Zegost_MF{
	meta:
		description = "Backdoor:Win32/Zegost.MF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {57 c6 45 ed 69 c6 45 ee 6e c6 45 ef 64 8b 55 90 01 01 8d 8e 90 01 04 89 86 90 01 04 b0 73 90 00 } //01 00 
		$a_00_1 = {5c 6b 65 79 6c 6f 67 2e 64 61 74 00 25 64 2e 62 61 6b } //01 00 
		$a_00_2 = {6c 6f 67 69 6e 78 78 00 47 6c 6f 62 61 6c 5c 67 75 69 67 65 20 25 64 } //01 00 
		$a_00_3 = {72 6f 73 73 65 63 6f 72 50 6c 61 72 74 6e 65 43 5c 6d 65 74 73 79 53 5c } //00 00 
	condition:
		any of ($a_*)
 
}
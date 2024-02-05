
rule Backdoor_Win32_Zegost_AM{
	meta:
		description = "Backdoor:Win32/Zegost.AM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {bb 4e 61 bc 00 c7 44 24 10 00 00 00 00 b9 3f 00 00 00 33 c0 8d bc 24 25 02 00 00 c6 84 24 24 02 00 00 00 f3 ab 66 ab 8d 8c 24 24 02 00 00 68 00 01 00 00 51 aa ff d6 8d 94 24 24 02 00 00 68 } //02 00 
		$a_01_1 = {f3 ab 66 ab aa b9 3f 00 00 00 33 c0 8d bc 24 25 01 00 00 c6 84 24 24 01 00 00 00 f3 ab 66 ab bb 01 00 00 00 c7 44 24 10 00 00 00 00 aa e8 } //01 00 
		$a_01_2 = {25 73 5c 25 64 5f 74 65 70 2e 64 6c 6c 00 } //01 00 
		$a_01_3 = {5c 75 6e 69 6e 73 74 61 6c 6c 2e 6c 6f 67 00 } //01 00 
		$a_01_4 = {53 76 63 48 6f 73 74 2e 44 4c 4c 2e 6c 6f 67 00 } //01 00 
		$a_03_5 = {48 54 54 50 45 58 45 00 5c 75 70 64 61 74 65 2e 74 65 6d 70 90 02 04 5c 63 6f 6d 6d 61 6e 64 2e 70 61 6b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
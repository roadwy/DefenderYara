
rule Backdoor_Win32_Zegost_N{
	meta:
		description = "Backdoor:Win32/Zegost.N,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 c6 44 24 ?? 70 c6 44 24 ?? 69 c6 44 24 ?? 64 8b 54 24 ?? 8d 8e ?? ?? ?? ?? c6 44 24 ?? 65 c6 44 24 ?? 72 } //2
		$a_03_1 = {7e 1a 53 8b 54 24 ?? 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c ee } //2
		$a_00_2 = {53 70 69 64 65 72 20 25 64 } //1 Spider %d
		$a_00_3 = {5c 63 6f 6d 5c 73 79 73 6c 6f 67 2e 64 61 74 00 25 73 5c 25 64 2e 62 61 6b } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
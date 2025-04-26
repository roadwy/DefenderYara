
rule Backdoor_Win32_Zegost_gen_A{
	meta:
		description = "Backdoor:Win32/Zegost.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 } //1 WinSta0\Default
		$a_03_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d [0-10] 2e 65 78 65 } //1
		$a_03_2 = {5b 57 49 4e 5d [0-06] 5b 43 54 52 4c 5d } //1
		$a_01_3 = {25 2d 32 34 73 20 25 2d 31 35 73 } //1 %-24s %-15s
		$a_00_4 = {48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 6e } //1 Http/1.1 403 Forbidden
		$a_00_5 = {5b 70 72 69 6e 74 20 73 63 72 65 65 6e 5d } //1 [print screen]
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
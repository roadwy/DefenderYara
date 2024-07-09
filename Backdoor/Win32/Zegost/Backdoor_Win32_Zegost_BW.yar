
rule Backdoor_Win32_Zegost_BW{
	meta:
		description = "Backdoor:Win32/Zegost.BW,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //1 [Print Screen]
		$a_00_1 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 } //1 WinSta0\Default
		$a_01_2 = {25 2d 32 34 73 20 25 2d 31 35 73 } //1 %-24s %-15s
		$a_03_3 = {8a 14 01 80 f2 ?? 88 10 40 ?? 75 f4 } //1
		$a_03_4 = {47 c6 44 24 ?? 68 c6 44 24 ?? 30 c6 44 24 ?? 73 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*2) >=4
 
}
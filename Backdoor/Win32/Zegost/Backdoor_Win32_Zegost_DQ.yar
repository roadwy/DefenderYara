
rule Backdoor_Win32_Zegost_DQ{
	meta:
		description = "Backdoor:Win32/Zegost.DQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 80 04 11 ?? 03 ca 8b 4d fc 80 34 11 ?? 03 ca 42 3b d0 7c e9 } //1
		$a_03_1 = {c6 00 4d c6 40 01 5a 66 81 38 4d 5a 0f 85 ?? ?? ?? ?? 8b 70 3c 03 f0 81 3e 50 45 00 00 0f 85 } //3
		$a_03_2 = {33 db c6 45 ?? 5c c6 45 ?? 52 c6 45 ?? 75 c6 45 ?? 25 c6 45 ?? 64 c6 45 ?? 2e c6 45 ?? 45 c6 45 ?? 58 c6 45 ?? 45 } //1
		$a_03_3 = {89 86 ac 00 00 00 c6 45 ?? 4b c6 45 ?? 75 c6 45 ?? 47 c6 45 ?? 6f c6 45 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*3+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
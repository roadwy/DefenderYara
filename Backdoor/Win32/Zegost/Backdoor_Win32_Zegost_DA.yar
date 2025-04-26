
rule Backdoor_Win32_Zegost_DA{
	meta:
		description = "Backdoor:Win32/Zegost.DA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c6 07 4d c6 47 01 5a ff ?? 6a 00 ff ?? 66 81 3f 4d 5a 74 } //1
		$a_01_1 = {c6 45 00 4d c6 45 01 5a 66 81 7d 00 4d 5a 74 } //1
		$a_03_2 = {73 c6 44 24 ?? 25 c6 44 24 ?? 64 c6 44 24 ?? 2e c6 44 24 ?? 76 c6 44 24 ?? 62 c6 44 24 ?? 73 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}
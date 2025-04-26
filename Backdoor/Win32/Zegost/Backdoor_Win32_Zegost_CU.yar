
rule Backdoor_Win32_Zegost_CU{
	meta:
		description = "Backdoor:Win32/Zegost.CU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 1e 04 ?? 34 ?? 88 04 1e 83 c6 01 3b 75 e8 7c de } //1
		$a_03_1 = {c8 00 00 00 c6 44 24 ?? 50 c6 44 24 ?? 72 c6 44 24 ?? 6f c6 44 24 ?? 64 c6 44 24 ?? 75 c6 44 24 ?? 63 c6 44 24 ?? 74 c6 44 24 ?? 4e c6 44 24 ?? 61 c6 44 24 ?? 6d c6 44 24 ?? 65 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}

rule Trojan_Win32_Zegost_CK_bit{
	meta:
		description = "Trojan:Win32/Zegost.CK!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e } //1
		$a_03_1 = {5c c6 44 24 ?? 75 c6 44 24 ?? 70 c6 44 24 ?? 64 c6 44 24 ?? 61 c6 44 24 ?? 74 c6 44 24 ?? 61 c6 44 24 ?? 00 } //1
		$a_03_2 = {8a 14 01 80 c2 ?? 80 f2 ?? 88 14 01 83 c1 01 3b ce 7c ed } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
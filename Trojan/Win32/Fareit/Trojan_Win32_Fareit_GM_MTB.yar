
rule Trojan_Win32_Fareit_GM_MTB{
	meta:
		description = "Trojan:Win32/Fareit.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 c9 31 d2 6a ?? 5e 81 c6 [0-04] 87 d6 80 34 01 ?? 41 89 d3 39 d9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fareit_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c8 83 e1 [0-30] 8a 0a 80 f1 4a 8b 5d ?? 03 d8 88 0b [0-30] 8b 4d ?? 03 c8 8a 1a 88 19 40 42 3d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
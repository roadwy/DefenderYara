
rule Trojan_Win32_Fareit_GM_MTB{
	meta:
		description = "Trojan:Win32/Fareit.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 c9 31 d2 6a 90 01 01 5e 81 c6 90 02 04 87 d6 80 34 01 90 01 01 41 89 d3 39 d9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fareit_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c8 83 e1 90 02 30 8a 0a 80 f1 4a 8b 5d 90 01 01 03 d8 88 0b 90 02 30 8b 4d 90 01 01 03 c8 8a 1a 88 19 40 42 3d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
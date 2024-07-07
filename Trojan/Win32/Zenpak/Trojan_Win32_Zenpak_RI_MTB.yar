
rule Trojan_Win32_Zenpak_RI_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 89 88 88 88 89 44 24 90 01 01 f7 e1 c1 ea 03 6b c2 0f 8b 4c 24 90 01 01 29 c1 89 c8 83 e8 04 89 4c 24 90 01 01 89 44 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RI_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 cd cc cc cc 89 44 24 90 01 01 f7 e1 c1 ea 04 6b c2 14 8b 4c 24 90 01 01 29 c1 89 c8 83 e8 0b 89 4c 24 90 01 01 89 44 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RI_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 8b 44 24 90 01 01 29 d0 d1 e8 01 d0 c1 e8 04 6b c0 13 8b 4c 24 90 01 01 29 c1 89 c8 83 e8 07 89 4c 24 90 01 01 89 44 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RI_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 84 24 a8 00 00 00 b9 39 8e e3 38 89 84 24 a4 00 00 00 f7 e1 c1 ea 02 6b c2 12 8b 8c 24 a4 00 00 00 29 c1 89 c8 83 e8 0b 89 8c 24 a0 00 00 00 89 84 24 9c 00 00 00 74 7f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
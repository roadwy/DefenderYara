
rule Trojan_Win32_Zenpak_RH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 8b 44 24 90 01 01 29 d0 d1 e8 01 d0 c1 e8 04 6b c0 13 8b 4c 24 90 01 01 29 c1 89 c8 83 e8 0a 89 4c 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RH_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 d0 83 f2 08 01 35 90 01 04 01 d0 b8 09 00 00 00 48 ba 06 00 00 00 89 f8 50 8f 05 90 01 04 8d 05 90 01 04 01 28 b9 02 00 00 00 e2 bf 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RH_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 07 00 00 00 83 c0 0a 31 1d 90 01 04 42 31 d0 8d 05 90 01 04 01 28 8d 05 90 01 04 01 30 8d 05 90 01 04 ff d0 89 d0 8d 05 90 01 04 01 38 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}

rule Trojan_Win32_Zenpak_RA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 24 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 24 29 c1 89 c8 83 e8 05 89 4c 24 20 89 44 24 1c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RA_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 f1 8b 75 ec 8b 5d d0 8a 34 1e 32 34 0f 8b 4d e8 88 34 19 8b 4d c0 8b 75 f0 39 f1 8b 4d b8 8b 75 b0 8b 7d c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RA_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 ?? 29 c1 89 c8 83 e8 0e 89 4c 24 ?? 89 44 24 ?? 74 43 eb 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RA_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 0c 8d 8d fc fe ff ff 81 c1 03 00 00 00 8a 95 ff fe ff ff 80 fa 4d 89 85 d8 fe ff ff 89 8d ?? fe ff ff 88 95 ?? fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RA_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e0 c7 40 14 57 03 00 00 c7 40 10 57 03 00 00 c7 40 0c 57 03 00 00 c7 40 08 57 03 00 00 c7 40 04 57 03 00 00 c7 00 57 03 00 00 a1 ?? ?? ?? ?? ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RA_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 6d 78 29 cc 89 44 24 ?? f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 ?? 29 c1 89 c8 83 e8 0d 89 4c 24 ?? 89 44 24 ?? 74 43 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RA_MTB_7{
	meta:
		description = "Trojan:Win32/Zenpak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 0c 8d 8d fc fe ff ff 81 c1 03 00 00 00 8a 95 ff fe ff ff 80 fa 4d 0f 94 c6 89 85 ?? fe ff ff 89 8d ?? fe ff ff 88 95 ?? fe ff ff 88 b5 ?? fe ff ff 8a 85 ?? fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}

rule Trojan_Win32_Zenpak_RI_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 6c 0c 00 00 88 45 ff 8a 45 ff 0f b6 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RI_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 89 88 88 88 89 44 24 ?? f7 e1 c1 ea 03 6b c2 0f 8b 4c 24 ?? 29 c1 89 c8 83 e8 04 89 4c 24 ?? 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RI_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 cd cc cc cc 89 44 24 ?? f7 e1 c1 ea 04 6b c2 14 8b 4c 24 ?? 29 c1 89 c8 83 e8 0b 89 4c 24 ?? 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RI_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 8b 44 24 ?? 29 d0 d1 e8 01 d0 c1 e8 04 6b c0 13 8b 4c 24 ?? 29 c1 89 c8 83 e8 07 89 4c 24 ?? 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RI_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 84 24 a8 00 00 00 b9 39 8e e3 38 89 84 24 a4 00 00 00 f7 e1 c1 ea 02 6b c2 12 8b 8c 24 a4 00 00 00 29 c1 89 c8 83 e8 0b 89 8c 24 a0 00 00 00 89 84 24 9c 00 00 00 74 7f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule Trojan_Win32_Zenpak_RD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 e8 47 54 00 00 89 25 38 3e 43 00 89 2d 3c 3e 43 00 e8 99 53 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zenpak_RD_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e8 06 83 f2 07 31 d0 e8 1c 00 00 00 4a 83 e8 03 8d 05 ?? ?? ?? ?? 31 28 01 d0 01 d0 89 35 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RD_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 d1 e9 ba 93 24 49 92 89 [0-06] 89 c8 f7 e2 c1 ea 02 6b c2 0e 8b [0-06] 29 c1 89 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RD_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 28 48 31 c2 83 c0 04 40 89 35 ?? ?? ?? ?? 29 c2 48 89 d0 01 3d ?? ?? ?? ?? b9 02 00 00 00 e2 c2 89 45 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RD_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d0 29 c2 8d 05 ?? ?? ?? ?? 31 30 31 2d ?? ?? ?? ?? 40 40 01 d0 8d 05 ?? ?? ?? ?? 89 38 40 8d 05 ?? ?? ?? ?? 31 18 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RD_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 89 88 88 88 89 84 24 ?? ?? 00 00 f7 e1 c1 ea 03 6b c2 0f 8b 8c 24 ?? ?? 00 00 29 c1 89 c8 83 e8 06 89 4c 24 ?? 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RD_MTB_7{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c0 b9 90 00 00 00 8d 54 24 20 be 60 00 00 00 8d bc 24 68 02 00 00 89 3c 24 c7 44 24 04 00 00 00 00 c7 44 24 08 60 00 00 00 89 44 24 1c 89 4c 24 18 89 54 24 14 89 74 24 10 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule Trojan_Win32_Zenpak_RD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 e8 06 83 f2 07 31 d0 e8 1c 00 00 00 4a 83 e8 03 8d 05 90 01 04 31 28 01 d0 01 d0 89 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_RD_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c1 d1 e9 ba 93 24 49 92 89 90 02 06 89 c8 f7 e2 c1 ea 02 6b c2 0e 8b 90 02 06 29 c1 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_RD_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 28 48 31 c2 83 c0 04 40 89 35 90 01 04 29 c2 48 89 d0 01 3d 90 01 04 b9 02 00 00 00 e2 c2 89 45 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_RD_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 d0 29 c2 8d 05 90 01 04 31 30 31 2d 90 01 04 40 40 01 d0 8d 05 90 01 04 89 38 40 8d 05 90 01 04 31 18 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_RD_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 89 88 88 88 89 84 24 90 01 02 00 00 f7 e1 c1 ea 03 6b c2 0f 8b 8c 24 90 01 02 00 00 29 c1 89 c8 83 e8 06 89 4c 24 90 01 01 89 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_RD_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 c0 b9 90 00 00 00 8d 54 24 20 be 60 00 00 00 8d bc 24 68 02 00 00 89 3c 24 c7 44 24 04 00 00 00 00 c7 44 24 08 60 00 00 00 89 44 24 1c 89 4c 24 18 89 54 24 14 89 74 24 10 e8 } //00 00 
	condition:
		any of ($a_*)
 
}
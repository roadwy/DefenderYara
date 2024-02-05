
rule Trojan_Win32_Zenpak_RK_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e1 8b 44 24 90 01 01 29 d0 d1 e8 01 d0 c1 e8 04 6b c0 13 8b 4c 24 90 01 01 29 c1 89 c8 83 e8 90 01 01 89 4c 24 90 01 01 89 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_RK_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 75 08 88 45 90 01 01 89 4d 90 01 01 89 55 90 01 01 89 75 90 01 01 8b 4d 90 01 01 8b 55 90 01 01 0f b6 0c 90 01 01 0f b6 55 90 01 01 29 d1 88 c8 88 45 fb 8a 45 fb 8b 4d f4 8b 55 e8 88 04 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
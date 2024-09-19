
rule Trojan_Win32_Zenpak_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? 5b 1c 00 00 30 c8 a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Zenpak_GXZ_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 20 83 ea ?? 31 d0 48 48 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 f0 ?? 29 d0 89 2d ?? ?? ?? ?? 31 35 ?? ?? ?? ?? 89 d8 50 8f 05 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 31 38 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Zenpak_GXZ_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af d1 0f b7 4d d0 29 d1 89 4d c8 8b 45 e8 8b 4d c0 89 08 8b 4d 0c 0f b7 45 cc 31 c1 66 89 4d ac 8b 55 e8 8b 4d b8 89 4a 04 8b 45 c8 b9 0b 00 00 00 31 d2 f7 f1 88 55 c4 8b 55 e0 83 c2 08 89 55 e0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
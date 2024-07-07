
rule Trojan_Win32_Zenpak_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 20 83 ea 90 01 01 31 d0 48 48 e8 90 01 04 e8 90 01 04 83 f0 90 01 01 29 d0 89 2d 90 01 04 31 35 90 01 04 89 d8 50 8f 05 90 01 04 8d 05 90 01 04 31 38 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Zenpak_GXZ_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af d1 0f b7 4d d0 29 d1 89 4d c8 8b 45 e8 8b 4d c0 89 08 8b 4d 0c 0f b7 45 cc 31 c1 66 89 4d ac 8b 55 e8 8b 4d b8 89 4a 04 8b 45 c8 b9 0b 00 00 00 31 d2 f7 f1 88 55 c4 8b 55 e0 83 c2 08 89 55 e0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
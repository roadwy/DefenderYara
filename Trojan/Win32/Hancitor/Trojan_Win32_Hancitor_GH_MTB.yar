
rule Trojan_Win32_Hancitor_GH_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c8 3b 0d ?? ?? ?? ?? 74 ?? 29 1e 8d 43 ?? 02 c2 66 8b d7 0f b6 c8 66 2b d1 a2 ?? ?? ?? ?? 66 83 ea ?? 0f b7 d2 83 ee ?? 81 fe ?? ?? ?? ?? 7f ?? 8b 44 24 ?? 8b 4c 24 ?? 85 ed 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Hancitor_GH_MTB_2{
	meta:
		description = "Trojan:Win32/Hancitor.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 11 88 10 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 83 c1 01 89 4d ?? 8b 15 ?? ?? ?? ?? 83 ea ?? 2b 15 ?? ?? ?? ?? 89 55 ?? c7 45 ?? 00 00 00 00 eb } //10
		$a_02_1 = {0f b7 55 f4 a1 ?? ?? ?? ?? 8d 4c 02 ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 4c 10 01 66 89 4d ?? e9 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
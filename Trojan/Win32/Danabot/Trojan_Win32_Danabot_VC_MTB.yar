
rule Trojan_Win32_Danabot_VC_MTB{
	meta:
		description = "Trojan:Win32/Danabot.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f7 c7 05 [0-0a] c1 ee ?? 03 c7 03 f1 0f 57 c0 8b cf 66 0f 13 05 ?? ?? ?? ?? c1 e1 ?? 03 ca 33 c8 81 3d [0-0a] 89 4c 24 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Danabot_VC_MTB_2{
	meta:
		description = "Trojan:Win32/Danabot.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f 57 c0 66 0f 13 05 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 2b 45 ?? 89 45 } //1
		$a_03_1 = {51 c7 45 fc ?? ?? ?? ?? 81 6d fc ?? ?? ?? ?? 2d f3 32 05 00 81 6d fc ?? ?? ?? ?? 81 45 fc ?? ?? ?? ?? 8b 45 fc 8b e5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
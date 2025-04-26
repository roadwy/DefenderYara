
rule Trojan_Win32_Danabot_KM_MTB{
	meta:
		description = "Trojan:Win32/Danabot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d3 03 d0 81 e2 ff 00 00 00 81 3d ?? ?? ?? ?? 8a 08 00 00 89 15 ?? ?? ?? ?? 75 90 09 19 00 8b 0d ?? ?? ?? ?? 0f be 86 ?? ?? ?? ?? 8a 99 ?? ?? ?? ?? 03 05 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Danabot_KM_MTB_2{
	meta:
		description = "Trojan:Win32/Danabot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 e2 89 74 24 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? a1 ?? ?? ?? ?? 3d 1a 0c 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Danabot_KM_MTB_3{
	meta:
		description = "Trojan:Win32/Danabot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 03 55 ?? 89 55 ?? 8b 45 ?? 31 45 ?? 2b 75 ?? 8b 45 ?? d1 6d ?? 29 45 ?? ff 4d ?? 0f 85 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Danabot_KM_MTB_4{
	meta:
		description = "Trojan:Win32/Danabot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {83 c0 7b 89 04 24 b8 f9 cd 03 00 01 04 24 83 2c 24 7b 8b 04 24 8a 04 08 88 04 0a 59 c3 } //2
		$a_02_1 = {0f b6 d3 03 ca a3 ?? ?? ?? ?? 81 e1 ff 00 00 00 8a 81 ?? ?? ?? ?? 30 04 37 83 6d ?? 01 8b 75 ?? 85 f6 7d } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}
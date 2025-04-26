
rule Trojan_Win32_Ranumbot_GC_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f6 33 c0 3b ce ?? ?? 8b 3d ?? ?? ?? ?? 90 18 8a 94 07 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 88 14 03 81 f9 ?? ?? ?? ?? 90 18 40 3b c1 } //10
		$a_80_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  10
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Ranumbot_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c1 01 89 4d ?? 8b 55 ?? 8b 45 ?? 3b 82 ?? ?? ?? ?? 73 ?? 8b 4d ?? 03 4d ?? 0f b6 11 8b 45 ?? 03 45 ?? 0f b6 08 33 ?? 8b 55 ?? 03 55 ?? 88 0a } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
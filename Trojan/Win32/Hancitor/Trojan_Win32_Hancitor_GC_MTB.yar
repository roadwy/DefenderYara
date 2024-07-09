
rule Trojan_Win32_Hancitor_GC_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 45 08 0f b7 c1 ff 75 08 8d 94 00 ?? ?? ?? ?? a0 ?? ?? ?? ?? 66 0f b6 c8 66 2b d1 8b 0d ?? ?? ?? ?? 04 01 f6 e9 66 03 d1 0f b7 d2 a2 ?? ?? ?? ?? c3 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Hancitor_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Hancitor.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 89 45 fc eb ?? 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 44 11 ?? a3 ?? ?? ?? ?? 0f b7 4d fc 0f af 0d ?? ?? ?? ?? 03 4d 0c 66 89 4d fc 8b 75 f4 41 83 c6 03 2b c8 83 ee 03 83 c1 71 ff e6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Hancitor_GC_MTB_3{
	meta:
		description = "Trojan:Win32/Hancitor.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c6 8a f2 8a 54 24 ?? 2b c8 8b 06 2a d3 c0 e6 ?? 83 c1 ?? 2a f3 89 0d ?? ?? ?? ?? 80 c2 ?? 88 35 ?? ?? ?? ?? 05 ?? ?? ?? ?? 0f b6 da 2b d9 89 06 33 c9 a3 ?? ?? ?? ?? 83 c3 ?? 89 0d ?? ?? ?? ?? 83 c6 04 ff 4c 24 ?? 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Hancitor_GC_MTB_4{
	meta:
		description = "Trojan:Win32/Hancitor.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_02_0 = {be ac 00 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 94 01 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d be ac 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 5d c3 } //10
		$a_02_1 = {03 45 fc 88 1c 30 8b 4d f8 83 c1 01 89 4d f8 eb [0-0f] 8b e5 5d c3 } //10
		$a_02_2 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 [0-14] 8b 55 08 8b ?? 2b ?? 8b 55 08 89 ?? 5e 8b e5 5d c3 } //10
		$a_02_3 = {89 08 5f 5d c3 90 0a ff 00 90 17 04 01 01 01 01 31 32 30 33 [0-c8] c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d } //10
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_02_3  & 1)*10+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=21
 
}
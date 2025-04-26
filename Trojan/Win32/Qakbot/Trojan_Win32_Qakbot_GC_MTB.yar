
rule Trojan_Win32_Qakbot_GC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 8d 83 ?? ?? ?? ?? 50 8d 83 ?? ?? ?? ?? 50 ff 93 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 56 c7 04 e4 ff ff 0f 00 59 8b 83 ?? ?? ?? ?? 83 bb ?? ?? ?? ?? 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d8 33 18 89 5d a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02 8b 45 d8 83 c0 04 03 45 9c 2b 45 9c 89 45 d8 8b 45 9c 2b 45 9c 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 0f 82 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GC_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 31 0d [0-04] c7 05 [0-04] 00 00 00 00 8b 1d [0-04] 01 1d [0-04] a1 [0-04] 8b 0d [0-04] 89 08 5b 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GC_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 4d fc 31 c9 09 c1 89 8b ?? ?? ?? ?? 8b 4d fc 31 c9 8b 0c e4 83 c4 04 fc f3 a4 55 c7 04 e4 ff ff 0f 00 59 83 bb ?? ?? ?? ?? 00 75 } //10
		$a_02_1 = {89 0c e4 ff b3 ?? ?? ?? ?? 59 01 c1 89 8b ?? ?? ?? ?? 59 ff a3 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Qakbot_GC_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 02 8b 4d ?? 8d 94 01 ?? ?? ?? ?? 8b 45 ?? 89 10 8b 4d ?? 8b 11 81 ea ?? ?? ?? ?? 8b 45 ?? 89 10 8b e5 } //1
		$a_02_1 = {8b d0 33 d1 8b c2 8b ff c7 05 [0-30] 8b ff 01 05 ?? ?? ?? ?? 8b ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GC_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {ba 01 00 00 00 6b c2 ?? 88 88 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ac cf 05 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? 6b 15 ?? ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 66 89 55 ?? e9 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GC_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 da 0f b7 c2 02 d9 8a ca 0f b6 db 2b d8 83 eb ?? 2a cb 89 1d ?? ?? ?? ?? 80 e9 ?? 8b 44 24 ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 30 8b 74 24 ?? 69 c2 ?? ?? ?? ?? 83 c6 04 0f b6 d1 89 74 24 ?? 66 2b d0 8b 44 24 10 66 03 15 ?? ?? ?? ?? 66 03 d0 83 6c 24 ?? 01 0f b7 d2 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GC_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_02_0 = {be ac 00 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 94 01 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d be ac 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 5d c3 90 0a 3c 00 c7 05 } //10
		$a_02_1 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 [0-14] 8b 55 08 8b ?? 2b ?? 8b 55 08 89 ?? 5e 8b e5 5d c3 } //10
		$a_02_2 = {03 45 fc 88 1c 30 8b 4d f8 83 c1 01 89 4d f8 eb [0-0f] 8b e5 5d c3 } //10
		$a_02_3 = {89 08 5f 5d c3 90 0a ff 00 33 [0-c8] c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d } //10
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_02_3  & 1)*10+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=21
 
}
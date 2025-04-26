
rule Trojan_Win32_Qakbot_GL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 [0-19] 33 d9 [0-02] c7 05 [0-04] 00 00 00 00 [0-06] 01 1d [0-04] a1 [0-04] 8b 0d [0-04] 89 08 5b 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GL_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 4d 08 8d 4c 02 d0 ba ?? ?? ?? ?? 2b d0 03 ca 83 c4 0c 8b f0 c6 05 ?? ?? ?? ?? fc 89 0d ?? ?? ?? ?? 8b 7d 08 05 ?? ?? ?? ?? ff d7 90 0a 46 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GL_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 01 10 [0-18] ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 fc 33 c2 03 d8 } //10
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}
rule Trojan_Win32_Qakbot_GL_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 4b 6a 00 [0-0a] e8 ?? ?? ?? ?? 2b d8 4b 8b 45 d8 33 18 89 5d a0 6a 00 e8 ?? ?? ?? ?? 8b d8 03 5d a0 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GL_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 f0 2b f3 b3 ?? f6 eb 03 f7 2a d0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 75 00 88 15 ?? ?? ?? ?? 75 [0-0a] 66 0f b6 44 24 ?? 8b 1d ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 66 2b c3 89 75 00 66 83 c0 ?? 83 c5 04 ff 4c 24 ?? 89 35 ?? ?? ?? ?? 0f b7 d0 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GL_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 01 10 [0-0c] 8b d8 a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 45 fc 03 d8 a1 ?? ?? ?? ?? 33 18 } //10
		$a_02_1 = {03 d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? e9 } //10
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GL_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 45 cc 03 45 ac 2d f2 05 00 00 [0-0c] 8b ?? d8 31 [0-5a] 33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 90 0a 18 00 99 52 50 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GL_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {2b d8 89 5d ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 [0-07] 8b d8 8b 45 e8 83 c0 04 03 d8 [0-50] 8b 45 ?? 3b 45 ?? 0f 82 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GL_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b ec 83 c4 e4 8d 45 fc 50 68 40 00 00 00 68 71 0c 00 00 68 61 40 0a 10 68 ff ff ff ff ff 15 ?? ?? ?? ?? 8b c5 8b e5 5d c3 } //10
		$a_02_1 = {81 e8 04 7a cc 8e 33 05 ?? ?? ?? ?? 2b c6 83 f0 6f 81 c0 7c f7 41 71 89 45 ?? e8 ?? ?? ?? ?? e8 } //5
		$a_00_2 = {34 1a 68 12 dc 09 10 c3 } //3
		$a_00_3 = {c0 c8 06 68 e1 0a 0a 10 c3 } //2
		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //VirtualProtectEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*5+(#a_00_2  & 1)*3+(#a_00_3  & 1)*2+(#a_80_4  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GL_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 01 10 a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 45 fc 8b 15 ?? ?? ?? ?? 31 02 83 45 fc 04 83 05 ?? ?? ?? ?? 04 } //10
		$a_02_1 = {03 d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? e9 } //4
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //4
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*4+(#a_00_2  & 1)*4+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=16
 
}
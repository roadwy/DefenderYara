
rule Trojan_Win32_Qakbot_GL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 90 02 19 33 d9 90 02 02 c7 05 90 02 04 00 00 00 00 90 02 06 01 1d 90 02 04 a1 90 02 04 8b 0d 90 02 04 89 08 5b 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GL_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 4d 08 8d 4c 02 d0 ba 90 01 04 2b d0 03 ca 83 c4 0c 8b f0 c6 05 90 01 04 fc 89 0d 90 01 04 8b 7d 08 05 90 01 04 ff d7 90 0a 46 00 e8 90 01 04 a1 90 01 04 8b 0d 90 01 04 8b 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GL_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 01 10 90 02 18 90 01 04 8b d8 a1 90 01 04 8b 00 8b 15 90 01 04 81 c2 90 01 04 03 55 fc 33 c2 03 d8 90 00 } //10
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}
rule Trojan_Win32_Qakbot_GL_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 90 01 04 8b 5d a0 2b d8 4b 6a 00 90 02 0a e8 90 01 04 2b d8 4b 8b 45 d8 33 18 89 5d a0 6a 00 e8 90 01 04 8b d8 03 5d a0 6a 00 e8 90 01 04 03 d8 6a 00 e8 90 01 04 03 d8 6a 00 e8 90 01 04 03 d8 8b 45 d8 89 18 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GL_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 f0 2b f3 b3 90 01 01 f6 eb 03 f7 2a d0 81 3d 90 01 08 89 35 90 01 04 8b 75 00 88 15 90 01 04 75 90 02 0a 66 0f b6 44 24 90 01 01 8b 1d 90 01 04 81 c6 90 01 04 66 2b c3 89 75 00 66 83 c0 90 01 01 83 c5 04 ff 4c 24 90 01 01 89 35 90 01 04 0f b7 d0 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GL_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 01 10 90 02 0c 8b d8 a1 90 01 04 05 90 01 04 03 45 fc 03 d8 a1 90 01 04 33 18 90 00 } //10
		$a_02_1 = {03 d8 01 1d 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 e9 90 00 } //10
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GL_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 45 cc 03 45 ac 2d f2 05 00 00 90 02 0c 8b 90 01 01 d8 31 90 02 5a 33 d2 3b 54 24 04 75 90 01 01 3b 04 24 5a 58 90 0a 18 00 99 52 50 90 00 } //10
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
		$a_02_0 = {2b d8 89 5d 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 90 02 07 8b d8 8b 45 e8 83 c0 04 03 d8 90 02 50 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //10
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
		$a_02_0 = {8b ec 83 c4 e4 8d 45 fc 50 68 40 00 00 00 68 71 0c 00 00 68 61 40 0a 10 68 ff ff ff ff ff 15 90 01 04 8b c5 8b e5 5d c3 90 00 } //10
		$a_02_1 = {81 e8 04 7a cc 8e 33 05 90 01 04 2b c6 83 f0 6f 81 c0 7c f7 41 71 89 45 90 01 01 e8 90 01 04 e8 90 00 } //5
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
		$a_02_0 = {8b 55 fc 01 10 a1 90 01 04 05 90 01 04 03 45 fc 8b 15 90 01 04 31 02 83 45 fc 04 83 05 90 01 04 04 90 00 } //10
		$a_02_1 = {03 d8 01 1d 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 e9 90 00 } //4
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //4
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*4+(#a_00_2  & 1)*4+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=16
 
}

rule Trojan_Win32_Qakbot_GJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 12 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 33 d1 03 c2 8b 15 ?? ?? ?? ?? 89 02 83 05 ?? ?? ?? ?? ?? 83 05 ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 } //1
		$a_01_1 = {2b d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 e6 00 31 fe 8b 7d fc 55 33 2c e4 0b ab [0-04] 83 e1 00 31 e9 5d fc f3 a4 56 c7 04 e4 ff ff 0f 00 59 ff b3 [0-04] 8f 45 fc ff 75 fc 58 53 81 04 e4 [0-04] 29 1c e4 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 ec fc f3 a4 [0-1e] 29 c9 09 c1 89 8b [0-04] 59 52 c7 04 [0-06] 59 55 83 e5 00 0b ab [0-04] 83 e0 00 09 e8 5d 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 89 4d [0-02] 8b 8b [0-04] 01 c1 51 8b 4d [0-02] 58 ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 3b 05 [0-04] 90 18 a1 [0-04] 80 c3 ?? 02 db 81 c6 [0-04] 2a da 89 35 [0-04] 02 1d [0-04] 89 b4 28 [0-04] 83 c5 04 81 fd 4e 07 00 00 73 1d 8b 35 [0-04] 8b 0d [0-04] 8b 3d [0-04] 8b 15 [0-04] e9 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 45 d8 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 [0-07] 8b d8 8b 45 ?? 83 c0 ?? 03 d8 [0-50] 2b d8 [0-04] 8b 45 ?? 3b 45 ?? 0f 82 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 cc 03 45 ac 2d f2 05 00 00 03 45 a0 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 31 18 } //10
		$a_02_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 90 0a 14 00 99 52 50 } //5
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*5+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 "
		
	strings :
		$a_02_0 = {2d f2 05 00 00 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 90 0a 2d 00 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 02 a1 ?? ?? ?? ?? 03 05 } //10
		$a_02_1 = {2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 99 [0-02] a1 ?? ?? ?? ?? 33 d2 3b 54 24 } //10
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=26
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 00 03 05 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 83 e8 5a 03 05 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 } //20
		$a_00_1 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3 } //5
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*20+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=31
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_02_0 = {2b d8 8b 45 ?? 89 18 [0-07] 8b d8 8b 45 ?? 03 45 ?? 2d f2 05 00 00 03 45 ?? 03 d8 [0-07] 2b d8 8b 45 ?? 31 } //10
		$a_02_1 = {8b 00 03 05 ?? ?? ?? ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 e8 ?? ?? ?? ?? 8b d8 83 c3 04 } //10
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=16
 
}

rule Trojan_Win32_Qakbot_GI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 90 01 04 81 c2 90 01 04 03 15 90 01 04 33 90 01 01 03 90 01 01 90 02 1e 89 90 01 01 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GI_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 90 01 04 81 c2 90 01 04 03 15 90 01 04 33 90 01 01 03 90 01 01 90 02 28 89 90 01 01 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GI_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {f3 a4 52 c7 04 e4 90 01 04 59 8b 83 90 01 04 56 c7 04 90 01 05 8f 83 90 01 04 21 8b 90 01 04 6a 00 01 3c 90 01 01 50 5f 03 bb 90 01 04 89 f8 5f ff e0 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GI_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 90 02 28 31 0d 90 02 08 c7 05 90 02 04 00 00 00 00 8b 1d 90 02 04 01 1d 90 02 04 a1 90 02 04 8b 0d 90 02 04 89 08 5b 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GI_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 33 05 90 01 04 a3 90 01 04 a1 90 01 04 8b 15 90 01 04 89 02 a1 90 01 04 83 c0 04 a3 90 01 04 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GI_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 d8 90 02 08 2b d8 8b 45 90 01 01 31 18 90 00 } //10
		$a_00_1 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3 } //1
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=12
 
}
rule Trojan_Win32_Qakbot_GI_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 00 88 86 90 0a 0c 00 8b c6 05 90 00 } //1
		$a_02_1 = {0f b6 c3 b2 90 01 01 f6 ea 02 c1 a2 90 01 04 b8 90 01 04 66 39 05 90 01 04 75 90 01 01 0f b6 c3 a3 90 01 04 8d 86 90 01 04 03 c8 8b 44 24 90 01 01 83 d5 00 83 44 24 90 01 01 04 81 c7 90 01 04 ff 4c 24 90 01 01 89 3d 90 01 04 89 38 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*10) >=11
 
}
rule Trojan_Win32_Qakbot_GI_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 90 02 03 03 45 90 02 03 03 d8 90 02 08 2b d8 8b 45 90 02 1e 31 90 00 } //20
		$a_00_1 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3 } //5
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*20+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=31
 
}
rule Trojan_Win32_Qakbot_GI_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {31 18 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 01 05 90 01 04 a1 90 01 04 83 c0 04 01 05 90 01 04 a1 90 01 04 3b 05 90 0a 5a 00 03 d8 90 02 07 2b d8 90 02 07 03 d8 90 02 07 2b d8 90 00 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GI_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b7 45 f8 99 03 c8 88 4d ff 8b 15 90 01 04 81 c2 d4 b4 08 01 89 15 90 01 04 a1 90 01 04 03 45 90 01 01 8b 0d 90 01 04 89 88 90 01 04 0f b7 55 90 01 01 a1 90 01 04 8d 8c 10 90 01 04 66 89 4d 90 01 01 e9 90 00 } //10
		$a_02_1 = {8b 02 05 58 f3 0b 01 89 02 83 c2 04 a3 90 01 04 0f b7 c3 2b c8 89 54 24 18 8b 15 90 01 04 8d 04 cd 00 00 00 00 2b c1 2b 05 90 01 04 03 44 24 90 01 01 01 44 24 90 01 01 83 6c 24 90 01 01 01 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=10
 
}
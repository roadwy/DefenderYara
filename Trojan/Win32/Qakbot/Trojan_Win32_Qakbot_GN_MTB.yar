
rule Trojan_Win32_Qakbot_GN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 90 01 04 81 c2 90 01 04 03 15 90 01 04 33 90 02 c8 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GN_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 90 17 02 01 01 31 33 90 01 01 c7 05 90 01 04 00 00 00 00 01 90 02 05 a1 90 01 04 8b 0d 90 01 04 89 08 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GN_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 4b a1 90 01 04 33 18 89 1d 90 02 32 03 d8 a1 90 01 04 89 18 90 02 0a 8b d8 a1 90 01 04 83 c0 04 03 d8 90 02 0a 03 d8 89 1d 90 01 04 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GN_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 31 0d 90 02 04 eb 00 c7 05 90 02 5a 01 90 02 05 a1 90 02 04 8b 0d 90 02 04 89 08 5e 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GN_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b d1 89 55 90 01 01 0f b6 05 90 02 04 03 45 90 01 01 89 45 90 01 01 0f b6 0d 90 02 04 8b 55 90 01 01 2b d1 89 55 90 01 01 0f b6 05 90 02 04 03 45 90 01 01 89 45 90 01 01 0f b6 0d 90 02 04 33 4d 90 01 01 89 4d 90 01 01 8b 15 90 02 04 03 55 90 01 01 8a 45 90 01 01 88 02 e9 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GN_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a ff ff 35 90 02 04 59 ff d1 90 0a 28 00 8b 15 90 02 04 89 15 90 02 04 ff 75 90 02 01 b9 90 02 04 51 ff 75 90 02 01 ff 75 90 00 } //1
		$a_02_1 = {8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 33 c0 90 0a ff 00 90 17 04 01 01 01 01 31 32 30 33 90 02 c8 a1 90 01 04 c7 05 90 01 04 00 00 00 00 01 05 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GN_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 71 00 00 00 ff 90 01 05 b8 dd 09 00 00 ff 90 01 05 b8 16 02 00 00 ff 90 01 05 b8 90 01 01 02 00 00 ff 90 01 05 ff 90 01 05 b8 01 00 00 00 50 ff 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GN_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 71 00 00 00 ff 90 02 05 b8 dd 09 00 00 ff 90 02 05 b8 16 02 00 00 ff 90 02 05 b8 90 01 01 02 00 00 ff 90 02 05 ff 90 02 05 b8 01 00 00 00 50 ff 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GN_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 83 bb 90 02 04 00 75 90 00 } //1
		$a_02_1 = {50 5d 03 ab 90 02 04 89 e8 5d ff 75 90 02 02 89 04 90 02 02 8d 83 90 02 04 51 29 0c 90 02 02 01 04 90 02 02 8d 83 90 02 04 ff 75 90 02 02 89 04 90 02 02 ff 93 90 02 04 50 8f 45 90 02 02 ff 75 90 02 02 8f 83 90 02 04 8f 45 90 02 02 8b 45 90 02 02 ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GN_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {01 10 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 89 45 90 01 01 90 02 07 8b d8 03 5d 90 02 08 2b d8 8b 45 90 01 01 33 18 89 5d 90 00 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GN_MTB_11{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a ff ff 35 90 02 04 59 ff d1 90 0a 28 00 8b 15 90 02 04 89 15 90 02 04 ff 75 90 02 01 b9 90 02 04 51 ff 75 90 02 01 ff 75 90 00 } //1
		$a_02_1 = {b8 f0 e9 00 00 b8 f0 e9 00 00 b8 f0 e9 00 00 b8 f0 e9 00 00 31 0d 90 02 c8 a1 90 02 04 c7 05 90 02 04 00 00 00 00 01 05 90 02 04 8b ff 8b 0d 90 02 04 8b 15 90 02 04 89 11 33 c0 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GN_MTB_12{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2d 00 10 00 00 89 45 ec 83 45 ec 04 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 71 00 00 00 ff 75 90 01 01 b8 90 01 04 ff 75 90 01 01 b8 90 01 04 ff 75 90 01 01 b8 90 01 04 ff 75 90 01 01 ff 35 90 01 04 b8 01 00 00 00 50 ff 65 ec 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GN_MTB_13{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 d8 90 02 0a 2b d8 90 02 0a 03 d8 90 02 0a 2b d8 8b 45 90 01 01 31 18 90 02 0a 8b 90 01 01 83 c3 04 90 02 3c 2b d8 90 02 04 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GN_MTB_14{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 90 01 01 3b 04 24 5a 58 90 0a af 00 01 02 a1 90 01 04 2d 32 02 00 00 03 05 90 01 04 a3 90 02 3c 31 02 90 00 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 90 02 05 03 90 02 05 8b 90 02 05 e8 90 00 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_02_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GN_MTB_15{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 45 d8 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 90 02 08 8b d8 8b 45 90 01 01 83 c0 90 01 01 03 d8 90 02 07 2b d8 90 00 } //10
		$a_02_1 = {8b d8 8b 45 90 01 01 83 c0 90 01 01 03 d8 90 02 07 2b d8 89 5d 90 01 01 8b 45 90 01 01 3b 45 90 00 } //5
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*5+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GN_MTB_16{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 06 00 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 90 01 01 3b 04 24 5a 58 90 00 } //10
		$a_02_1 = {2d 00 10 00 00 a3 90 01 04 83 05 90 01 04 04 ff 90 01 05 ff 90 01 05 ff 90 01 05 ff 90 01 05 ff 90 01 05 6a 01 ff 90 00 } //10
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 90 02 05 03 90 02 05 8b 90 02 05 e8 90 00 } //5
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 90 02 1e 8b d0 8b 90 02 06 e8 90 00 } //5
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*5+(#a_02_3  & 1)*5+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=26
 
}
rule Trojan_Win32_Qakbot_GN_MTB_17{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 51 8b 15 90 02 04 52 ff 15 90 02 04 a1 90 02 04 a3 90 02 04 68 90 02 04 e8 90 02 04 83 c4 04 8b 0d 90 02 04 89 0d 90 02 04 8b 0d 90 02 04 81 e9 90 02 04 51 c7 05 90 02 08 ff 05 90 02 04 ff 35 90 02 04 ff 35 90 02 04 ff 35 90 02 04 a1 90 02 04 ff d0 90 00 } //1
		$a_02_1 = {c6 00 00 8b 0d 90 02 04 03 0d 90 02 04 0f be 11 a1 90 02 04 03 05 90 02 04 0f be 08 03 ca 8b 15 90 02 04 03 15 90 02 04 88 0a a1 90 02 04 83 c0 01 a3 90 02 04 eb 90 02 01 8b e5 5d c3 90 00 } //1
		$a_02_2 = {89 08 5f 5d c3 90 0a 23 00 90 17 04 01 01 01 01 31 32 30 33 90 02 05 8b c8 8b d1 89 15 90 02 04 a1 90 02 04 8b 0d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Qakbot_GN_MTB_18{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 90 01 01 3b 04 24 5a 58 90 0a 7d 00 01 02 a1 90 01 04 2d 32 02 00 00 03 05 90 01 04 a3 90 01 04 a1 90 01 04 a3 90 01 04 a1 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 90 00 } //10
		$a_02_1 = {33 d2 3b 54 24 04 75 90 01 01 3b 04 24 5a 58 90 0a af 00 01 02 a1 90 01 04 2d 32 02 00 00 03 05 90 01 04 a3 90 02 32 31 18 90 00 } //10
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 90 02 05 03 90 02 05 8b 90 02 05 e8 90 00 } //5
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_02_3  & 1)*5+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GN_MTB_19{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 1c 64 a1 18 00 00 00 3e 8b 90 02 01 30 3e 8b 90 02 01 0c 89 90 02 0c 8b 48 0c 90 02 19 b8 01 00 00 00 85 c0 0f 84 90 02 04 83 90 02 05 00 75 90 00 } //1
		$a_02_1 = {8b 4d fc 51 8b 15 90 02 04 52 ff 15 90 02 04 a1 90 02 04 a3 90 02 04 68 90 02 04 e8 90 02 04 83 c4 04 8b 0d 90 02 04 89 0d 90 02 04 8b 0d 90 02 04 81 e9 90 02 04 51 c7 05 90 02 08 ff 05 90 02 04 ff 35 90 02 04 ff 35 90 02 04 ff 35 90 02 04 a1 90 02 04 ff d0 90 00 } //1
		$a_02_2 = {c6 00 00 8b 0d 90 02 04 03 0d 90 02 04 0f be 11 a1 90 02 04 03 05 90 02 04 0f be 08 03 ca 8b 15 90 02 04 03 15 90 02 04 88 0a a1 90 02 04 83 c0 01 a3 90 02 04 eb 90 02 01 8b e5 5d c3 90 00 } //1
		$a_02_3 = {89 08 5f 5b 5d c3 90 0a 23 00 90 17 04 01 01 01 01 31 32 30 33 90 02 05 8b c8 8b d1 89 15 90 02 04 a1 90 02 04 8b 0d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}
rule Trojan_Win32_Qakbot_GN_MTB_20{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_02_0 = {99 03 04 24 13 54 24 04 83 c4 90 01 01 8b d0 8b 45 90 01 01 03 45 90 01 01 8b 4d 90 01 01 e8 90 00 } //5
		$a_02_1 = {2b d8 89 5d 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 90 17 04 01 01 01 01 30 32 31 33 90 02 0f 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 00 } //10
		$a_02_2 = {2b d8 8b 45 90 01 01 90 17 04 01 01 01 01 30 32 31 33 90 02 01 89 5d 90 01 01 8b 45 90 01 01 8b 55 90 01 01 89 02 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 00 } //10
		$a_02_3 = {2b d8 89 5d 90 01 01 8b 45 90 02 04 90 17 02 01 01 31 33 90 02 0f 8b 45 90 01 01 8b 55 90 01 01 89 02 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 00 } //10
		$a_00_4 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_02_3  & 1)*10+(#a_00_4  & 1)*5+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GN_MTB_21{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 90 02 02 64 a1 18 00 00 00 3e 8b 90 02 02 30 3e 8b 90 02 02 0c 89 0d 90 02 04 a1 90 02 04 8b 48 0c 89 0d 90 02 04 8b 15 90 02 04 89 15 90 02 04 b8 01 00 00 00 85 c0 0f 84 90 02 04 83 3d 90 02 04 00 75 90 00 } //1
		$a_02_1 = {55 8b ec eb 00 a1 90 02 04 a3 90 02 04 ff 35 90 02 04 6a 00 c7 04 90 02 06 81 2c 90 02 06 ff 35 90 02 04 ff 35 90 02 04 ff 35 90 02 04 59 ff d1 90 00 } //1
		$a_02_2 = {03 c6 03 45 90 02 02 8b 15 90 02 04 03 55 90 02 02 03 55 90 02 02 03 55 90 02 02 8b 0d 90 02 04 8b 35 90 02 04 8a 04 90 02 02 88 04 90 02 02 8b 0d 90 02 04 83 c1 01 89 0d 90 02 04 eb 90 02 02 5e 8b e5 5d c3 90 00 } //1
		$a_02_3 = {b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 90 17 04 01 01 01 01 31 32 30 33 90 02 06 eb 00 c7 05 90 02 04 00 00 00 00 90 02 5a 01 90 02 05 a1 90 02 04 8b 0d 90 02 04 89 08 5e 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}

rule Trojan_Win32_Qakbot_GO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 33 [0-ff] 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GO_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 33 [0-64] 89 18 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GO_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 ?? 03 d8 [0-ff] 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GO_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 ?? 03 d8 90 08 40 01 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GO_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {32 c1 2a c1 04 ?? c0 c0 ?? c0 c0 ?? 34 ?? c0 c8 ?? 32 c1 c0 c0 ?? 04 ?? 2a c1 32 c1 32 c1 34 ?? 2c ?? aa 4a 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GO_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 ?? 03 d8 90 08 58 02 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 } //10
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}
rule Trojan_Win32_Qakbot_GO_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 ?? 03 d8 90 08 c2 01 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 } //10
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}
rule Trojan_Win32_Qakbot_GO_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 4b a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04 03 d8 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 d8 89 1d ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GO_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 55 fc 89 55 ?? 0f b6 05 [0-04] 03 45 ?? 89 45 ?? 0f b6 0d [0-04] 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 [0-04] 33 45 ?? 89 45 ?? 0f b6 0d [0-04] 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 [0-04] 8b 4d ?? 2b c8 89 4d ?? 8b 15 [0-04] 03 55 ?? 8a 45 ?? 88 02 e9 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GO_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {2b d8 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 90 0a c8 00 01 02 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 90 17 02 01 01 31 33 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GO_MTB_11{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 [0-02] 57 8b 4d [0-02] 8b f9 03 f9 33 7d [0-02] 3b f9 76 [0-02] 51 51 57 ff 75 [0-02] e8 [0-04] 59 49 75 [0-02] b8 00 00 00 00 5f c9 c2 } //1
		$a_02_1 = {51 68 00 10 00 00 52 50 ff 93 [0-04] 8b f8 89 bb [0-04] 8b b3 [0-04] 8b 8b [0-04] fc f3 a4 b9 [0-04] 8b 83 [0-04] 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 03 83 [0-04] ff e0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GO_MTB_12{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {73 52 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? e8 [0-1e] 03 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb 90 0a 64 00 a1 ?? ?? ?? ?? 3b 05 } //10
		$a_02_1 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 ?? 03 d8 } //10
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GO_MTB_13{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 90 0a c8 00 01 02 a1 ?? ?? ?? ?? 83 e8 0b 03 05 ?? ?? ?? ?? a3 [0-4b] 90 17 02 01 01 31 33 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-05] 03 [0-05] 8b [0-05] e8 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_02_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GO_MTB_14{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 90 0a c8 00 01 02 a1 ?? ?? ?? ?? 2d ?? ?? 00 00 03 05 ?? ?? ?? ?? a3 [0-96] 90 17 02 01 01 31 33 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-05] 03 [0-05] 8b [0-05] e8 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_02_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GO_MTB_15{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 90 0a fa 00 01 02 a1 ?? ?? ?? ?? 2d ?? ?? 00 00 03 05 ?? ?? ?? ?? a3 [0-96] 90 17 02 01 01 31 33 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-05] 03 [0-05] 8b [0-05] e8 } //5
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 [0-1e] 8b d0 8b [0-06] e8 } //5
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_02_2  & 1)*5+(#a_02_3  & 1)*5+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GO_MTB_16{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_02_0 = {89 02 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 90 0a af 00 01 02 a1 [0-0f] 03 05 ?? ?? ?? ?? a3 [0-3c] 90 17 02 01 01 31 33 } //10
		$a_02_1 = {89 10 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 90 0a af 00 01 10 a1 [0-0f] 03 05 ?? ?? ?? ?? a3 [0-3c] 90 17 02 01 01 31 33 } //10
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-05] 03 [0-05] 8b [0-05] e8 } //5
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_02_3  & 1)*5+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GO_MTB_17{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 07 00 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 90 0a fa 00 2b d8 89 5d ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 90 17 02 01 01 31 33 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-05] 03 [0-05] 8b [0-05] e8 } //3
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 [0-1e] 8b d0 8b [0-06] e8 } //3
		$a_02_4 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 8b 45 ?? 03 45 ?? 8b 4d ?? e8 } //3
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_02_2  & 1)*3+(#a_02_3  & 1)*3+(#a_02_4  & 1)*3+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=19
 
}
rule Trojan_Win32_Qakbot_GO_MTB_18{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 90 0a c8 00 01 02 a1 ?? ?? ?? ?? 2d ?? ?? 00 00 03 05 ?? ?? ?? ?? a3 [0-96] 90 17 02 01 01 31 33 } //10
		$a_02_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 90 0a c8 00 a1 ?? ?? ?? ?? 2d ?? ?? 00 00 03 05 ?? ?? ?? ?? 03 [0-96] 90 17 02 01 01 31 33 } //10
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 [0-1e] 8b d0 8b [0-06] e8 } //5
		$a_02_4 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-05] 03 [0-05] 8b [0-05] e8 } //5
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_02_3  & 1)*5+(#a_02_4  & 1)*5+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=21
 
}
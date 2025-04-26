
rule Trojan_Win32_Qakbot_GN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 33 [0-c8] 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GN_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 90 17 02 01 01 31 33 ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 [0-05] a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GN_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 4b a1 ?? ?? ?? ?? 33 18 89 1d [0-32] 03 d8 a1 ?? ?? ?? ?? 89 18 [0-0a] 8b d8 a1 ?? ?? ?? ?? 83 c0 04 03 d8 [0-0a] 03 d8 89 1d ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GN_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 31 0d [0-04] eb 00 c7 05 [0-5a] 01 [0-05] a1 [0-04] 8b 0d [0-04] 89 08 5e 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GN_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b d1 89 55 ?? 0f b6 05 [0-04] 03 45 ?? 89 45 ?? 0f b6 0d [0-04] 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 [0-04] 03 45 ?? 89 45 ?? 0f b6 0d [0-04] 33 4d ?? 89 4d ?? 8b 15 [0-04] 03 55 ?? 8a 45 ?? 88 02 e9 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GN_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a ff ff 35 [0-04] 59 ff d1 90 0a 28 00 8b 15 [0-04] 89 15 [0-04] ff 75 [0-01] b9 [0-04] 51 ff 75 [0-01] ff 75 } //1
		$a_02_1 = {8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 33 c0 90 0a ff 00 90 17 04 01 01 01 01 31 32 30 33 [0-c8] a1 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GN_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 71 00 00 00 ff ?? ?? ?? ?? ?? b8 dd 09 00 00 ff ?? ?? ?? ?? ?? b8 16 02 00 00 ff ?? ?? ?? ?? ?? b8 ?? 02 00 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? b8 01 00 00 00 50 ff } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GN_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 71 00 00 00 ff [0-05] b8 dd 09 00 00 ff [0-05] b8 16 02 00 00 ff [0-05] b8 ?? 02 00 00 ff [0-05] ff [0-05] b8 01 00 00 00 50 ff } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GN_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 83 bb [0-04] 00 75 } //1
		$a_02_1 = {50 5d 03 ab [0-04] 89 e8 5d ff 75 [0-02] 89 04 [0-02] 8d 83 [0-04] 51 29 0c [0-02] 01 04 [0-02] 8d 83 [0-04] ff 75 [0-02] 89 04 [0-02] ff 93 [0-04] 50 8f 45 [0-02] ff 75 [0-02] 8f 83 [0-04] 8f 45 [0-02] 8b 45 [0-02] ff e0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GN_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {01 10 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 ?? [0-07] 8b d8 03 5d [0-08] 2b d8 8b 45 ?? 33 18 89 5d } //10
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
		$a_02_0 = {6a ff ff 35 [0-04] 59 ff d1 90 0a 28 00 8b 15 [0-04] 89 15 [0-04] ff 75 [0-01] b9 [0-04] 51 ff 75 [0-01] ff 75 } //1
		$a_02_1 = {b8 f0 e9 00 00 b8 f0 e9 00 00 b8 f0 e9 00 00 b8 f0 e9 00 00 31 0d [0-c8] a1 [0-04] c7 05 [0-04] 00 00 00 00 01 05 [0-04] 8b ff 8b 0d [0-04] 8b 15 [0-04] 89 11 33 c0 e9 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GN_MTB_12{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2d 00 10 00 00 89 45 ec 83 45 ec 04 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 71 00 00 00 ff 75 ?? b8 ?? ?? ?? ?? ff 75 ?? b8 ?? ?? ?? ?? ff 75 ?? b8 ?? ?? ?? ?? ff 75 ?? ff 35 ?? ?? ?? ?? b8 01 00 00 00 50 ff 65 ec } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GN_MTB_13{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 [0-0a] 2b d8 [0-0a] 03 d8 [0-0a] 2b d8 8b 45 ?? 31 18 [0-0a] 8b ?? 83 c3 04 [0-3c] 2b d8 [0-04] 8b 45 ?? 3b 45 ?? 0f 82 } //10
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
		$a_02_0 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 90 0a af 00 01 02 a1 ?? ?? ?? ?? 2d 32 02 00 00 03 05 ?? ?? ?? ?? a3 [0-3c] 31 02 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-05] 03 [0-05] 8b [0-05] e8 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_02_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GN_MTB_15{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 45 d8 03 45 ?? 03 45 ?? 8b 55 ?? 31 [0-08] 8b d8 8b 45 ?? 83 c0 ?? 03 d8 [0-07] 2b d8 } //10
		$a_02_1 = {8b d8 8b 45 ?? 83 c0 ?? 03 d8 [0-07] 2b d8 89 5d ?? 8b 45 ?? 3b 45 } //5
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
		$a_02_0 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 } //10
		$a_02_1 = {2d 00 10 00 00 a3 ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 6a 01 ff } //10
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-05] 03 [0-05] 8b [0-05] e8 } //5
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 [0-1e] 8b d0 8b [0-06] e8 } //5
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*5+(#a_02_3  & 1)*5+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=26
 
}
rule Trojan_Win32_Qakbot_GN_MTB_17{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 51 8b 15 [0-04] 52 ff 15 [0-04] a1 [0-04] a3 [0-04] 68 [0-04] e8 [0-04] 83 c4 04 8b 0d [0-04] 89 0d [0-04] 8b 0d [0-04] 81 e9 [0-04] 51 c7 05 [0-08] ff 05 [0-04] ff 35 [0-04] ff 35 [0-04] ff 35 [0-04] a1 [0-04] ff d0 } //1
		$a_02_1 = {c6 00 00 8b 0d [0-04] 03 0d [0-04] 0f be 11 a1 [0-04] 03 05 [0-04] 0f be 08 03 ca 8b 15 [0-04] 03 15 [0-04] 88 0a a1 [0-04] 83 c0 01 a3 [0-04] eb [0-01] 8b e5 5d c3 } //1
		$a_02_2 = {89 08 5f 5d c3 90 0a 23 00 90 17 04 01 01 01 01 31 32 30 33 [0-05] 8b c8 8b d1 89 15 [0-04] a1 [0-04] 8b 0d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Qakbot_GN_MTB_18{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 90 0a 7d 00 01 02 a1 ?? ?? ?? ?? 2d 32 02 00 00 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 } //10
		$a_02_1 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 90 0a af 00 01 02 a1 ?? ?? ?? ?? 2d 32 02 00 00 03 05 ?? ?? ?? ?? a3 [0-32] 31 18 } //10
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-05] 03 [0-05] 8b [0-05] e8 } //5
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_02_3  & 1)*5+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GN_MTB_19{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 1c 64 a1 18 00 00 00 3e 8b [0-01] 30 3e 8b [0-01] 0c 89 [0-0c] 8b 48 0c [0-19] b8 01 00 00 00 85 c0 0f 84 [0-04] 83 [0-05] 00 75 } //1
		$a_02_1 = {8b 4d fc 51 8b 15 [0-04] 52 ff 15 [0-04] a1 [0-04] a3 [0-04] 68 [0-04] e8 [0-04] 83 c4 04 8b 0d [0-04] 89 0d [0-04] 8b 0d [0-04] 81 e9 [0-04] 51 c7 05 [0-08] ff 05 [0-04] ff 35 [0-04] ff 35 [0-04] ff 35 [0-04] a1 [0-04] ff d0 } //1
		$a_02_2 = {c6 00 00 8b 0d [0-04] 03 0d [0-04] 0f be 11 a1 [0-04] 03 05 [0-04] 0f be 08 03 ca 8b 15 [0-04] 03 15 [0-04] 88 0a a1 [0-04] 83 c0 01 a3 [0-04] eb [0-01] 8b e5 5d c3 } //1
		$a_02_3 = {89 08 5f 5b 5d c3 90 0a 23 00 90 17 04 01 01 01 01 31 32 30 33 [0-05] 8b c8 8b d1 89 15 [0-04] a1 [0-04] 8b 0d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}
rule Trojan_Win32_Qakbot_GN_MTB_20{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_02_0 = {99 03 04 24 13 54 24 04 83 c4 ?? 8b d0 8b 45 ?? 03 45 ?? 8b 4d ?? e8 } //5
		$a_02_1 = {2b d8 89 5d ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 90 17 04 01 01 01 01 30 32 31 33 [0-0f] 83 45 ?? 04 83 45 ?? 04 8b 45 } //10
		$a_02_2 = {2b d8 8b 45 ?? 90 17 04 01 01 01 01 30 32 31 33 [0-01] 89 5d ?? 8b 45 ?? 8b 55 ?? 89 02 83 45 ?? 04 83 45 ?? 04 8b 45 } //10
		$a_02_3 = {2b d8 89 5d ?? 8b 45 [0-04] 90 17 02 01 01 31 33 [0-0f] 8b 45 ?? 8b 55 ?? 89 02 83 45 ?? 04 83 45 ?? 04 8b 45 } //10
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
		$a_02_0 = {55 8b ec 83 ec [0-02] 64 a1 18 00 00 00 3e 8b [0-02] 30 3e 8b [0-02] 0c 89 0d [0-04] a1 [0-04] 8b 48 0c 89 0d [0-04] 8b 15 [0-04] 89 15 [0-04] b8 01 00 00 00 85 c0 0f 84 [0-04] 83 3d [0-04] 00 75 } //1
		$a_02_1 = {55 8b ec eb 00 a1 [0-04] a3 [0-04] ff 35 [0-04] 6a 00 c7 04 [0-06] 81 2c [0-06] ff 35 [0-04] ff 35 [0-04] ff 35 [0-04] 59 ff d1 } //1
		$a_02_2 = {03 c6 03 45 [0-02] 8b 15 [0-04] 03 55 [0-02] 03 55 [0-02] 03 55 [0-02] 8b 0d [0-04] 8b 35 [0-04] 8a 04 [0-02] 88 04 [0-02] 8b 0d [0-04] 83 c1 01 89 0d [0-04] eb [0-02] 5e 8b e5 5d c3 } //1
		$a_02_3 = {b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 b8 bc 01 00 00 90 17 04 01 01 01 01 31 32 30 33 [0-06] eb 00 c7 05 [0-04] 00 00 00 00 [0-5a] 01 [0-05] a1 [0-04] 8b 0d [0-04] 89 08 5e 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}
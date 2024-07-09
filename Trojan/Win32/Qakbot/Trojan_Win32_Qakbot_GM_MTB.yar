
rule Trojan_Win32_Qakbot_GM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 0e 00 00 00 ff 35 ?? ?? ?? ?? b8 9c 00 00 00 ff 35 ?? ?? ?? ?? b8 11 00 00 00 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? b8 01 00 00 00 50 ff 25 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ff c7 05 [0-30] 01 05 [0-30] 8b ff a1 [0-30] 8b 0d ?? ?? ?? ?? 89 08 } //1
		$a_02_1 = {8b 11 89 15 [0-40] 8b 0d [0-c8] a1 [0-20] 33 c1 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GM_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 56 c7 04 e4 ff ff 0f 00 59 8b 83 ?? ?? ?? ?? 50 c7 04 e4 ?? ?? ?? ?? 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 89 55 fc 89 c2 03 93 ?? ?? ?? ?? 52 8b 55 fc 8f 83 ?? ?? ?? ?? ff a3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GM_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 [0-19] 33 [0-03] c7 05 [0-04] 00 00 00 00 [0-06] 01 [0-05] a1 [0-04] 8b 0d [0-04] 89 08 ?? 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GM_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 d8 33 18 89 5d a0 [0-32] 03 d8 8b 45 d8 89 18 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 [0-0a] 8b 55 d8 83 c2 04 03 55 a4 03 c2 40 89 45 d8 8b 45 a8 3b 45 cc 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GM_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 04 e4 ff ff 0f 00 59 6a 00 89 3c [0-01] 31 ff 0b bb [0-04] 89 f8 5f 50 c7 04 e4 [0-04] 8f 83 [0-04] 21 8b [0-04] 6a 00 31 34 [0-01] 50 5e 03 b3 [0-04] 89 f0 5e ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GM_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 04 e4 ff ff 0f 00 59 89 75 [0-01] 31 f6 0b b3 [0-04] 89 f0 8b 75 [0-01] 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 52 8b 93 [0-04] 50 8f 45 [0-01] 01 55 [0-01] ff 75 [0-01] 58 5a ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GM_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 50 c7 04 e4 ff ff 0f 00 59 89 75 [0-01] 33 75 [0-01] 33 b3 [0-04] 83 e0 00 09 f0 8b 75 [0-01] 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 51 8b 8b [0-04] 50 8f 45 [0-01] 01 4d [0-01] ff 75 [0-01] 58 59 ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GM_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 04 e4 31 0c e4 ff 93 [0-04] 51 83 e1 00 31 c1 83 a3 [0-04] 00 09 8b [0-04] 59 29 c9 8f 45 [0-01] 0b 4d [0-01] 8f 45 [0-01] 8b 45 [0-01] 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 51 8b 8b [0-04] 50 8f 45 [0-01] 01 4d [0-01] ff 75 [0-01] 58 59 ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GM_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 ?? 83 c0 04 03 d8 [0-08] 2b d8 89 5d ?? 8b 45 ?? 83 c0 04 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 82 90 0a 4b 00 8b 45 ?? 03 45 ?? 8b 55 ?? 31 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GM_MTB_11{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {99 03 04 24 13 54 24 04 83 c4 ?? 8b d0 8b 45 ?? 03 45 ?? 8b 4d ?? e8 } //5
		$a_02_1 = {2b d8 89 5d ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 } //10
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GM_MTB_12{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 90 0a af 00 01 02 a1 ?? ?? ?? ?? 83 e8 0b 03 05 ?? ?? ?? ?? a3 [0-3c] 90 17 02 01 01 31 33 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-05] 03 [0-05] 8b [0-05] e8 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_02_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GM_MTB_13{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {99 52 50 8b 45 d4 33 d2 3b 54 24 04 75 0d 3b 04 24 5a 58 0f 87 90 0a 64 00 8b 00 33 45 ?? 89 45 ?? 8b 45 ?? 8b 55 ?? 89 02 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 ?? 8b d0 8b 45 ?? 03 45 ?? 8b 4d ?? e8 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_02_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GM_MTB_14{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 00 03 45 ?? 03 d8 [0-96] 8b 45 ?? 05 ?? ?? ?? ?? 03 45 ?? 8b 15 ?? ?? ?? ?? 31 [0-96] 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 45 ?? 0f 82 } //10
		$a_02_1 = {03 d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? e9 } //4
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //4
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*4+(#a_00_2  & 1)*4+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=15
 
}
rule Trojan_Win32_Qakbot_GM_MTB_15{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 45 cc 03 45 [0-28] 2b d8 8b 45 d8 31 18 83 45 ?? 04 83 45 d8 04 8b 45 [0-5a] 33 d2 3b 54 24 04 75 ?? 3b 04 24 5a 58 90 0a 18 00 99 52 50 } //10
		$a_02_1 = {8b d8 8b 45 cc 03 45 ?? 03 d8 [0-07] 2b d8 [0-07] 03 d8 [0-07] 2b d8 8b 45 d8 31 ?? 83 45 ?? 04 83 45 d8 04 8b 45 ?? 3b 45 d4 72 } //10
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GM_MTB_16{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_02_0 = {89 10 83 45 [0-04] 04 83 45 [0-04] 04 8b 45 ?? 3b 45 90 0a af 00 01 10 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 [0-3c] 90 17 02 01 01 31 33 } //10
		$a_02_1 = {89 02 83 45 [0-04] 04 83 45 [0-04] 04 8b 45 ?? 3b 45 90 0a af 00 01 10 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 [0-3c] 90 17 02 01 01 31 33 } //10
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 [0-05] 03 [0-05] 8b [0-05] e8 } //5
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_02_3  & 1)*5+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=21
 
}
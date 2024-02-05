
rule Trojan_Win32_Qakbot_GO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 90 01 04 81 c2 90 01 04 03 15 90 01 04 33 90 02 ff 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 90 01 04 81 c2 90 01 04 03 15 90 01 04 33 90 02 64 89 18 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 90 01 04 81 c2 90 01 04 03 55 90 01 01 33 90 01 01 03 d8 90 02 ff 83 45 90 01 01 04 83 05 90 01 04 04 8b 45 90 01 01 3b 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 90 01 04 81 c2 90 01 04 03 55 90 01 01 33 90 01 01 03 d8 90 08 40 01 83 45 90 01 01 04 83 05 90 01 04 04 8b 45 90 01 01 3b 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {32 c1 2a c1 04 90 01 01 c0 c0 90 01 01 c0 c0 90 01 01 34 90 01 01 c0 c8 90 01 01 32 c1 c0 c0 90 01 01 04 90 01 01 2a c1 32 c1 32 c1 34 90 01 01 2c 90 01 01 aa 4a 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 90 01 04 81 c2 90 01 04 03 55 90 01 01 33 90 01 01 03 d8 90 08 58 02 83 45 90 01 01 04 83 05 90 01 04 04 8b 45 90 01 01 3b 05 90 00 } //01 00 
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 90 01 04 81 c2 90 01 04 03 55 90 01 01 33 90 01 01 03 d8 90 08 c2 01 83 45 90 01 01 04 83 05 90 01 04 04 8b 45 90 01 01 3b 05 90 00 } //01 00 
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d8 4b a1 90 01 04 33 18 89 1d 90 01 04 a1 90 01 04 8b 15 90 01 04 89 02 68 90 01 04 e8 90 01 04 8b d8 a1 90 01 04 83 c0 04 03 d8 68 90 01 04 e8 90 01 04 03 d8 89 1d 90 01 04 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 55 fc 89 55 90 01 01 0f b6 05 90 02 04 03 45 90 01 01 89 45 90 01 01 0f b6 0d 90 02 04 8b 55 90 01 01 2b d1 89 55 90 01 01 0f b6 05 90 02 04 33 45 90 01 01 89 45 90 01 01 0f b6 0d 90 02 04 8b 55 90 01 01 2b d1 89 55 90 01 01 0f b6 05 90 02 04 8b 4d 90 01 01 2b c8 89 4d 90 01 01 8b 15 90 02 04 03 55 90 01 01 8a 45 90 01 01 88 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b d8 89 1d 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 0a c8 00 01 02 a1 90 01 04 03 05 90 01 04 8b 15 90 01 04 90 17 02 01 01 31 33 90 00 } //05 00 
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //01 00 
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_11{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 90 02 02 57 8b 4d 90 02 02 8b f9 03 f9 33 7d 90 02 02 3b f9 76 90 02 02 51 51 57 ff 75 90 02 02 e8 90 02 04 59 49 75 90 02 02 b8 00 00 00 00 5f c9 c2 90 00 } //01 00 
		$a_02_1 = {51 68 00 10 00 00 52 50 ff 93 90 02 04 8b f8 89 bb 90 02 04 8b b3 90 02 04 8b 8b 90 02 04 fc f3 a4 b9 90 02 04 8b 83 90 02 04 68 90 02 04 8f 83 90 02 04 21 8b 90 02 04 03 83 90 02 04 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_12{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {73 52 8b 15 90 01 04 03 15 90 01 04 a1 90 01 04 03 05 90 01 04 8b 0d 90 01 04 e8 90 02 1e 03 05 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 eb 90 0a 64 00 a1 90 01 04 3b 05 90 00 } //0a 00 
		$a_02_1 = {8b 00 8b 15 90 01 04 81 c2 90 01 04 03 55 90 01 01 33 90 01 01 03 d8 90 00 } //01 00 
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_13{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 90 01 01 3b 04 24 5a 58 90 0a c8 00 01 02 a1 90 01 04 83 e8 0b 03 05 90 01 04 a3 90 02 4b 90 17 02 01 01 31 33 90 00 } //05 00 
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //05 00 
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 90 02 05 03 90 02 05 8b 90 02 05 e8 90 00 } //01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_14{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 90 01 01 3b 04 24 5a 58 90 0a c8 00 01 02 a1 90 01 04 2d 90 01 02 00 00 03 05 90 01 04 a3 90 02 96 90 17 02 01 01 31 33 90 00 } //05 00 
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //05 00 
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 90 02 05 03 90 02 05 8b 90 02 05 e8 90 00 } //01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_15{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 90 01 01 3b 04 24 5a 58 90 0a fa 00 01 02 a1 90 01 04 2d 90 01 02 00 00 03 05 90 01 04 a3 90 02 96 90 17 02 01 01 31 33 90 00 } //05 00 
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //05 00 
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 90 02 05 03 90 02 05 8b 90 02 05 e8 90 00 } //05 00 
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 90 02 1e 8b d0 8b 90 02 06 e8 90 00 } //01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_16{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {89 02 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 0a af 00 01 02 a1 90 02 0f 03 05 90 01 04 a3 90 02 3c 90 17 02 01 01 31 33 90 00 } //0a 00 
		$a_02_1 = {89 10 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 0a af 00 01 10 a1 90 02 0f 03 05 90 01 04 a3 90 02 3c 90 17 02 01 01 31 33 90 00 } //05 00 
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //05 00 
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 90 02 05 03 90 02 05 8b 90 02 05 e8 90 00 } //01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_17{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 90 01 01 3b 04 24 5a 58 90 0a fa 00 2b d8 89 5d 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 90 17 02 01 01 31 33 90 00 } //05 00 
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //03 00 
		$a_02_2 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 90 02 05 03 90 02 05 8b 90 02 05 e8 90 00 } //03 00 
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 90 02 1e 8b d0 8b 90 02 06 e8 90 00 } //03 00 
		$a_02_4 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 8b 45 90 01 01 03 45 90 01 01 8b 4d 90 01 01 e8 90 00 } //01 00 
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GO_MTB_18{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 d2 3b 54 24 04 75 90 01 01 3b 04 24 5a 58 90 0a c8 00 01 02 a1 90 01 04 2d 90 01 02 00 00 03 05 90 01 04 a3 90 02 96 90 17 02 01 01 31 33 90 00 } //0a 00 
		$a_02_1 = {33 d2 3b 54 24 04 75 90 01 01 3b 04 24 5a 58 90 0a c8 00 a1 90 01 04 2d 90 01 02 00 00 03 05 90 01 04 03 90 02 96 90 17 02 01 01 31 33 90 00 } //05 00 
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //05 00 
		$a_02_3 = {99 03 04 24 13 54 24 04 83 c4 08 90 02 1e 8b d0 8b 90 02 06 e8 90 00 } //05 00 
		$a_02_4 = {99 03 04 24 13 54 24 04 83 c4 08 8b d0 90 02 05 03 90 02 05 8b 90 02 05 e8 90 00 } //01 00 
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
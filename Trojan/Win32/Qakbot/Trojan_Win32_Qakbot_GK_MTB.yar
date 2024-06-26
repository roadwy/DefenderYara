
rule Trojan_Win32_Qakbot_GK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 90 01 04 8b 5d b4 2b d8 6a 00 e8 90 01 04 03 d8 6a 00 e8 90 01 04 03 d8 43 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GK_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 57 c7 04 e4 90 02 04 59 89 7d 90 01 01 33 7d 90 01 01 0b bb 90 02 04 83 e0 00 31 f8 8b 7d 90 01 01 68 90 02 04 8f 83 90 02 04 21 8b 90 02 04 89 4d 90 01 01 8b 8b 90 02 04 01 c1 51 8b 4d 90 01 01 58 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GK_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 10 89 15 90 01 04 a1 90 01 04 8b 15 90 01 04 89 02 a1 90 01 04 83 c0 04 a3 90 01 04 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 09 0d 00 8b 15 90 01 04 2b d0 a1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GK_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c1 4f 05 90 01 04 0f af f7 8a 00 88 81 90 01 04 41 69 f6 90 00 } //0a 00 
		$a_02_1 = {0f b7 c2 03 c0 2b f8 8b 03 2b 7c 24 90 01 01 05 90 01 04 2b f9 89 03 a3 90 01 04 83 c7 f0 8b c7 2b 44 24 90 01 01 2b c2 83 6c 24 90 01 01 01 0f b7 d8 a1 90 01 04 89 5c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GK_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //0a 00 
		$a_02_1 = {03 d8 01 1d 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 eb 90 0a 78 00 a1 90 01 04 3b 05 90 01 04 73 90 01 01 8b 15 90 01 04 03 15 90 01 04 a1 90 01 04 03 05 90 01 04 8b 0d 90 01 04 e8 90 00 } //01 00 
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GK_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //0a 00 
		$a_02_1 = {73 45 8b 15 90 01 04 03 15 90 01 04 a1 90 01 04 03 05 90 01 04 8b 0d 90 01 04 e8 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 eb ae 90 0a 5a 00 a1 90 01 04 3b 05 90 00 } //01 00 
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GK_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 06 00 00 14 00 "
		
	strings :
		$a_02_0 = {03 d8 01 1d 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 eb 90 0a 96 00 a1 90 01 04 3b 05 90 01 04 73 90 01 01 8b 15 90 01 04 03 15 90 01 04 a1 90 01 04 03 05 90 01 04 8b 0d 90 01 04 e8 90 00 } //05 00 
		$a_00_1 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3 } //05 00 
		$a_00_2 = {f3 a5 89 c1 83 e1 03 f3 a4 5f 5e c3 } //05 00 
		$a_00_3 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
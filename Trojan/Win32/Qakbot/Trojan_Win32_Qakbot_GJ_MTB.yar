
rule Trojan_Win32_Qakbot_GJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 12 8b 0d 90 01 04 81 c1 90 01 04 03 0d 90 01 04 33 d1 03 c2 8b 15 90 01 04 89 02 83 05 90 01 05 83 05 90 01 05 a1 90 01 04 3b 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 } //01 00 
		$a_01_1 = {2b d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {83 e6 00 31 fe 8b 7d fc 55 33 2c e4 0b ab 90 02 04 83 e1 00 31 e9 5d fc f3 a4 56 c7 04 e4 ff ff 0f 00 59 ff b3 90 02 04 8f 45 fc ff 75 fc 58 53 81 04 e4 90 02 04 29 1c e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 ec fc f3 a4 90 02 1e 29 c9 09 c1 89 8b 90 02 04 59 52 c7 04 90 02 06 59 55 83 e5 00 0b ab 90 02 04 83 e0 00 09 e8 5d 68 90 02 04 8f 83 90 02 04 21 8b 90 02 04 89 4d 90 02 02 8b 8b 90 02 04 01 c1 51 8b 4d 90 02 02 58 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 3b 05 90 02 04 90 18 a1 90 02 04 80 c3 90 01 01 02 db 81 c6 90 02 04 2a da 89 35 90 02 04 02 1d 90 02 04 89 b4 28 90 02 04 83 c5 04 81 fd 4e 07 00 00 73 1d 8b 35 90 02 04 8b 0d 90 02 04 8b 3d 90 02 04 8b 15 90 02 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 45 d8 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 90 02 07 8b d8 8b 45 90 01 01 83 c0 90 01 01 03 d8 90 02 50 2b d8 90 02 04 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //05 00 
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //01 00 
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 cc 03 45 ac 2d f2 05 00 00 03 45 a0 03 d8 6a 00 e8 90 01 04 2b d8 8b 45 d8 31 18 90 00 } //05 00 
		$a_02_1 = {33 d2 3b 54 24 04 75 90 01 01 3b 04 24 90 0a 14 00 99 52 50 90 00 } //05 00 
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2d f2 05 00 00 03 05 90 01 04 8b 15 90 01 04 31 02 90 0a 2d 00 a1 90 01 04 8b 15 90 01 04 01 02 a1 90 01 04 03 05 90 00 } //0a 00 
		$a_02_1 = {2b d8 01 1d 90 01 04 83 05 90 01 04 04 a1 90 01 04 99 90 02 02 a1 90 01 04 33 d2 3b 54 24 90 00 } //05 00 
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 14 00 "
		
	strings :
		$a_02_0 = {8b 00 03 05 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 89 18 6a 00 e8 90 01 04 8b d8 a1 90 01 04 03 05 90 01 04 83 e8 5a 03 05 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 31 18 90 00 } //05 00 
		$a_00_1 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3 } //05 00 
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GJ_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b d8 8b 45 90 01 01 89 18 90 02 07 8b d8 8b 45 90 01 01 03 45 90 01 01 2d f2 05 00 00 03 45 90 01 01 03 d8 90 02 07 2b d8 8b 45 90 01 01 31 90 00 } //0a 00 
		$a_02_1 = {8b 00 03 05 90 01 04 03 d8 e8 90 01 04 2b d8 a1 90 01 04 89 18 e8 90 01 04 8b d8 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 03 d8 e8 90 01 04 2b d8 a1 90 01 04 31 18 e8 90 01 04 8b d8 83 c3 04 90 00 } //05 00 
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
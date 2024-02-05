
rule Trojan_Win32_Qakbot_GH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {83 e6 00 09 d6 8b 55 90 01 01 89 75 90 01 01 2b 75 90 01 01 0b b3 90 01 04 83 e1 00 31 f1 8b 75 90 01 01 fc f3 a4 90 0a 2d 00 89 55 90 02 04 33 93 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GH_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 90 01 04 8b 5d b4 2b d8 6a 00 e8 90 01 04 2b d8 6a 00 e8 90 01 04 2b d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GH_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {81 c1 3c 73 0d 01 89 0d 90 02 04 89 54 24 90 02 01 89 15 90 02 04 89 0b 83 c3 04 0f b6 c8 66 83 c1 90 02 01 89 5c 24 90 02 01 66 03 4c 24 90 02 01 83 6c 24 90 02 01 01 66 8b f9 89 7c 24 90 02 01 66 89 3d 90 02 04 0f b7 d9 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GH_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {89 1c e4 29 db 09 c3 89 df 5b 89 55 f8 83 e2 00 31 fa 83 a3 90 01 04 00 31 93 90 01 04 8b 55 f8 83 fb 00 90 00 } //0a 00 
		$a_02_1 = {89 55 f8 83 e2 00 33 93 90 01 04 83 e6 00 09 d6 8b 55 f8 6a 00 89 3c e4 31 ff 0b bb 90 01 04 89 f9 5f fc f3 a4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GH_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 50 c7 04 e4 ff ff 0f 00 59 89 55 90 01 01 2b 55 90 01 01 33 93 90 02 04 83 e0 00 31 d0 8b 55 90 01 01 53 c7 04 e4 90 02 04 8f 83 90 02 04 21 8b 90 02 04 89 7d 90 01 01 89 c7 03 bb 90 02 04 57 8b 7d 90 01 01 8f 83 90 02 04 ff a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GH_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {56 83 e6 00 09 c6 83 e7 00 31 f7 5e 52 33 14 90 01 01 31 fa 83 a3 90 01 04 00 31 93 90 01 04 5a 83 fb 00 90 01 02 89 7d f8 89 df 03 bb 90 01 04 57 90 00 } //0a 00 
		$a_02_1 = {5e 89 55 f8 83 e2 00 0b 93 90 01 04 83 e1 00 31 d1 8b 55 f8 fc f3 a4 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GH_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 d8 90 02 08 2b d8 8b 45 90 01 01 31 90 02 ff 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //01 00 
		$a_00_1 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3 } //01 00 
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GH_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 57 a1 90 02 04 a3 90 02 04 8b 0d 90 02 04 8b 11 89 15 90 02 04 8b 15 90 02 04 a1 90 02 04 50 8f 05 90 02 04 8b 3d 90 02 04 89 15 90 02 04 8b c7 eb 00 eb 00 eb 00 eb 00 eb 00 eb 00 bb 90 00 } //01 00 
		$a_02_1 = {8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b c8 8b d1 89 15 90 02 04 a1 90 02 04 8b 0d 90 02 04 89 08 5f 5b 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GH_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 2b ca 03 c1 8a c8 2a ca 80 e9 90 01 01 88 0d 90 01 04 83 ee 90 01 01 83 fe 90 01 03 5f 89 35 90 01 04 8b c3 5e 5b 59 c3 90 00 } //0a 00 
		$a_02_1 = {55 8b ec 6a ff 68 90 01 04 64 a1 00 00 00 00 50 81 ec 90 01 04 53 56 57 a1 90 01 04 33 c5 50 8d 45 f4 64 a3 00 00 00 00 89 65 f0 68 90 01 04 6a 00 68 90 01 04 ff 15 90 01 04 68 90 01 04 68 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GH_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b7 55 f4 2b ca 89 0d 90 01 04 a1 90 01 04 05 70 83 07 01 a3 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 8b 15 90 01 04 89 91 90 01 04 a1 90 01 04 6b c0 90 01 01 03 05 90 01 04 66 89 45 90 01 01 e9 90 00 } //0a 00 
		$a_02_1 = {0f b6 c8 81 c2 80 f6 ff ff 03 ca 8b 54 24 90 01 01 89 0d 90 01 04 90 18 8b 3d 90 01 04 8d 8e 90 01 04 89 4d 00 83 c5 04 89 0d 90 01 04 b1 a7 2a ca 2a 0d 90 01 04 02 c1 83 6c 24 90 01 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GH_MTB_11{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d 90 01 02 00 00 8b 4d 08 89 01 5e 8b e5 5d c3 90 00 } //0a 00 
		$a_02_1 = {03 45 fc 88 1c 30 8b 55 f8 83 c2 01 89 55 f8 eb 90 01 01 a1 90 01 04 a3 90 01 04 5e 5b 8b e5 5d c3 90 00 } //0a 00 
		$a_02_2 = {89 11 5d c3 90 0a 28 00 31 0d 90 01 04 a1 90 01 04 a3 90 01 04 8b 0d 90 01 04 8b 15 90 00 } //01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
		$a_00_5 = {5d 04 00 00 00 4e 04 80 5c 2a 00 } //00 01 
	condition:
		any of ($a_*)
 
}
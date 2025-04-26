
rule Trojan_Win32_Qakbot_GH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 e6 00 09 d6 8b 55 ?? 89 75 ?? 2b 75 ?? 0b b3 ?? ?? ?? ?? 83 e1 00 31 f1 8b 75 ?? fc f3 a4 90 0a 2d 00 89 55 [0-04] 33 93 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GH_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 ?? ?? ?? ?? 8b 5d b4 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GH_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c1 3c 73 0d 01 89 0d [0-04] 89 54 24 [0-01] 89 15 [0-04] 89 0b 83 c3 04 0f b6 c8 66 83 c1 [0-01] 89 5c 24 [0-01] 66 03 4c 24 [0-01] 83 6c 24 [0-01] 01 66 8b f9 89 7c 24 [0-01] 66 89 3d [0-04] 0f b7 d9 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GH_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 1c e4 29 db 09 c3 89 df 5b 89 55 f8 83 e2 00 31 fa 83 a3 ?? ?? ?? ?? 00 31 93 ?? ?? ?? ?? 8b 55 f8 83 fb 00 } //10
		$a_02_1 = {89 55 f8 83 e2 00 33 93 ?? ?? ?? ?? 83 e6 00 09 d6 8b 55 f8 6a 00 89 3c e4 31 ff 0b bb ?? ?? ?? ?? 89 f9 5f fc f3 a4 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Qakbot_GH_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 50 c7 04 e4 ff ff 0f 00 59 89 55 ?? 2b 55 ?? 33 93 [0-04] 83 e0 00 31 d0 8b 55 ?? 53 c7 04 e4 [0-04] 8f 83 [0-04] 21 8b [0-04] 89 7d ?? 89 c7 03 bb [0-04] 57 8b 7d ?? 8f 83 [0-04] ff a3 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GH_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {56 83 e6 00 09 c6 83 e7 00 31 f7 5e 52 33 14 ?? 31 fa 83 a3 ?? ?? ?? ?? 00 31 93 ?? ?? ?? ?? 5a 83 fb 00 ?? ?? 89 7d f8 89 df 03 bb ?? ?? ?? ?? 57 } //10
		$a_02_1 = {5e 89 55 f8 83 e2 00 0b 93 ?? ?? ?? ?? 83 e1 00 31 d1 8b 55 f8 fc f3 a4 50 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Qakbot_GH_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 [0-08] 2b d8 8b 45 ?? 31 [0-ff] 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82 } //10
		$a_00_1 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3 } //1
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=11
 
}
rule Trojan_Win32_Qakbot_GH_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 57 a1 [0-04] a3 [0-04] 8b 0d [0-04] 8b 11 89 15 [0-04] 8b 15 [0-04] a1 [0-04] 50 8f 05 [0-04] 8b 3d [0-04] 89 15 [0-04] 8b c7 eb 00 eb 00 eb 00 eb 00 eb 00 eb 00 bb } //1
		$a_02_1 = {8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b c8 8b d1 89 15 [0-04] a1 [0-04] 8b 0d [0-04] 89 08 5f 5b 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GH_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 2b ca 03 c1 8a c8 2a ca 80 e9 ?? 88 0d ?? ?? ?? ?? 83 ee ?? 83 fe ?? ?? ?? 5f 89 35 ?? ?? ?? ?? 8b c3 5e 5b 59 c3 } //10
		$a_02_1 = {55 8b ec 6a ff 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 81 ec ?? ?? ?? ?? 53 56 57 a1 ?? ?? ?? ?? 33 c5 50 8d 45 f4 64 a3 00 00 00 00 89 65 f0 68 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Qakbot_GH_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b7 55 f4 2b ca 89 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 70 83 07 01 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 15 ?? ?? ?? ?? 89 91 ?? ?? ?? ?? a1 ?? ?? ?? ?? 6b c0 ?? 03 05 ?? ?? ?? ?? 66 89 45 ?? e9 } //10
		$a_02_1 = {0f b6 c8 81 c2 80 f6 ff ff 03 ca 8b 54 24 ?? 89 0d ?? ?? ?? ?? 90 18 8b 3d ?? ?? ?? ?? 8d 8e ?? ?? ?? ?? 89 4d 00 83 c5 04 89 0d ?? ?? ?? ?? b1 a7 2a ca 2a 0d ?? ?? ?? ?? 02 c1 83 6c 24 ?? 01 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GH_MTB_11{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d ?? ?? 00 00 8b 4d 08 89 01 5e 8b e5 5d c3 } //10
		$a_02_1 = {03 45 fc 88 1c 30 8b 55 f8 83 c2 01 89 55 f8 eb ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 5e 5b 8b e5 5d c3 } //10
		$a_02_2 = {89 11 5d c3 90 0a 28 00 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 } //10
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}
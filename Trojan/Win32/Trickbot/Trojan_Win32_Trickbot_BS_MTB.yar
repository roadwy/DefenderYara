
rule Trojan_Win32_Trickbot_BS_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 16 8d 84 3d ?? ?? ?? ?? 0f b6 d3 88 18 0f b6 06 03 c2 8b f1 99 f7 fe 8b 45 14 8a 94 15 ?? ?? ?? ?? 30 10 40 ff 4d 0c 89 45 14 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_BS_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff d6 8b 45 fc 0f b6 4d 17 0f b6 84 05 ?? ?? ?? ?? 03 c1 8b cb 99 f7 f9 8b 45 08 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d f8 89 45 08 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_BS_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 8b 51 ?? 8b 79 ?? 2b d7 03 d6 66 0f b6 0a 8b f9 2b c8 66 85 c9 7d ?? 81 c1 00 01 00 00 8b 85 ?? ?? ?? ?? 88 0a 03 f0 eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_BS_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 fb 0f b6 04 37 89 55 ?? 03 d6 8a 1a 88 1c 37 47 3b f9 88 02 7c } //1
		$a_00_1 = {03 d7 8a 1a 88 19 88 02 0f b6 01 0f b6 0a 03 c1 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_BS_MTB_5{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 f9 8b 4c 24 ?? 33 c0 8a 04 0a 8b 54 24 ?? 0f be 0c 3a 51 50 e8 ?? ?? ?? ?? 88 07 8b 44 24 ?? 83 c4 10 47 48 89 44 24 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_BS_MTB_6{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {3b d8 72 10 ff 15 ?? ?? ?? ?? eb 08 ff 15 ?? ?? ?? ?? 8b d8 8b ?? ff 15 ?? ?? ?? ?? 8b [0-14] b8 01 00 00 00 03 c1 [0-06] 89 85 54 ff ff ff 8b ?? e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_BS_MTB_7{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b da 3b d8 72 ?? ff 15 ?? ?? ?? ?? eb ?? ff 15 ?? ?? ?? ?? 8b d8 8b ce ff 15 ?? ?? ?? ?? 8b 0f 8b b5 ?? ?? ?? ?? 8b 51 ?? 8b 8d ?? ?? ?? ?? 88 04 1a b8 01 00 00 00 03 c1 0f 80 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_BS_MTB_8{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b fb 2b fa 3b f9 72 ?? ff 15 ?? ?? ?? ?? eb ?? ff 15 ?? ?? ?? ?? 8b f8 dd 45 ?? ff 15 ?? ?? ?? ?? 8b 16 8b 4a ?? 88 04 39 b8 01 00 00 00 03 c3 0f 80 } //1
		$a_02_1 = {50 68 00 00 f0 3f 6a 00 68 ?? ?? ?? ?? 51 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_BS_MTB_9{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b de 2b da 3b d8 72 ?? ff 15 ?? ?? ?? ?? 8b c3 eb ?? ff 15 ?? ?? ?? ?? 8b 0f 8b 51 ?? 66 0f b6 1c 02 2b 5d ?? 66 85 db 7d ?? 81 c3 00 01 00 00 85 c9 74 ?? 66 83 39 01 75 1c 8b 51 ?? 8b 41 ?? 2b f2 3b f0 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_BS_MTB_10{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {25 ff 00 00 00 89 84 9d ?? ?? ?? ?? 8b 84 8d ?? ?? ?? ?? 03 84 9d ?? ?? ?? ?? be e1 01 00 00 99 f7 fe 8a 84 95 ?? ?? ?? ?? 8b 55 ?? 8b 75 ?? 30 04 32 ff 45 ?? 8b 45 ?? 3b 45 ?? 72 } //1
		$a_00_1 = {5f 5f 5f 43 50 50 64 65 62 75 67 48 6f 6f 6b } //1 ___CPPdebugHook
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
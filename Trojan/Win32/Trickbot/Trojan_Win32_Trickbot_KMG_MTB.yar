
rule Trojan_Win32_Trickbot_KMG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c6 99 f7 f9 0f b6 04 2b 8b f2 8a 14 2e 88 14 2b 88 04 2e 0f b6 0c 2e 0f b6 04 2b 03 c1 99 b9 ?? ?? ?? ?? f7 f9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c0 ec 02 80 e4 0f 0a e1 8b 4c 24 ?? 88 64 24 ?? 88 44 24 ?? 88 47 ?? 0f b7 44 24 ?? 66 89 07 83 44 24 08 03 8b 44 24 ?? 40 e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b df 7e ?? 8b 4c 24 ?? 8d 4c 19 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c3 7c ?? 8d 43 01 c6 83 ?? ?? ?? ?? 00 83 f8 3e 7d } //1
		$a_00_1 = {38 42 68 66 31 41 51 41 62 38 38 4d 40 72 77 } //1 8Bhf1AQAb88M@rw
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b df 7e ?? 8b 4c 24 ?? 8d 4c 19 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c3 7c ?? 8d 43 01 c6 83 ?? ?? ?? ?? 00 83 f8 3e 7d } //1
		$a_00_1 = {6f 64 71 40 29 64 35 56 30 66 25 52 31 26 50 } //1 odq@)d5V0f%R1&P
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_5{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b df 7e ?? 8b 4c 24 ?? 8d 4c 19 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c3 7c ?? 8d 43 01 c6 83 ?? ?? ?? ?? 00 83 f8 3e 7d } //1
		$a_00_1 = {7a 31 3e 67 3e 61 55 66 51 2b 37 68 63 39 3e } //1 z1>g>aUfQ+7hc9>
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_6{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 c7 45 8c 00 01 00 00 c7 45 ?? 02 00 00 00 ff 15 ?? ?? ?? ?? 8b d0 8d 4d ?? ff 15 ?? ?? ?? ?? 8d 4d ?? 51 ff 15 ?? ?? ?? ?? 8b 56 ?? 8b 4e ?? 2b d1 88 04 1a 8b 85 ?? ?? ?? ?? 03 d8 e9 ?? ?? ?? ?? 68 ?? ?? ?? ?? eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_7{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 f6 3b fb 7e ?? 8d 87 ?? ?? ?? ?? 8a 08 88 8e ?? ?? ?? ?? 46 48 3b f7 7c ?? 8d 47 ?? 83 f8 3e 88 9f ?? ?? ?? ?? 7d } //1
		$a_00_1 = {45 53 45 54 20 68 79 75 6e 79 61 } //1 ESET hyunya
		$a_00_2 = {62 29 58 21 51 4d 42 4a 49 5f 78 54 41 76 4a } //1 b)X!QMBJI_xTAvJ
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_8{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b fb 7e ?? 8b 54 24 ?? 8d 4c 3a ?? 8b ff 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c7 7c ?? 8d 47 01 83 f8 3e 88 9f ?? ?? ?? ?? 7d } //1
		$a_00_1 = {23 6f 71 34 34 64 32 3f 45 31 41 56 31 30 6b } //1 #oq44d2?E1AV10k
		$a_00_2 = {53 74 75 70 20 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 68 61 68 61 68 } //1 Stup windows defender hahah
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
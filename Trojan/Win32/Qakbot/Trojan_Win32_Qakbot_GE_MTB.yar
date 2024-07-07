
rule Trojan_Win32_Qakbot_GE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 57 c7 04 e4 ff ff 0f 00 59 8b 83 90 01 04 50 c7 04 e4 90 01 04 8f 83 90 01 04 21 8b 90 01 04 01 83 90 01 04 ff a3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GE_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 31 0d 90 02 04 c7 05 90 02 04 00 00 00 00 8b 1d 90 02 04 01 1d 90 02 04 a1 90 02 04 8b 0d 90 02 04 89 08 5b 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GE_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c0 66 03 c6 66 89 44 24 90 01 01 0f b7 f0 8b 01 05 e8 66 03 01 89 01 8a cb a3 90 01 04 80 e9 90 01 01 66 8b 44 24 90 01 01 02 c8 83 6c 24 90 01 01 01 88 4c 24 90 01 01 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GE_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2a de 0f b6 c6 80 eb 90 02 01 2b 44 24 90 02 01 2d 4b c9 00 00 a3 90 02 04 8b 84 31 90 02 04 05 90 01 02 06 01 88 1d 90 02 04 a3 90 02 04 89 84 31 90 02 04 83 c6 04 81 fe 7a 22 00 00 73 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GE_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 52 c7 04 e4 ff ff 0f 00 59 83 bb 90 01 04 00 90 01 02 51 51 56 8b b3 90 01 04 89 74 e4 04 5e ff 93 90 01 04 89 83 90 01 04 59 8b 83 90 01 04 52 c7 04 e4 90 01 04 83 bb 90 01 04 00 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GE_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c9 83 c1 bb 8d 04 41 0f b7 c0 89 44 24 90 01 01 8b 02 05 a8 f8 02 01 89 02 83 c2 04 a3 90 01 04 8b 44 24 90 01 01 83 c0 90 01 01 89 54 24 90 01 01 03 c1 83 6c 24 90 01 01 01 0f b6 c0 8d 04 c3 0f b7 f0 75 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GE_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 e6 00 09 ce 59 89 7d 90 01 01 83 e7 00 33 bb 90 01 04 83 e1 00 31 f9 8b 7d 90 01 01 fc f3 a4 55 c7 04 e4 ff ff 0f 00 59 56 2b 34 e4 90 00 } //10
		$a_02_1 = {6a 00 89 14 e4 ff b3 90 01 04 5a 01 c2 89 93 90 01 04 5a ff a3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Qakbot_GE_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 90 01 04 03 d8 a1 90 01 04 33 18 89 1d 90 01 04 a1 90 01 04 03 05 90 01 04 2b 05 90 01 04 8b 15 90 01 04 89 02 90 00 } //1
		$a_03_1 = {03 d8 89 1d 90 01 04 a1 90 01 04 2b 05 90 01 04 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GE_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 00 03 45 90 01 01 03 d8 90 02 1e 2b d8 a1 90 02 04 89 18 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 15 90 02 04 31 02 a1 90 02 04 83 c0 04 a3 90 02 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 00 } //10
		$a_00_1 = {f3 ab 89 d1 83 e1 03 f3 aa 5f c3 } //1
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=11
 
}
rule Trojan_Win32_Qakbot_GE_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_02_0 = {03 45 fc 88 1c 30 8b 4d f8 83 c1 01 89 4d f8 eb 90 02 0f 8b e5 5d c3 90 00 } //10
		$a_80_1 = {52 65 67 4f 70 65 6e 4b 65 79 41 } //RegOpenKeyA  10
		$a_80_2 = {67 68 72 74 79 65 } //ghrtye  10
		$a_80_3 = {4b 4c 49 4f 59 32 34 30 4c 68 4b 37 76 73 6f 5a 43 54 4a 6f 55 57 34 56 4f 4c 59 62 4b 4c 78 65 6b 34 4e 70 53 7a 53 54 6c 50 6a 7a 39 52 33 77 } //KLIOY240LhK7vsoZCTJoUW4VOLYbKLxek4NpSzSTlPjz9R3w  10
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=41
 
}
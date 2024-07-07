
rule Trojan_Win32_Qakbot_GD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {59 fc 51 8d 83 90 01 04 50 8d 83 90 01 04 50 ff 93 90 01 04 89 83 90 01 04 59 f3 a4 8d 83 90 01 04 50 ff 93 90 01 04 89 83 90 01 04 57 c7 04 e4 ff ff 0f 00 59 51 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GD_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b 15 90 02 04 33 d1 c7 05 90 02 04 00 00 00 00 8b da 01 1d 90 02 04 a1 90 02 04 8b 0d 90 02 04 89 08 5b 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GD_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 d1 8b 55 fc fc f3 a4 52 c7 04 e4 ff ff 0f 00 59 89 75 fc 33 75 fc 0b b3 90 01 04 83 e0 00 09 f0 8b 75 fc 68 90 01 04 8f 83 90 01 04 21 8b 90 01 04 01 83 90 01 04 ff a3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GD_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 17 80 c1 21 0f b6 c1 3b 05 90 01 04 8b 44 24 90 01 01 90 18 81 c2 b0 70 08 01 8a cd 02 0d 90 01 04 89 17 83 c7 04 ff 4c 24 90 01 01 89 15 90 01 04 8b 54 24 90 01 01 75 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GD_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02 } //1
		$a_01_1 = {03 d8 89 5d d8 8b 45 9c 2b 45 9c 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 0f 82 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GD_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe c6 0f b6 f6 8a 14 3e 02 c2 0f b6 c8 88 45 0b 8a 04 39 88 04 3e 88 14 39 8a 04 3e 8b 4d f8 02 c2 0f b6 c0 8a 04 38 30 04 0b 43 8a 45 0b 3b 5d fc 7c } //4
		$a_01_1 = {32 04 37 88 44 3b 04 47 3b 3b } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}
rule Trojan_Win32_Qakbot_GD_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 83 e1 00 31 c1 83 a3 90 01 04 00 09 8b 90 01 04 59 81 e1 00 00 00 00 8f 45 90 01 01 0b 4d 90 01 01 f3 a4 56 c7 04 e4 ff ff 0f 00 59 83 bb 90 01 04 00 75 90 01 01 c7 45 90 01 01 00 00 00 00 ff 75 90 01 01 31 0c e4 50 8b 83 90 01 04 87 04 e4 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GD_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 ce 8a f2 2b ce 2a f3 8b 74 24 90 02 01 81 c1 90 02 04 89 4c 24 90 02 01 80 c6 90 02 01 8a 54 24 90 02 01 89 0d 90 02 04 80 c2 90 02 01 8b 0e 02 d3 81 c1 90 02 04 88 35 90 02 04 89 0e 83 c6 04 83 6c 24 90 02 01 01 89 74 24 90 02 01 8b 74 24 90 02 01 89 0d 90 02 04 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GD_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_02_0 = {c7 85 6c ff ff ff 90 01 04 c7 85 6c ff ff ff 90 01 04 c7 85 6c ff ff ff 90 01 04 c7 85 6c ff ff ff 90 01 04 c7 85 6c ff ff ff 90 01 04 c7 85 6c ff ff ff 90 01 04 c7 85 6c ff ff ff 90 01 04 c7 85 6c ff ff ff 90 00 } //10
		$a_02_1 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 90 02 14 8b 55 08 8b 90 01 01 2b 90 01 01 8b 55 08 89 90 01 01 5e 8b e5 5d c3 90 00 } //10
		$a_00_2 = {68 00 5a 00 54 00 44 00 4b 00 54 00 64 00 4a 00 4e 00 53 00 } //10 hZTDKTdJNS
		$a_80_3 = {4c 6f 61 64 43 75 72 73 6f 72 46 72 6f 6d 46 69 6c 65 57 } //LoadCursorFromFileW  10
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=41
 
}
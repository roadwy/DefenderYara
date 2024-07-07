
rule Trojan_Win32_Qakbot_GQ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 0f 82 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GQ_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {49 8d 41 01 03 c7 a3 90 01 04 8a 04 16 88 02 42 8b 1d 90 01 04 8b c3 2b c7 66 83 3d 90 01 04 00 8d 78 90 01 01 74 90 01 01 b0 b9 2a c3 a2 90 01 04 85 c9 75 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GQ_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {59 fc 83 bb 90 01 04 00 90 18 f3 a4 83 bb 90 01 04 00 75 90 01 01 ff 93 90 01 04 89 90 02 02 29 f6 09 c6 89 b3 90 01 04 8b 75 90 01 01 57 c7 04 e4 ff ff 0f 00 59 83 bb 90 01 04 00 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GQ_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 90 02 02 a1 90 02 04 a3 90 02 04 8b 90 02 05 8b 90 02 02 89 90 02 05 8b 90 02 05 a1 90 02 04 a3 90 02 04 b8 90 02 04 b8 90 02 04 a1 90 02 04 8b d8 33 d9 c7 05 90 02 04 00 00 00 00 01 90 02 05 a1 90 02 04 8b 0d 90 02 04 89 08 5b 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GQ_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {b8 73 16 00 00 ff 35 90 01 04 b8 73 16 00 00 ff 35 90 01 04 b8 73 16 00 00 ff 35 90 01 04 ff 35 90 01 04 b8 01 00 00 00 50 ff 25 90 00 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GQ_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 0a c8 00 03 05 90 01 04 48 a3 90 01 04 a1 90 01 04 8b 15 90 01 04 01 02 90 02 05 8b d8 a1 90 01 04 03 05 90 01 04 03 d8 90 02 05 2b d8 a1 90 01 04 90 17 02 01 01 31 33 90 00 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GQ_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {83 c4 04 8b 0d 90 02 08 89 0d 90 02 08 8b 0d 90 02 08 81 e9 90 02 08 51 c7 05 90 02 08 ff 05 90 02 08 ff 35 90 02 08 ff 35 90 02 08 ff 35 90 02 08 a1 90 02 08 ff d0 90 00 } //1
		$a_02_1 = {55 8b ec 53 57 a1 90 02 04 a3 90 02 04 8b 0d 90 02 04 8b 11 89 15 90 02 0a a1 90 02 04 50 8f 05 90 02 04 8b 3d 90 02 0f 8b c7 eb 00 eb 00 eb 00 eb 00 eb 00 eb 00 bb 90 00 } //1
		$a_02_2 = {8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b c8 8b d1 89 15 90 02 04 a1 90 02 04 8b 0d 90 02 04 89 08 90 02 02 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}
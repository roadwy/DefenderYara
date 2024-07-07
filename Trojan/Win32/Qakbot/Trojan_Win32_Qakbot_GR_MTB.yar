
rule Trojan_Win32_Qakbot_GR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 2b 15 90 01 04 1b 05 90 02 32 8b 0d 90 01 04 83 c1 90 01 01 8b 15 90 01 04 83 d2 00 33 c0 03 4d 90 01 01 13 d0 66 89 4d fc 8b 7d f0 05 90 01 04 ff e7 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GR_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 57 c7 04 e4 ff ff 90 02 02 59 56 83 e6 00 0b b3 90 02 04 83 e0 00 09 f0 5e 68 90 02 04 8f 83 90 02 04 21 8b 90 02 04 6a 00 01 90 02 02 50 5a 03 93 90 02 04 89 d0 5a ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GR_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 68 00 10 00 00 52 50 ff 93 90 02 06 89 bb 90 02 04 8b b3 90 02 04 8b 8b 90 02 04 fc f3 a4 b9 ff ff 0f 00 8b 83 90 02 04 68 90 02 04 8f 83 90 02 04 21 8b 90 02 04 03 83 90 02 04 ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GR_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 eb 00 a1 90 02 04 a3 90 02 04 8b 90 02 05 8b 90 01 01 89 90 02 05 8b 90 02 05 a1 90 02 04 a3 90 02 1e 33 d9 c7 05 90 02 04 00 00 00 00 01 90 01 01 90 02 04 a1 90 02 04 8b 0d 90 02 04 89 08 5b 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GR_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 04 a3 90 01 04 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 09 25 00 03 05 90 01 04 8b 15 90 01 04 33 02 a3 90 01 04 a1 90 01 04 8b 15 90 01 04 89 02 a1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GR_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 ea 01 89 55 90 01 01 85 c9 74 90 01 01 8b 45 90 01 01 83 e8 90 01 01 2b 45 90 01 01 a3 90 01 04 8b 4d 90 01 01 8b 55 90 01 01 8a 02 88 01 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 8b 55 90 01 01 83 c2 01 89 55 90 01 01 a1 90 01 04 83 e8 90 01 01 2b 05 90 01 04 89 45 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GR_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_02_0 = {03 d8 8b 45 90 01 01 90 17 02 01 01 31 33 90 01 01 89 5d 90 01 01 8b 45 90 01 01 8b 55 90 01 01 89 10 33 c0 89 45 90 01 01 8b 45 90 01 01 83 c0 90 01 01 03 45 90 01 01 89 45 90 02 08 8b 5d 90 01 01 83 c3 04 03 5d 90 01 01 2b d8 90 00 } //10
		$a_02_1 = {8b 00 8b 55 90 01 01 03 55 90 01 01 03 55 90 01 01 4a 90 17 02 01 01 31 33 90 01 01 89 45 90 01 01 8b 45 90 01 01 8b 55 90 01 01 89 10 33 c0 89 45 90 02 08 8b 5d 90 01 01 83 c3 04 03 5d 90 01 01 2b d8 90 00 } //10
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=16
 
}
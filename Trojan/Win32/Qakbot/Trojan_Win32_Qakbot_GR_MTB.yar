
rule Trojan_Win32_Qakbot_GR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 2b 15 ?? ?? ?? ?? 1b 05 [0-32] 8b 0d ?? ?? ?? ?? 83 c1 ?? 8b 15 ?? ?? ?? ?? 83 d2 00 33 c0 03 4d ?? 13 d0 66 89 4d fc 8b 7d f0 05 ?? ?? ?? ?? ff e7 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GR_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 57 c7 04 e4 ff ff [0-02] 59 56 83 e6 00 0b b3 [0-04] 83 e0 00 09 f0 5e 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 6a 00 01 [0-02] 50 5a 03 93 [0-04] 89 d0 5a ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GR_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 68 00 10 00 00 52 50 ff 93 [0-06] 89 bb [0-04] 8b b3 [0-04] 8b 8b [0-04] fc f3 a4 b9 ff ff 0f 00 8b 83 [0-04] 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 03 83 [0-04] ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GR_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 eb 00 a1 [0-04] a3 [0-04] 8b [0-05] 8b ?? 89 [0-05] 8b [0-05] a1 [0-04] a3 [0-1e] 33 d9 c7 05 [0-04] 00 00 00 00 01 ?? [0-04] a1 [0-04] 8b 0d [0-04] 89 08 5b 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GR_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 90 09 25 00 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 33 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GR_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 ea 01 89 55 ?? 85 c9 74 ?? 8b 45 ?? 83 e8 ?? 2b 45 ?? a3 ?? ?? ?? ?? 8b 4d ?? 8b 55 ?? 8a 02 88 01 8b 4d ?? 83 c1 01 89 4d ?? 8b 55 ?? 83 c2 01 89 55 ?? a1 ?? ?? ?? ?? 83 e8 ?? 2b 05 ?? ?? ?? ?? 89 45 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GR_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_02_0 = {03 d8 8b 45 ?? 90 17 02 01 01 31 33 ?? 89 5d ?? 8b 45 ?? 8b 55 ?? 89 10 33 c0 89 45 ?? 8b 45 ?? 83 c0 ?? 03 45 ?? 89 45 [0-08] 8b 5d ?? 83 c3 04 03 5d ?? 2b d8 } //10
		$a_02_1 = {8b 00 8b 55 ?? 03 55 ?? 03 55 ?? 4a 90 17 02 01 01 31 33 ?? 89 45 ?? 8b 45 ?? 8b 55 ?? 89 10 33 c0 89 45 [0-08] 8b 5d ?? 83 c3 04 03 5d ?? 2b d8 } //10
		$a_00_2 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=16
 
}
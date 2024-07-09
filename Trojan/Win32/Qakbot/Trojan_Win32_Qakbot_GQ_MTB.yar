
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
		$a_02_0 = {49 8d 41 01 03 c7 a3 ?? ?? ?? ?? 8a 04 16 88 02 42 8b 1d ?? ?? ?? ?? 8b c3 2b c7 66 83 3d ?? ?? ?? ?? 00 8d 78 ?? 74 ?? b0 b9 2a c3 a2 ?? ?? ?? ?? 85 c9 75 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GQ_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {59 fc 83 bb ?? ?? ?? ?? 00 90 18 f3 a4 83 bb ?? ?? ?? ?? 00 75 ?? ff 93 ?? ?? ?? ?? 89 [0-02] 29 f6 09 c6 89 b3 ?? ?? ?? ?? 8b 75 ?? 57 c7 04 e4 ff ff 0f 00 59 83 bb ?? ?? ?? ?? 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GQ_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 [0-02] a1 [0-04] a3 [0-04] 8b [0-05] 8b [0-02] 89 [0-05] 8b [0-05] a1 [0-04] a3 [0-04] b8 [0-04] b8 [0-04] a1 [0-04] 8b d8 33 d9 c7 05 [0-04] 00 00 00 00 01 [0-05] a1 [0-04] 8b 0d [0-04] 89 08 5b 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GQ_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {b8 73 16 00 00 ff 35 ?? ?? ?? ?? b8 73 16 00 00 ff 35 ?? ?? ?? ?? b8 73 16 00 00 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? b8 01 00 00 00 50 ff 25 } //10
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
		$a_02_0 = {83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 90 0a c8 00 03 05 ?? ?? ?? ?? 48 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 02 [0-05] 8b d8 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 d8 [0-05] 2b d8 a1 ?? ?? ?? ?? 90 17 02 01 01 31 33 } //10
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
		$a_02_0 = {83 c4 04 8b 0d [0-08] 89 0d [0-08] 8b 0d [0-08] 81 e9 [0-08] 51 c7 05 [0-08] ff 05 [0-08] ff 35 [0-08] ff 35 [0-08] ff 35 [0-08] a1 [0-08] ff d0 } //1
		$a_02_1 = {55 8b ec 53 57 a1 [0-04] a3 [0-04] 8b 0d [0-04] 8b 11 89 15 [0-0a] a1 [0-04] 50 8f 05 [0-04] 8b 3d [0-0f] 8b c7 eb 00 eb 00 eb 00 eb 00 eb 00 eb 00 bb } //1
		$a_02_2 = {8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b c8 8b d1 89 15 [0-04] a1 [0-04] 8b 0d [0-04] 89 08 [0-02] 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}
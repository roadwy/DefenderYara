
rule Trojan_Win32_Qbot_RM_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 49 0e 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 55 ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 49 0e 00 00 6a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Qbot_RM_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {54 66 74 76 67 79 62 47 74 66 76 67 79 62 } //TftvgybGtfvgyb  1
		$a_80_1 = {4b 6a 69 6e 68 75 44 64 72 66 74 } //KjinhuDdrft  1
		$a_80_2 = {49 68 75 6e 45 64 66 64 66 67 } //IhunEdfdfg  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Qbot_RM_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b a5 08 00 [0-0a] 64 00 00 00 } //1
		$a_03_1 = {89 18 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_RM_MTB_5{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 8a a5 08 00 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 [0-3c] 8b 45 ?? 3b 05 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RM_MTB_6{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? 8b 45 ?? 8b 55 ?? 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RM_MTB_7{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 ?? 03 d8 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 33 18 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 89 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RM_MTB_8{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 ?? 03 d8 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 33 18 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 89 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RM_MTB_9{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 [0-0a] 01 10 00 00 } //1
		$a_03_1 = {8a a5 08 00 [0-05] e0 21 09 00 } //1
		$a_03_2 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 e8 ?? ?? ?? ?? 8b d8 83 c3 04 } //10
		$a_03_3 = {31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8 } //10
		$a_03_4 = {31 18 83 45 [0-05] 04 83 [0-05] 04 8b [0-0a] 72 [0-0a] 00 10 00 00 8b [0-0a] 83 c0 04 } //10
		$a_03_5 = {89 02 83 45 ?? 04 8b [0-02] 83 c0 04 89 45 ?? 8b 45 ?? 3b 45 ?? 72 [0-05] c7 45 ?? 00 10 00 00 [0-0a] 83 c0 04 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*10+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10+(#a_03_5  & 1)*10) >=11
 
}
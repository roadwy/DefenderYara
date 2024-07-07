
rule Trojan_Win32_Qbot_RM_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 02 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 e8 90 01 04 8b d8 a1 90 01 04 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 49 0e 00 00 6a 00 e8 90 01 04 8b d8 a1 90 01 04 8b 00 8b 55 90 01 01 03 55 90 01 01 03 55 90 01 01 33 c2 03 d8 68 49 0e 00 00 6a 90 00 } //2
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
		$a_03_0 = {8b a5 08 00 90 02 0a 64 00 00 00 90 00 } //1
		$a_03_1 = {89 18 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_RM_MTB_5{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 8a a5 08 00 03 45 90 01 01 8b 15 90 01 04 31 02 83 45 90 01 01 04 83 05 90 01 04 04 68 90 01 04 e8 90 01 04 68 90 02 3c 8b 45 90 01 01 3b 05 90 01 04 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RM_MTB_6{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 01 01 8b 45 90 01 01 8b 55 90 01 01 01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RM_MTB_7{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 90 01 01 03 d8 68 90 01 04 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 33 18 68 90 01 04 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 89 18 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RM_MTB_8{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 90 01 01 03 d8 68 90 01 04 6a 90 01 01 e8 90 01 04 03 d8 8b 45 90 01 01 33 18 68 90 01 04 6a 90 01 01 e8 90 01 04 03 d8 8b 45 90 01 01 89 18 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RM_MTB_9{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 90 02 0a 01 10 00 00 90 00 } //1
		$a_03_1 = {8a a5 08 00 90 02 05 e0 21 09 00 90 00 } //1
		$a_03_2 = {01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 e8 90 01 04 8b d8 83 c3 04 90 00 } //10
		$a_03_3 = {31 18 6a 00 e8 90 01 04 8b d8 83 c3 04 6a 00 e8 90 01 04 2b d8 90 00 } //10
		$a_03_4 = {31 18 83 45 90 02 05 04 83 90 02 05 04 8b 90 02 0a 72 90 02 0a 00 10 00 00 8b 90 02 0a 83 c0 04 90 00 } //10
		$a_03_5 = {89 02 83 45 90 01 01 04 8b 90 02 02 83 c0 04 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 72 90 02 05 c7 45 90 01 01 00 10 00 00 90 02 0a 83 c0 04 90 00 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*10+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10+(#a_03_5  & 1)*10) >=11
 
}
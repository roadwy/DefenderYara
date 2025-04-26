
rule Trojan_Win32_Qbot_RT_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d a2 d1 00 00 03 } //1
		$a_03_1 = {31 02 6a 01 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 01 e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 18 83 45 ?? 04 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 82 ?? ?? ?? ?? c7 45 ?? 00 10 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 [0-0a] 01 10 00 00 } //1
		$a_03_1 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 31 18 e8 ?? ?? ?? ?? 8b d8 83 c3 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_RT_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 ?? 8b 00 03 45 ?? 03 d8 6a ?? e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 89 18 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a ?? e8 ?? ?? ?? ?? 8b d8 83 c3 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RT_MTB_5{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? 8b 45 ?? 8b 55 ?? 01 02 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 03 55 ?? 8b 4d ?? 33 11 03 c2 8b 55 ?? 89 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RT_MTB_6{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04 03 d8 e8 ?? ?? ?? ?? 2b d8 89 1d ?? ?? ?? ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Qbot_RT_MTB_7{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 0f } //1
		$a_03_1 = {03 d8 68 69 23 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 69 23 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 6a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_RT_MTB_8{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {41 76 4f 70 30 61 53 75 6c 65 } //AvOp0aSule  1
		$a_80_1 = {42 36 52 64 4c 79 68 55 77 6c } //B6RdLyhUwl  1
		$a_80_2 = {42 75 38 53 56 37 78 57 4d 44 53 } //Bu8SV7xWMDS  1
		$a_80_3 = {43 47 33 31 55 30 41 73 64 } //CG31U0Asd  1
		$a_80_4 = {44 51 4e 38 61 50 72 } //DQN8aPr  1
		$a_80_5 = {44 68 33 4f 57 55 53 7a 34 72 70 } //Dh3OWUSz4rp  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Qbot_RT_MTB_9{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 ?? 05 8a a5 08 00 03 45 ?? 03 d8 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 03 d8 68 } //1
		$a_02_1 = {8b 45 ec 31 18 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
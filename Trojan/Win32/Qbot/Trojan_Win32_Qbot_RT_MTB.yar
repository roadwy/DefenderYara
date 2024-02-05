
rule Trojan_Win32_Qbot_RT_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2d a2 d1 00 00 03 } //01 00 
		$a_03_1 = {31 02 6a 01 e8 90 01 04 8b d8 83 c3 04 6a 01 e8 90 01 04 2b d8 01 1d 90 01 04 83 05 90 01 04 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 18 83 45 90 01 01 04 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 01 04 c7 45 90 01 01 00 10 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 90 02 0a 01 10 00 00 90 00 } //01 00 
		$a_03_1 = {8b d8 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 d8 e8 90 01 04 2b d8 8b 45 90 01 01 31 18 e8 90 01 04 8b d8 83 c3 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RT_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 90 01 01 8b 00 03 45 90 01 01 03 d8 6a 90 01 01 e8 90 01 04 2b d8 8b 45 90 01 01 89 18 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 6a 90 01 01 e8 90 01 04 8b d8 83 c3 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RT_MTB_5{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 01 01 8b 45 90 01 01 8b 55 90 01 01 01 02 68 90 01 04 6a 00 e8 90 01 04 8b 55 90 01 01 03 55 90 01 01 03 55 90 01 01 8b 4d 90 01 01 33 11 03 c2 8b 55 90 01 01 89 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RT_MTB_6{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 d8 e8 90 01 04 2b d8 a1 90 01 04 31 18 e8 90 01 04 8b d8 a1 90 01 04 83 c0 04 03 d8 e8 90 01 04 2b d8 89 1d 90 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RT_MTB_7{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 0f 90 00 } //01 00 
		$a_03_1 = {03 d8 68 69 23 00 00 6a 00 e8 90 01 04 03 d8 68 69 23 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 6a 00 e8 90 01 04 6a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RT_MTB_8{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {41 76 4f 70 30 61 53 75 6c 65 } //AvOp0aSule  01 00 
		$a_80_1 = {42 36 52 64 4c 79 68 55 77 6c } //B6RdLyhUwl  01 00 
		$a_80_2 = {42 75 38 53 56 37 78 57 4d 44 53 } //Bu8SV7xWMDS  01 00 
		$a_80_3 = {43 47 33 31 55 30 41 73 64 } //CG31U0Asd  01 00 
		$a_80_4 = {44 51 4e 38 61 50 72 } //DQN8aPr  01 00 
		$a_80_5 = {44 68 33 4f 57 55 53 7a 34 72 70 } //Dh3OWUSz4rp  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RT_MTB_9{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 03 d8 68 90 01 04 6a 90 01 01 e8 90 01 04 03 d8 68 90 00 } //01 00 
		$a_02_1 = {8b 45 ec 31 18 6a 90 01 01 e8 90 01 04 6a 90 01 01 e8 90 01 04 6a 90 01 01 e8 90 01 04 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
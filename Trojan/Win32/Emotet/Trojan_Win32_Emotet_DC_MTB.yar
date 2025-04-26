
rule Trojan_Win32_Emotet_DC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 e0 2b f2 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 8b 45 e4 03 45 0c 8b 4d e8 88 0c 30 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Emotet_DC_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c2 89 d0 89 c2 c1 e2 04 01 c2 89 c8 29 d0 01 f8 0f b6 00 31 f0 88 03 83 45 e4 01 8b 45 e4 3b 45 dc 7c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Emotet_DC_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {61 73 73 2e 44 4c 4c } //1 ass.DLL
		$a_81_1 = {61 73 73 2e 61 73 73 } //1 ass.ass
		$a_81_2 = {61 73 64 7a 78 63 71 77 65 31 32 33 } //1 asdzxcqwe123
		$a_81_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_81_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_5 = {52 61 69 73 65 45 78 63 65 70 74 69 6f 6e } //1 RaiseException
		$a_81_6 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //1 Control_RunDLL
		$a_81_7 = {61 62 7a 69 75 6c 65 6f 78 73 62 6f 72 70 62 } //1 abziuleoxsborpb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule Trojan_Win32_Emotet_DC_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.DC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 0d 00 10 00 00 50 68 00 4e 02 00 57 6a ff } //5
		$a_01_1 = {83 c4 04 0d 00 10 00 00 50 68 00 4e 02 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
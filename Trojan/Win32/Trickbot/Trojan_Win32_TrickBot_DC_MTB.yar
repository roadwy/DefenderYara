
rule Trojan_Win32_TrickBot_DC_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8b c1 bf ?? ?? ?? ?? f7 f7 8b 7c 24 0c 8a 04 39 8a 54 14 ?? 32 c2 88 04 39 41 81 f9 e0 07 00 00 75 } //1
		$a_00_1 = {33 d2 5b 8d 0c 07 8b c7 f7 f3 8b 44 24 10 8a 04 02 30 01 47 3b 7c 24 18 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBot_DC_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 72 79 70 74 65 72 2e 64 6c 6c } //1 Crypter.dll
		$a_81_1 = {43 72 79 70 74 65 72 2e 70 64 62 } //1 Crypter.pdb
		$a_81_2 = {64 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c } //1 dKERNEL32.dll
		$a_81_3 = {2e 30 30 63 66 67 } //1 .00cfg
		$a_81_4 = {5f 6d 66 45 77 56 4b 41 47 4f 41 54 } //1 _mfEwVKAGOAT
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_TrickBot_DC_MTB_3{
	meta:
		description = "Trojan:Win32/TrickBot.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 75 6b 6d 6e 6a 75 66 65 77 67 6a 6f 67 68 75 69 67 6f 68 76 62 74 79 73 6f 67 68 67 74 79 } //1 hukmnjufewgjoghuigohvbtysoghgty
		$a_81_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_81_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_81_3 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //1 TerminateProcess
		$a_81_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
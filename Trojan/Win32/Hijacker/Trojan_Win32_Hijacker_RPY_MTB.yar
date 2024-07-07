
rule Trojan_Win32_Hijacker_RPY_MTB{
	meta:
		description = "Trojan:Win32/Hijacker.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {8b 7d d8 6a 40 68 00 30 00 00 ff 77 50 ff 76 08 ff 33 ff 15 } //1
		$a_01_1 = {53 56 33 c0 c7 06 44 00 00 00 50 50 6a 04 50 50 50 57 50 c7 46 2c 01 00 00 00 66 89 46 30 ff 15 } //1
		$a_01_2 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //1 NtQueryInformationProcess
		$a_01_3 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 NtUnmapViewOfSection
		$a_01_4 = {48 4f 4c 4c 4f 57 49 4e 47 2e 70 64 62 } //1 HOLLOWING.pdb
		$a_01_5 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_7 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}

rule Trojan_Win32_Poison_NB_MTB{
	meta:
		description = "Trojan:Win32/Poison.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_01_0 = {79 08 4b 81 cb 00 ff ff ff 43 8a 5c 9c 14 30 1c 2a 42 3b d0 } //2
		$a_01_1 = {4e 81 ce 00 ff ff ff 46 8a 17 8b 44 b4 14 88 54 24 10 89 07 8b 54 24 10 83 c7 04 81 e2 ff 00 00 00 41 81 f9 00 01 00 00 } //1
		$a_81_2 = {6d 5f 53 74 75 62 } //1 m_Stub
		$a_81_3 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_81_4 = {43 3a 5c 66 69 6c 65 2e 65 78 65 } //1 C:\file.exe
		$a_81_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_81_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_81_7 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 NtUnmapViewOfSection
		$a_81_8 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_81_9 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=11
 
}
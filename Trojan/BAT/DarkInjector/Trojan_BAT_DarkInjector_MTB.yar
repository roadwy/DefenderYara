
rule Trojan_BAT_DarkInjector_MTB{
	meta:
		description = "Trojan:BAT/DarkInjector!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 53 42 } //1 AntiSB
		$a_01_1 = {41 6e 74 69 56 4d } //1 AntiVM
		$a_01_2 = {43 68 65 63 6b 44 65 66 65 6e 64 65 72 } //1 CheckDefender
		$a_01_3 = {52 75 6e 50 53 } //1 RunPS
		$a_01_4 = {50 72 6f 63 65 73 73 50 65 72 73 69 73 74 65 6e 63 65 } //1 ProcessPersistence
		$a_01_5 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 } //1 CreateProcess
		$a_01_6 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 GetThreadContext
		$a_01_7 = {57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 Wow64GetThreadContext
		$a_01_8 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
		$a_01_9 = {57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 Wow64SetThreadContext
		$a_01_10 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_11 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_12 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 NtUnmapViewOfSection
		$a_01_13 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_14 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_01_15 = {53 74 61 72 74 49 6e 6a 65 63 74 } //1 StartInject
		$a_01_16 = {47 65 74 49 6e 6a 65 63 74 69 6f 6e 50 61 74 68 } //1 GetInjectionPath
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=17
 
}
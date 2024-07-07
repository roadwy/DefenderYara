
rule Trojan_BAT_Polazert_MTB{
	meta:
		description = "Trojan:BAT/Polazert!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_01_0 = {44 65 6c 65 67 61 74 65 52 65 73 75 6d 65 54 68 72 65 61 64 } //1 DelegateResumeThread
		$a_01_1 = {44 65 6c 65 67 61 74 65 57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 DelegateWow64SetThreadContext
		$a_01_2 = {44 65 6c 65 67 61 74 65 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 DelegateSetThreadContext
		$a_01_3 = {44 65 6c 65 67 61 74 65 57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 DelegateWow64GetThreadContext
		$a_01_4 = {44 65 6c 65 67 61 74 65 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 DelegateGetThreadContext
		$a_01_5 = {44 65 6c 65 67 61 74 65 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 DelegateVirtualAllocEx
		$a_01_6 = {44 65 6c 65 67 61 74 65 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 DelegateWriteProcessMemory
		$a_01_7 = {44 65 6c 65 67 61 74 65 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 DelegateReadProcessMemory
		$a_01_8 = {44 65 6c 65 67 61 74 65 5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 DelegateZwUnmapViewOfSection
		$a_01_9 = {44 65 6c 65 67 61 74 65 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 DelegateCreateProcessA
		$a_01_10 = {50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 ProcessInformation
		$a_01_11 = {53 74 61 72 74 75 70 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 StartupInformation
		$a_01_12 = {74 00 65 00 6d 00 70 00 } //1 temp
		$a_01_13 = {2e 00 65 00 78 00 65 00 } //1 .exe
		$a_01_14 = {2e 00 70 00 73 00 31 00 } //1 .ps1
		$a_01_15 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_01_16 = {2d 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 50 00 6f 00 6c 00 69 00 63 00 79 00 20 00 62 00 79 00 70 00 61 00 73 00 73 00 } //1 -ExecutionPolicy bypass
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=17
 
}

rule Trojan_BAT_SwotterLoader_MTB{
	meta:
		description = "Trojan:BAT/SwotterLoader!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 53 42 } //1 AntiSB
		$a_01_1 = {41 6e 74 69 56 4d } //1 AntiVM
		$a_01_2 = {6c 6f 61 64 72 65 73 6f 75 72 63 65 } //1 loadresource
		$a_01_3 = {49 73 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //1 IsAdministrator
		$a_01_4 = {50 72 6f 63 65 73 73 50 65 72 73 69 73 74 65 6e 63 65 57 61 74 63 68 65 72 } //1 ProcessPersistenceWatcher
		$a_01_5 = {50 72 6f 74 65 63 74 54 68 65 46 69 6c 65 } //1 ProtectTheFile
		$a_01_6 = {53 74 61 72 74 49 6e 6a 65 63 74 } //1 StartInject
		$a_01_7 = {47 65 74 49 6e 6a 65 63 74 69 6f 6e 50 61 74 68 } //1 GetInjectionPath
		$a_01_8 = {44 65 6c 65 67 61 74 65 57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 DelegateWow64SetThreadContext
		$a_01_9 = {44 65 6c 65 67 61 74 65 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 DelegateSetThreadContext
		$a_01_10 = {44 65 6c 65 67 61 74 65 57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 DelegateWow64GetThreadContext
		$a_01_11 = {44 65 6c 65 67 61 74 65 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 DelegateGetThreadContext
		$a_01_12 = {44 65 6c 65 67 61 74 65 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 DelegateVirtualAllocEx
		$a_01_13 = {44 65 6c 65 67 61 74 65 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 DelegateWriteProcessMemory
		$a_01_14 = {44 65 6c 65 67 61 74 65 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 DelegateReadProcessMemory
		$a_01_15 = {44 65 6c 65 67 61 74 65 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 DelegateCreateProcessA
		$a_01_16 = {44 65 6c 65 67 61 74 65 5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 DelegateZwUnmapViewOfSection
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=17
 
}
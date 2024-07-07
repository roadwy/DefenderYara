
rule Trojan_BAT_StealerLoader_AB_MTB{
	meta:
		description = "Trojan:BAT/StealerLoader.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 1b 00 00 "
		
	strings :
		$a_01_0 = {44 65 6c 65 67 61 74 65 57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 DelegateWow64SetThreadContext
		$a_01_1 = {44 65 6c 65 67 61 74 65 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 DelegateSetThreadContext
		$a_01_2 = {44 65 6c 65 67 61 74 65 57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 DelegateWow64GetThreadContext
		$a_01_3 = {44 65 6c 65 67 61 74 65 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 DelegateGetThreadContext
		$a_01_4 = {44 65 6c 65 67 61 74 65 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 DelegateVirtualAllocEx
		$a_01_5 = {44 65 6c 65 67 61 74 65 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 DelegateWriteProcessMemory
		$a_01_6 = {44 65 6c 65 67 61 74 65 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 DelegateReadProcessMemory
		$a_01_7 = {44 65 6c 65 67 61 74 65 5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 DelegateZwUnmapViewOfSection
		$a_01_8 = {44 65 6c 65 67 61 74 65 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 DelegateCreateProcessA
		$a_01_9 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_10 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_11 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_12 = {50 61 72 61 6d 65 74 65 72 69 7a 65 64 54 68 72 65 61 64 53 74 61 72 74 } //1 ParameterizedThreadStart
		$a_01_13 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //1 NtQueryInformationProcess
		$a_01_14 = {58 4f 52 5f 44 45 43 } //1 XOR_DEC
		$a_01_15 = {50 72 6f 63 65 73 73 50 65 72 73 69 73 74 65 6e 63 65 57 61 74 63 68 65 72 } //1 ProcessPersistenceWatcher
		$a_01_16 = {41 6c 6c 6f 77 41 63 63 65 73 73 } //1 AllowAccess
		$a_01_17 = {50 72 6f 74 65 63 74 54 68 65 46 69 6c 65 } //1 ProtectTheFile
		$a_01_18 = {53 74 61 72 74 75 70 } //1 Startup
		$a_01_19 = {4c 6f 61 64 41 70 69 } //1 LoadApi
		$a_01_20 = {43 72 65 61 74 65 41 70 69 } //1 CreateApi
		$a_01_21 = {53 74 61 72 74 49 6e 6a 65 63 74 } //1 StartInject
		$a_01_22 = {47 65 74 49 6e 6a 65 63 74 69 6f 6e 50 61 74 68 } //1 GetInjectionPath
		$a_01_23 = {46 69 6c 65 53 79 73 74 65 6d 41 63 63 65 73 73 52 75 6c 65 } //1 FileSystemAccessRule
		$a_01_24 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_25 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //1 GetDelegateForFunctionPointer
		$a_01_26 = {4b 69 6c 6c } //1 Kill
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1) >=27
 
}
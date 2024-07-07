
rule Trojan_Win64_CryptInject_AG_MSR{
	meta:
		description = "Trojan:Win64/CryptInject.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_80_0 = {41 55 6a 6f 5a 4b 64 63 53 5a } //AUjoZKdcSZ  3
		$a_80_1 = {53 77 69 74 63 68 54 6f 46 69 62 65 72 } //SwitchToFiber  1
		$a_80_2 = {43 72 65 61 74 65 46 69 62 65 72 } //CreateFiber  1
		$a_80_3 = {43 6f 6e 76 65 72 74 54 68 72 65 61 64 54 6f 46 69 62 65 72 } //ConvertThreadToFiber  1
		$a_80_4 = {49 6e 69 74 69 61 6c 69 7a 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e } //InitializeCriticalSection  1
		$a_80_5 = {48 65 61 70 41 6c 6c 6f 63 } //HeapAlloc  1
		$a_80_6 = {47 65 74 50 72 6f 63 65 73 73 48 65 61 70 } //GetProcessHeap  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=9
 
}
rule Trojan_Win64_CryptInject_AG_MSR_2{
	meta:
		description = "Trojan:Win64/CryptInject.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0b 00 00 "
		
	strings :
		$a_80_0 = {59 54 42 53 42 62 4e 54 57 55 } //YTBSBbNTWU  3
		$a_80_1 = {78 73 68 69 4d 45 43 77 75 47 } //xshiMECwuG  3
		$a_80_2 = {53 77 69 74 63 68 54 6f 46 69 62 65 72 } //SwitchToFiber  1
		$a_80_3 = {43 72 65 61 74 65 46 69 62 65 72 } //CreateFiber  1
		$a_80_4 = {44 65 6c 65 74 65 46 69 62 65 72 } //DeleteFiber  1
		$a_80_5 = {53 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 41 } //SetCurrentDirectoryA  1
		$a_80_6 = {47 65 74 46 69 6c 65 41 74 74 72 69 62 75 74 65 73 41 } //GetFileAttributesA  1
		$a_80_7 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 41 } //GetComputerNameA  1
		$a_80_8 = {48 65 61 70 41 6c 6c 6f 63 } //HeapAlloc  1
		$a_80_9 = {47 65 74 50 72 6f 63 65 73 73 48 65 61 70 } //GetProcessHeap  1
		$a_80_10 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 49 64 } //GetCurrentThreadId  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=12
 
}
rule Trojan_Win64_CryptInject_AG_MSR_3{
	meta:
		description = "Trojan:Win64/CryptInject.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 11 00 00 "
		
	strings :
		$a_80_0 = {48 57 67 75 6c 6c 4f 46 6b 5a } //HWgullOFkZ  5
		$a_80_1 = {72 73 6f 42 55 70 63 44 6a 57 } //rsoBUpcDjW  5
		$a_01_2 = {73 69 74 75 72 6f 37 30 31 7a 68 2e 64 6c 6c } //2 situro701zh.dll
		$a_80_3 = {43 6f 6e 6e 65 63 74 4e 61 6d 65 64 50 69 70 65 } //ConnectNamedPipe  1
		$a_80_4 = {44 69 73 63 6f 6e 6e 65 63 74 4e 61 6d 65 64 50 69 70 65 } //DisconnectNamedPipe  1
		$a_80_5 = {49 6e 69 74 69 61 6c 69 7a 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e } //InitializeCriticalSection  1
		$a_80_6 = {45 6e 74 65 72 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e } //EnterCriticalSection  1
		$a_80_7 = {4c 65 61 76 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e } //LeaveCriticalSection  1
		$a_80_8 = {43 72 65 61 74 65 54 68 72 65 61 64 } //CreateThread  1
		$a_80_9 = {4f 70 65 6e 54 68 72 65 61 64 } //OpenThread  1
		$a_80_10 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //ResumeThread  1
		$a_80_11 = {47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 } //GetModuleFileNameA  1
		$a_80_12 = {43 72 65 61 74 65 4e 61 6d 65 64 50 69 70 65 41 } //CreateNamedPipeA  1
		$a_80_13 = {43 72 65 61 74 65 41 63 74 43 74 78 41 } //CreateActCtxA  1
		$a_80_14 = {41 63 74 69 76 61 74 65 41 63 74 43 74 78 } //ActivateActCtx  1
		$a_80_15 = {47 65 74 50 72 6f 63 65 73 73 48 65 61 70 } //GetProcessHeap  1
		$a_80_16 = {48 65 61 70 41 6c 6c 6f 63 } //HeapAlloc  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_01_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1) >=21
 
}
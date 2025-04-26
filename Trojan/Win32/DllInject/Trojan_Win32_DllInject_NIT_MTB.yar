
rule Trojan_Win32_DllInject_NIT_MTB{
	meta:
		description = "Trojan:Win32/DllInject.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 09 00 00 "
		
	strings :
		$a_01_0 = {44 4c 4c 20 49 6e 6a 65 63 74 65 64 21 } //2 DLL Injected!
		$a_01_1 = {50 52 4f 43 45 53 53 20 49 4e 4a 45 43 54 49 4f 4e } //2 PROCESS INJECTION
		$a_01_2 = {5f 51 75 65 72 79 5f 70 65 72 66 5f 63 6f 75 6e 74 65 72 } //2 _Query_perf_counter
		$a_01_3 = {50 72 6f 63 65 73 73 20 6f 70 65 6e 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //2 Process opened successfully
		$a_01_4 = {52 65 6c 65 61 73 65 5c 73 6b 65 65 74 32 2e 70 64 62 } //2 Release\skeet2.pdb
		$a_01_5 = {74 65 72 6d 69 6e 61 74 65 } //1 terminate
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_8 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=14
 
}

rule Trojan_Win64_VMPAgent_RP_MTB{
	meta:
		description = "Trojan:Win64/VMPAgent.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,55 00 55 00 0d 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 50 69 63 74 75 72 65 73 5c 74 65 6d 70 2e 74 6d 70 } //10 C:\Users\Public\Pictures\temp.tmp
		$a_01_1 = {51 51 50 43 4c 65 61 6b 53 63 61 6e 2e 65 78 65 } //1 QQPCLeakScan.exe
		$a_01_2 = {6b 77 73 70 72 6f 74 65 63 74 36 34 2e 65 78 65 } //1 kwsprotect64.exe
		$a_01_3 = {4b 76 4d 6f 6e 58 50 2e 65 78 65 } //1 KvMonXP.exe
		$a_01_4 = {72 73 64 65 6c 61 79 6c 61 75 6e 63 68 65 72 2e 65 78 65 } //1 rsdelaylauncher.exe
		$a_01_5 = {33 36 30 54 72 61 79 2e 65 78 65 } //1 360Tray.exe
		$a_01_6 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 20 2b 20 45 78 69 74 50 72 6f 63 65 73 73 } //10 CreateRemoteThread + ExitProcess
		$a_01_7 = {45 69 70 20 4d 6f 64 69 66 69 63 61 74 69 6f 6e 20 2b 20 45 78 69 74 50 72 6f 63 65 73 73 } //10 Eip Modification + ExitProcess
		$a_01_8 = {49 6e 6a 65 63 74 20 73 68 65 6c 6c 63 6f 64 65 } //10 Inject shellcode
		$a_01_9 = {43 72 61 73 68 20 77 69 74 68 20 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //10 Crash with VirtualProtectEx
		$a_01_10 = {43 72 61 73 68 20 77 69 74 68 20 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 Crash with WriteProcessMemory
		$a_01_11 = {43 72 61 73 68 20 77 69 74 68 20 44 75 70 6c 69 63 61 74 65 48 61 6e 64 6c 65 } //10 Crash with DuplicateHandle
		$a_01_12 = {43 72 61 73 68 20 77 69 74 68 20 43 72 65 61 74 65 4a 6f 62 4f 62 6a 65 63 74 2c 20 41 73 73 69 67 6e 50 72 6f 63 65 73 73 54 6f 4a 6f 62 4f 62 6a 65 63 74 2c 20 54 65 72 6d 69 6e 61 74 65 4a 6f 62 4f 62 6a 65 63 74 } //10 Crash with CreateJobObject, AssignProcessToJobObject, TerminateJobObject
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*10+(#a_01_11  & 1)*10+(#a_01_12  & 1)*10) >=85
 
}
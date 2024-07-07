
rule Backdoor_Win32_Agent_ADF{
	meta:
		description = "Backdoor:Win32/Agent.ADF,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2a 00 0b 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 50 72 6f 63 65 73 73 41 74 53 74 61 72 74 75 70 } //5 StartProcessAtStartup
		$a_01_1 = {53 74 61 72 74 50 72 6f 63 65 73 73 41 74 57 69 6e 4c 6f 67 6f 6e } //5 StartProcessAtWinLogon
		$a_01_2 = {53 74 6f 70 50 72 6f 63 65 73 73 41 74 57 69 6e 4c 6f 67 6f 66 66 } //5 StopProcessAtWinLogoff
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //5 CreateToolhelp32Snapshot
		$a_01_4 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //5 Process32Next
		$a_01_5 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //5 CreateRemoteThread
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //5 WriteProcessMemory
		$a_01_7 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //5 VirtualAllocEx
		$a_01_8 = {78 75 68 75 61 6e 6b 69 6c 6c 6c 6f 76 65 } //1 xuhuankilllove
		$a_01_9 = {53 79 73 74 65 6d 5c 77 61 62 33 32 64 62 2e 64 6c 6c } //1 System\wab32db.dll
		$a_01_10 = {42 65 69 5a 68 75 } //1 BeiZhu
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=42
 
}
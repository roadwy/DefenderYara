
rule TrojanDownloader_Win32_Agent_WY{
	meta:
		description = "TrojanDownloader:Win32/Agent.WY,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0e 00 00 "
		
	strings :
		$a_00_0 = {60 2b c0 64 8b 40 30 85 c0 78 0c 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 8b 40 34 8d 40 7c 8b 40 3c 89 44 24 1c 61 } //3
		$a_00_1 = {2b ed 8b d3 03 52 3c 8b 52 78 03 d3 } //2
		$a_00_2 = {73 68 65 6c 6c 5f 74 72 61 79 77 6e 64 } //1 shell_traywnd
		$a_00_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_5 = {44 65 62 75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 } //1 DebugActiveProcess
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_7 = {47 65 74 57 69 6e 64 6f 77 54 68 72 65 61 64 50 72 6f 63 65 73 73 49 64 } //1 GetWindowThreadProcessId
		$a_00_8 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_00_9 = {45 78 69 74 50 72 6f 63 65 73 73 } //1 ExitProcess
		$a_01_10 = {47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 } //1 GetModuleFileNameA
		$a_00_11 = {46 69 6e 64 57 69 6e 64 6f 77 41 } //1 FindWindowA
		$a_00_12 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64 } //1 GetCurrentProcessId
		$a_00_13 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1) >=17
 
}

rule Backdoor_BAT_Agentesla_MTB{
	meta:
		description = "Backdoor:BAT/Agentesla!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 14 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 69 6e 64 57 69 6e 64 6f 77 } //01 00  FindWindow
		$a_01_1 = {47 65 74 46 69 6c 65 41 74 74 72 69 62 75 74 65 73 } //01 00  GetFileAttributes
		$a_01_2 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 } //01 00  GetModuleHandle
		$a_01_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //01 00  GetProcAddress
		$a_01_4 = {47 65 74 55 73 65 72 4e 61 6d 65 } //01 00  GetUserName
		$a_01_5 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 } //01 00  CreateProcess
		$a_01_6 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  GetThreadContext
		$a_01_7 = {57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  Wow64GetThreadContext
		$a_01_8 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  SetThreadContext
		$a_01_9 = {57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  Wow64SetThreadContext
		$a_01_10 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  ReadProcessMemory
		$a_01_11 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_12 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  NtUnmapViewOfSection
		$a_01_13 = {69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //01 00  irtualAllocEx
		$a_01_14 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //01 00  ResumeThread
		$a_01_15 = {47 65 74 50 72 6f 63 65 73 73 65 73 } //01 00  GetProcesses
		$a_01_16 = {67 65 74 5f 55 73 65 72 4e 61 6d 65 } //01 00  get_UserName
		$a_01_17 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_18 = {49 6e 76 6f 6b 65 } //14 00  Invoke
		$a_03_19 = {52 65 5a 65 72 30 56 90 01 01 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
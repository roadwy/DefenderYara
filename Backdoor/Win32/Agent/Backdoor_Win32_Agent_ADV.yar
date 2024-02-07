
rule Backdoor_Win32_Agent_ADV{
	meta:
		description = "Backdoor:Win32/Agent.ADV,SIGNATURE_TYPE_PEHSTR,44 01 44 01 0a 00 00 64 00 "
		
	strings :
		$a_01_0 = {00 46 5f 53 65 72 76 65 72 2e 65 78 65 00 } //64 00 
		$a_01_1 = {00 74 68 75 61 2e 33 33 32 32 2e 6f 72 67 00 } //64 00 
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_3 = {54 54 75 6e 6e 65 6c } //0a 00  TTunnel
		$a_01_4 = {43 61 70 74 75 72 65 57 69 6e 64 6f 77 } //01 00  CaptureWindow
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_7 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 41 } //01 00  LookupPrivilegeValueA
		$a_01_8 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_9 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  Toolhelp32ReadProcessMemory
	condition:
		any of ($a_*)
 
}
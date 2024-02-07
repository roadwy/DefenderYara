
rule HackTool_Win32_ProcKiller_B{
	meta:
		description = "HackTool:Win32/ProcKiller.B,SIGNATURE_TYPE_PEHSTR_EXT,3f 00 3e 00 0a 00 00 0a 00 "
		
	strings :
		$a_00_0 = {57 69 6e 53 74 61 74 69 6f 6e 54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //0a 00  WinStationTerminateProcess
		$a_00_1 = {43 73 72 47 65 74 50 72 6f 63 65 73 73 49 64 } //0a 00  CsrGetProcessId
		$a_00_2 = {44 75 70 6c 69 63 61 74 65 48 61 6e 64 6c 65 } //0a 00  DuplicateHandle
		$a_00_3 = {68 03 00 01 40 8b 45 f8 50 ff 15 } //0a 00 
		$a_02_4 = {89 45 a8 89 45 ac 89 45 b0 89 45 b4 89 45 b8 89 45 bc 81 7d c8 00 00 00 80 0f 83 a8 00 00 00 90 01 02 6a 1c 8d 45 a4 50 8b 4d c8 51 8b 55 f8 52 ff 15 90 01 02 41 00 90 02 09 8b 45 b0 50 ff 15 90 01 02 41 00 90 02 0a 89 45 98 8b 45 b0 50 68 90 90 00 00 00 8b 4d 98 51 90 00 } //0a 00 
		$a_00_5 = {c7 45 cc 01 00 00 00 8b 45 e4 89 45 d0 8b 4d e8 89 4d d4 0f b6 45 0c f7 d8 1b c0 83 e0 02 89 45 d8 8b f4 6a 00 6a 00 6a 00 8d 45 cc 50 6a 00 8b 4d f4 51 ff 15 } //01 00 
		$a_00_6 = {53 75 73 70 65 6e 64 54 68 72 65 61 64 } //01 00  SuspendThread
		$a_00_7 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 } //01 00  LookupPrivilegeValue
		$a_00_8 = {6a 00 6a 00 68 60 f0 00 00 8b 45 08 50 ff 15 } //01 00 
		$a_00_9 = {6a 00 6a 00 6a 12 8b 45 08 50 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
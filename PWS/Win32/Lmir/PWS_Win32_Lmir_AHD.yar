
rule PWS_Win32_Lmir_AHD{
	meta:
		description = "PWS:Win32/Lmir.AHD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 ec 1c 53 55 56 57 68 3f 00 0f 00 6a 00 6a 00 ff 15 90 01 04 68 ff 01 0f 00 68 90 01 04 50 ff 15 90 01 04 8d 4c 24 10 51 6a 01 50 ff 15 90 01 04 6a 01 68 90 01 04 e8 90 01 04 68 90 01 04 e8 90 01 04 8b 1d 90 01 04 8b 3d 90 01 04 8b 2d 90 01 04 83 c4 0c 85 c0 74 19 50 6a 00 68 01 04 10 00 ff d3 90 00 } //01 00 
		$a_00_1 = {33 36 30 54 72 61 79 2e 65 78 65 } //01 00  360Tray.exe
		$a_00_2 = {33 36 30 53 61 66 65 2e 65 78 65 } //01 00  360Safe.exe
		$a_01_3 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 41 } //01 00  LookupPrivilegeValueA
		$a_01_4 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //01 00  AdjustTokenPrivileges
		$a_01_5 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //01 00  CreateRemoteThread
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_7 = {53 65 74 53 65 72 76 69 63 65 53 74 61 74 75 73 } //01 00  SetServiceStatus
		$a_01_8 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_01_9 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00  ShellExecuteA
	condition:
		any of ($a_*)
 
}

rule VirTool_Win32_DelfInject_gen_O{
	meta:
		description = "VirTool:Win32/DelfInject.gen!O,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_00_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //01 00  VirtualAllocEx
		$a_00_2 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  SetThreadContext
		$a_00_3 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //01 00  ResumeThread
		$a_01_4 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  ReadProcessMemory
		$a_01_5 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  GetThreadContext
		$a_00_6 = {53 65 74 46 69 6c 65 50 6f 69 6e 74 65 72 } //01 00  SetFilePointer
		$a_00_7 = {47 65 74 46 69 6c 65 53 69 7a 65 } //01 00  GetFileSize
		$a_00_8 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //01 00  CreateProcessA
		$a_00_9 = {52 65 61 64 46 69 6c 65 } //01 00  ReadFile
		$a_02_10 = {6a 00 6a 00 68 90 01 02 00 00 53 e8 90 01 04 6a 00 53 e8 90 01 04 90 03 02 02 8b f0 89 c6 81 ee 90 01 02 00 00 8d 45 fc 90 03 02 02 8b d6 89 f2 e8 90 01 04 6a 00 8d 45 f4 50 56 8d 45 fc e8 90 01 04 50 53 e8 90 00 } //01 00 
		$a_03_11 = {89 c3 83 fb ff 0f 84 90 01 02 00 00 6a 00 53 e8 90 01 04 89 c6 81 ee 00 5e 00 00 6a 00 6a 00 68 00 5e 00 00 53 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
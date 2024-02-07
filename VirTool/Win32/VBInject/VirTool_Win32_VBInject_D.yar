
rule VirTool_Win32_VBInject_D{
	meta:
		description = "VirTool:Win32/VBInject.D,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0c 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 74 75 62 53 42 58 } //02 00  StubSBX
		$a_01_1 = {63 72 78 73 73 } //02 00  crxss
		$a_01_2 = {52 75 6e 50 45 } //02 00  RunPE
		$a_01_3 = {63 00 6f 00 6e 00 73 00 65 00 6e 00 74 00 69 00 6e 00 67 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 4e 00 61 00 6d 00 65 00 3d 00 6d 00 } //02 00  consenting computerName=m
		$a_01_4 = {78 00 6c 00 6d 00 33 00 32 00 61 00 70 00 69 00 } //01 00  xlm32api
		$a_01_5 = {31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 30 00 } //01 00  1234567890
		$a_01_6 = {6d 50 72 6f 63 65 73 73 } //01 00  mProcess
		$a_01_7 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  ZwUnmapViewOfSection
		$a_01_8 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_9 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_10 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //01 00  Process32Next
		$a_01_11 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 } //00 00  RtlMoveMemory
	condition:
		any of ($a_*)
 
}
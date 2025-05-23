
rule VirTool_Win32_VBInject_C{
	meta:
		description = "VirTool:Win32/VBInject.C,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0f 00 00 "
		
	strings :
		$a_00_0 = {2f 23 2f 2b 5c 23 5c } //1 /#/+\#\
		$a_00_1 = {5c 00 76 00 62 00 70 00 53 00 74 00 75 00 62 00 2e 00 76 00 62 00 70 00 } //1 \vbpStub.vbp
		$a_00_2 = {62 61 73 43 6f 6e 74 65 78 74 00 } //1
		$a_00_3 = {62 61 73 4d 61 69 6e 00 } //1 慢䵳楡n
		$a_00_4 = {62 61 73 50 72 6f 63 65 73 53 00 } //1
		$a_00_5 = {62 61 73 52 75 6e 50 45 00 } //1
		$a_01_6 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 GetThreadContext
		$a_01_7 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_8 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
		$a_01_9 = {53 75 73 70 65 6e 64 54 68 72 65 61 64 } //1 SuspendThread
		$a_01_10 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_01_11 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 CreateProcessA
		$a_01_12 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_13 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_14 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //1 VirtualProtectEx
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=14
 
}
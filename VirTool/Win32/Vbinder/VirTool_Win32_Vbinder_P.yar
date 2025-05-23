
rule VirTool_Win32_Vbinder_P{
	meta:
		description = "VirTool:Win32/Vbinder.P,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0b 00 00 "
		
	strings :
		$a_01_0 = {43 00 72 00 65 00 61 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //2 CreateProcess
		$a_01_1 = {57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //2 WriteProcessMemory
		$a_01_2 = {47 00 65 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 } //2 GetThreadContext
		$a_01_3 = {53 00 65 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 } //2 SetThreadContext
		$a_01_4 = {52 00 65 00 73 00 75 00 6d 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00 } //2 ResumeThread
		$a_01_5 = {52 00 74 00 6c 00 4d 00 6f 00 76 00 65 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //2 RtlMoveMemory
		$a_01_6 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 45 00 78 00 } //2 VirtualAllocEx
		$a_00_7 = {5c 00 73 00 74 00 69 00 6b 00 69 00 2e 00 76 00 62 00 70 00 } //2 \stiki.vbp
		$a_00_8 = {73 74 69 6b 69 00 73 74 69 6b 69 00 00 73 74 69 6b 69 } //2 瑳歩i瑳歩i猀楴楫
		$a_01_9 = {73 74 69 6b 69 00 } //1 瑳歩i
		$a_01_10 = {2e 00 65 00 78 00 65 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*2+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=18
 
}
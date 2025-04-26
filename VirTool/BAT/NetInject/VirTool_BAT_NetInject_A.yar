
rule VirTool_BAT_NetInject_A{
	meta:
		description = "VirTool:BAT/NetInject.A,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2b 00 0a 00 00 "
		
	strings :
		$a_01_0 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 WriteProcessMemory
		$a_01_1 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //10 SetThreadContext
		$a_01_2 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //10 ResumeThread
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //10 VirtualAllocEx
		$a_00_4 = {49 73 53 61 6e 64 62 6f 78 69 65 } //1 IsSandboxie
		$a_00_5 = {49 73 4e 6f 72 6d 61 6e 53 61 6e 64 62 6f 78 } //1 IsNormanSandbox
		$a_00_6 = {49 73 53 75 6e 62 65 6c 74 53 61 6e 64 62 6f 78 } //1 IsSunbeltSandbox
		$a_00_7 = {49 73 41 6e 75 62 69 73 53 61 6e 64 62 6f 78 } //1 IsAnubisSandbox
		$a_00_8 = {49 73 43 57 53 61 6e 64 62 6f 78 } //1 IsCWSandbox
		$a_00_9 = {49 73 57 69 72 65 73 68 61 72 6b } //1 IsWireshark
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=43
 
}
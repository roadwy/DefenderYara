
rule VirTool_BAT_NetInject_A{
	meta:
		description = "VirTool:BAT/NetInject.A,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2b 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //0a 00  WriteProcessMemory
		$a_01_1 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //0a 00  SetThreadContext
		$a_01_2 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //0a 00  ResumeThread
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //01 00  VirtualAllocEx
		$a_00_4 = {49 73 53 61 6e 64 62 6f 78 69 65 } //01 00  IsSandboxie
		$a_00_5 = {49 73 4e 6f 72 6d 61 6e 53 61 6e 64 62 6f 78 } //01 00  IsNormanSandbox
		$a_00_6 = {49 73 53 75 6e 62 65 6c 74 53 61 6e 64 62 6f 78 } //01 00  IsSunbeltSandbox
		$a_00_7 = {49 73 41 6e 75 62 69 73 53 61 6e 64 62 6f 78 } //01 00  IsAnubisSandbox
		$a_00_8 = {49 73 43 57 53 61 6e 64 62 6f 78 } //01 00  IsCWSandbox
		$a_00_9 = {49 73 57 69 72 65 73 68 61 72 6b } //00 00  IsWireshark
	condition:
		any of ($a_*)
 
}
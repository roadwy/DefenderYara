
rule VirTool_Win32_DelfInject_gen_Z{
	meta:
		description = "VirTool:Win32/DelfInject.gen!Z,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_1 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_00_2 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
		$a_00_3 = {55 6e 64 65 74 65 63 74 6f 72 20 31 2e 31 } //3 Undetector 1.1
		$a_03_4 = {8a 04 1f 24 0f 8b 55 90 01 01 8a 14 32 80 e2 0f 32 c2 8a 14 1f 80 e2 f0 02 d0 88 14 1f 46 8d 45 90 01 01 8b 55 90 01 01 e8 90 01 04 8b 45 90 01 01 e8 90 01 04 3b f0 7e 05 be 01 00 00 00 43 ff 4d 90 01 01 75 c2 90 00 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*3+(#a_03_4  & 1)*5) >=8
 
}
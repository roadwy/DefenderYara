
rule VirTool_Win32_DelfInject_gen_U{
	meta:
		description = "VirTool:Win32/DelfInject.gen!U,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_00_0 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 49 64 } //10 GetCurrentThreadId
		$a_00_1 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //10 TerminateProcess
		$a_00_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //10 VirtualProtectEx
		$a_02_3 = {8b 45 fc 8b 55 f4 8a 44 10 ff 88 45 f3 8d 45 e8 8a 55 f3 80 ea 90 01 01 e8 90 01 04 8b 55 e8 8b 45 f8 e8 90 01 04 8b 45 f8 ff 45 f4 ff 4d ec 75 cf 90 00 } //1
		$a_03_4 = {44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 80 ea 90 01 01 e8 90 01 04 8b 55 f4 8b c6 e8 90 01 04 47 4b 75 da 90 09 04 00 8b 45 fc 90 03 01 01 8a 8b 90 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*1+(#a_03_4  & 1)*1) >=31
 
}
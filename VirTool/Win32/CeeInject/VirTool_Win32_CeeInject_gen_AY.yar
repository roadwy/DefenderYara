
rule VirTool_Win32_CeeInject_gen_AY{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AY,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {83 f8 01 8a 04 0a 75 05 02 04 1f eb 03 2a 04 1f 88 01 41 4e 75 } //2
		$a_01_1 = {8b 42 3c 03 c3 8d 84 30 f8 00 00 00 } //2
		$a_01_2 = {8a 14 08 8b c6 32 d3 83 e0 07 b9 08 00 00 00 8a da 2b c8 d2 e3 8a c8 d2 ea 0a da 88 1c 3e 46 3b f5 72 } //2
		$a_10_3 = {53 62 69 65 44 6c 6c 2e 64 6c 6c } //1 SbieDll.dll
		$a_10_4 = {53 79 6e 74 68 65 74 69 63 55 73 65 72 2e 46 47 56 53 } //1 SyntheticUser.FGVS
		$a_10_5 = {53 41 4e 44 42 4f 58 } //1 SANDBOX
		$a_10_6 = {45 78 69 74 20 53 69 6c 65 6e 74 6c 79 } //1 Exit Silently
		$a_10_7 = {4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //1 NtWriteVirtualMemory
		$a_10_8 = {4e 74 52 65 73 75 6d 65 54 68 72 65 61 64 } //1 NtResumeThread
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_10_3  & 1)*1+(#a_10_4  & 1)*1+(#a_10_5  & 1)*1+(#a_10_6  & 1)*1+(#a_10_7  & 1)*1+(#a_10_8  & 1)*1) >=5
 
}
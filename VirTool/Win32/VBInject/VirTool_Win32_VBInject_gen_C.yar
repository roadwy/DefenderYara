
rule VirTool_Win32_VBInject_gen_C{
	meta:
		description = "VirTool:Win32/VBInject.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,18 00 16 00 07 00 00 "
		
	strings :
		$a_00_0 = {6f 00 6c 00 6c 00 79 00 64 00 62 00 67 00 } //1 ollydbg
		$a_00_1 = {72 00 65 00 67 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //1 regmon.exe
		$a_00_2 = {66 00 69 00 6c 00 65 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //1 filemon.exe
		$a_00_3 = {70 00 72 00 6f 00 63 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //1 procmon.exe
		$a_00_4 = {2d 00 73 00 6b 00 69 00 70 00 61 00 6e 00 74 00 69 00 } //4 -skipanti
		$a_00_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 WriteProcessMemory
		$a_01_6 = {f3 00 01 c1 e7 04 58 ff 9d fb 12 fc 0d 6c 50 ff 6c 40 ff fc a0 00 0a 04 50 ff 66 ec fe df 01 00 26 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*4+(#a_00_5  & 1)*10+(#a_01_6  & 1)*10) >=22
 
}
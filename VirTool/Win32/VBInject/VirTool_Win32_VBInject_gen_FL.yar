
rule VirTool_Win32_VBInject_gen_FL{
	meta:
		description = "VirTool:Win32/VBInject.gen!FL,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 04 51 52 e8 ?? ?? ?? 00 8b 45 ?? 6a 00 50 6a 01 8d 4d ?? 6a 00 51 6a 10 6a 00 ff d3 } //2
		$a_01_1 = {5a 77 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //1 ZwWriteVirtualMemory
		$a_01_2 = {77 00 69 00 6e 00 33 00 32 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 win32_process
		$a_01_3 = {4d 00 53 00 4d 00 50 00 45 00 4e 00 47 00 2e 00 45 00 58 00 45 00 } //1 MSMPENG.EXE
		$a_01_4 = {41 00 56 00 47 00 55 00 41 00 52 00 44 00 2e 00 45 00 58 00 45 00 } //1 AVGUARD.EXE
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
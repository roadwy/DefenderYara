
rule VirTool_Win32_VBInject_OS_bit{
	meta:
		description = "VirTool:Win32/VBInject.OS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 8b 0d 18 00 00 00 [0-40] 8b 49 30 [0-40] 02 51 02 [0-40] ff e2 } //2
		$a_03_1 = {8b 43 2c eb [0-40] 0f 6e e0 [0-40] 0f ef e6 [0-40] 0f 7e e0 [0-40] 83 f8 00 0f 85 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule VirTool_Win32_VBInject_OS_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.OS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 ff 35 30 00 00 00 [0-30] 58 [0-30] 8b 40 0c [0-30] 8b 40 14 } //1
		$a_03_1 = {81 3b 4d 00 53 00 75 [0-30] 81 7b 04 56 00 42 00 75 [0-30] 8b 70 10 [0-30] 8b 5e 3c [0-30] 01 de [0-30] [0-30] 8b 5e 78 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}
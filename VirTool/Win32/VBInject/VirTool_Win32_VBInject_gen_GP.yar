
rule VirTool_Win32_VBInject_gen_GP{
	meta:
		description = "VirTool:Win32/VBInject.gen!GP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 01 07 00 01 00 } //1
		$a_01_1 = {68 95 e3 35 69 } //1
		$a_01_2 = {89 90 b0 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule VirTool_Win32_VBInject_gen_GP_2{
	meta:
		description = "VirTool:Win32/VBInject.gen!GP,SIGNATURE_TYPE_PEHSTR,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4a 37 46 4b 31 58 43 53 6e 6e 54 33 00 00 00 00 74 68 53 6c 47 62 48 55 4e 39 50 67 57 39 00 00 6f 71 4b 31 62 63 00 00 4b 33 43 45 68 70 00 00 79 37 53 43 38 7a 78 35 4a 34 4e 53 6e 00 00 00 54 59 6b 67 49 00 00 00 62 42 4b 6b 7a 79 52 57 5a 00 00 00 52 42 73 39 4f 52 66 4e 00 00 00 00 58 39 4f 34 7a 7a 35 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
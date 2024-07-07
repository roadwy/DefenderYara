
rule VirTool_Win32_VBInject_gen_GA{
	meta:
		description = "VirTool:Win32/VBInject.gen!GA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3b c2 7f 0e c6 04 07 cc 90 01 05 89 45 ec eb ee 90 00 } //2
		$a_01_1 = {c7 45 a8 e8 00 00 00 89 7d a0 } //1
		$a_01_2 = {c7 45 a8 c3 00 00 00 89 7d a0 } //1
		$a_01_3 = {c7 45 a8 58 00 00 00 89 7d a0 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}

rule VirTool_Win32_VBInject_gen_IM{
	meta:
		description = "VirTool:Win32/VBInject.gen!IM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 04 81 07 00 01 90 } //1
		$a_01_1 = {68 95 e3 35 69 } //1
		$a_01_2 = {68 c8 46 4a c5 } //1
		$a_01_3 = {68 c2 8c 10 c5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
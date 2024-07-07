
rule VirTool_Win32_VBInject_gen_FQ{
	meta:
		description = "VirTool:Win32/VBInject.gen!FQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {94 ac ef 1c 00 94 ac ef 10 00 aa 08 08 00 8f } //1
		$a_01_1 = {f5 07 00 01 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
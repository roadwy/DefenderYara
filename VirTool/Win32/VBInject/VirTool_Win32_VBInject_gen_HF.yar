
rule VirTool_Win32_VBInject_gen_HF{
	meta:
		description = "VirTool:Win32/VBInject.gen!HF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 40 1c 03 41 10 } //1
		$a_01_1 = {89 81 90 02 00 00 } //1
		$a_01_2 = {89 81 e0 01 00 00 } //1
		$a_01_3 = {8b 80 84 02 00 00 83 c0 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
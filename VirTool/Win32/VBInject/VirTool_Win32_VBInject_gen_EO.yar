
rule VirTool_Win32_VBInject_gen_EO{
	meta:
		description = "VirTool:Win32/VBInject.gen!EO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 81 b0 00 00 } //1
		$a_03_1 = {8b 80 a4 00 00 00 [0-0a] 83 c0 08 } //1
		$a_03_2 = {66 b9 ff 00 [0-10] 66 b9 d0 00 } //1
		$a_01_3 = {50 68 bd ca 3b d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
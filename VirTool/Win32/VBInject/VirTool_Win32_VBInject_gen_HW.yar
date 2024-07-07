
rule VirTool_Win32_VBInject_gen_HW{
	meta:
		description = "VirTool:Win32/VBInject.gen!HW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 c1 8b 8d 90 01 01 ff ff ff 0f 80 90 01 04 89 81 b0 00 00 00 90 00 } //1
		$a_03_1 = {07 00 01 00 90 09 02 00 c7 90 00 } //1
		$a_03_2 = {8b 91 a4 00 00 00 8b 85 90 01 02 ff ff 83 c2 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
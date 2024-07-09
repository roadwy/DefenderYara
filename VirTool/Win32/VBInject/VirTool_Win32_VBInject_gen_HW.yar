
rule VirTool_Win32_VBInject_gen_HW{
	meta:
		description = "VirTool:Win32/VBInject.gen!HW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 c1 8b 8d ?? ff ff ff 0f 80 ?? ?? ?? ?? 89 81 b0 00 00 00 } //1
		$a_03_1 = {07 00 01 00 90 09 02 00 c7 } //1
		$a_03_2 = {8b 91 a4 00 00 00 8b 85 ?? ?? ff ff 83 c2 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
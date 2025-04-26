
rule VirTool_Win32_VBInject_gen_HI{
	meta:
		description = "VirTool:Win32/VBInject.gen!HI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 40 1c 8b 8d ?? ?? ff ff 03 41 10 8b 4d 08 89 81 24 01 00 00 } //1
		$a_01_1 = {8b 4d 08 89 41 74 } //1
		$a_01_2 = {8b 80 18 01 00 00 83 c0 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
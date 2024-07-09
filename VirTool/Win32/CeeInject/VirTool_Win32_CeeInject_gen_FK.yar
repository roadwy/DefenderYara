
rule VirTool_Win32_CeeInject_gen_FK{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 f3 34 66 81 e9 a9 00 66 0b c3 c0 e3 03 02 c8 f6 d8 d0 e3 f7 d3 c0 e0 1a } //1
		$a_03_1 = {30 0c 2f 83 c7 01 3b fa 89 3d ?? ?? ?? ?? 7c } //1
		$a_01_2 = {66 4b 66 81 f1 b0 00 f6 d3 fe c8 fe c1 8b 44 24 14 8b 4c 24 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
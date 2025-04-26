
rule VirTool_Win32_VBInject_gen_LF{
	meta:
		description = "VirTool:Win32/VBInject.gen!LF,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {c7 04 c1 64 a1 18 00 c7 44 c1 04 00 00 8b 40 } //2
		$a_01_1 = {c7 04 c1 55 89 e5 90 c7 44 c1 04 31 f6 90 31 } //2
		$a_01_2 = {c7 04 c1 c0 8b 75 08 c7 44 c1 04 90 8b 46 08 } //2
		$a_01_3 = {c7 00 07 0f 6e ce c7 40 04 0f ef c1 0f } //1
		$a_01_4 = {c7 00 65 72 6e 65 c7 40 04 6c 33 32 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
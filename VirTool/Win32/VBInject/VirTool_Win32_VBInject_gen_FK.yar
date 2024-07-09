
rule VirTool_Win32_VBInject_gen_FK{
	meta:
		description = "VirTool:Win32/VBInject.gen!FK,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 91 a4 00 00 00 (90 13|) c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 08 [0-06] 89 95 } //4
		$a_01_1 = {89 81 b0 00 00 00 } //1
		$a_01_2 = {89 8a b0 00 00 00 } //1
		$a_01_3 = {68 95 e3 35 69 } //1
		$a_01_4 = {c7 02 07 00 01 00 } //1
		$a_01_5 = {68 c2 8c 10 c5 68 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
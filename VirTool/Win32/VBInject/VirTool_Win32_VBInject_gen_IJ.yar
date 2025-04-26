
rule VirTool_Win32_VBInject_gen_IJ{
	meta:
		description = "VirTool:Win32/VBInject.gen!IJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 c2 0f 80 ?? ?? ?? ?? 89 81 b0 00 00 00 } //1
		$a_01_1 = {c7 01 07 00 01 90 } //1
		$a_01_2 = {68 95 e3 35 69 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
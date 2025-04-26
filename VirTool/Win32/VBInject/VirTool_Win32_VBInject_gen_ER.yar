
rule VirTool_Win32_VBInject_gen_ER{
	meta:
		description = "VirTool:Win32/VBInject.gen!ER,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {f5 f8 00 00 00 aa f4 28 6b ?? ?? b1 } //1
		$a_03_1 = {00 30 f5 03 00 00 00 6c ?? ?? 52 28 ?? ?? 40 00 f5 04 00 00 00 6c } //1
		$a_01_2 = {f5 00 01 00 00 b2 f5 01 00 00 00 80 0c 00 fc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
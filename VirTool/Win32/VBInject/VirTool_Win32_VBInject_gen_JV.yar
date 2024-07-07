
rule VirTool_Win32_VBInject_gen_JV{
	meta:
		description = "VirTool:Win32/VBInject.gen!JV,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 d2 00 00 00 ff d7 8b 56 44 b9 c7 00 00 00 88 82 35 03 00 00 ff d7 8b 4e 44 88 81 36 03 00 00 b9 a7 00 00 00 ff d7 8b 56 44 b9 68 00 00 00 88 82 37 03 00 00 } //1
		$a_03_1 = {b9 d2 00 00 00 ff d6 8b 15 90 01 04 b9 c7 00 00 00 88 82 35 03 00 00 ff d6 8b 0d 90 01 04 88 81 36 03 00 00 b9 a7 00 00 00 ff d6 8b 15 90 01 04 b9 68 00 00 00 88 82 37 03 00 00 ff d6 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
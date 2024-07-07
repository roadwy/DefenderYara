
rule VirTool_Win32_CeeInject_gen_GO{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 46 28 57 03 45 f4 89 87 b0 00 00 00 ff 75 } //1
		$a_03_1 = {33 c0 8b c8 81 e1 ff 07 00 00 8a 89 90 01 04 00 88 90 01 04 40 3d 90 01 04 72 e4 90 00 } //1
		$a_03_2 = {8a 0c 02 8d 34 02 8a 83 90 01 04 22 c2 f6 d1 32 c1 83 c9 ff 88 06 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
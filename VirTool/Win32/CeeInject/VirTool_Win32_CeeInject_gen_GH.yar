
rule VirTool_Win32_CeeInject_gen_GH{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 42 28 50 68 00 00 40 00 e8 } //1
		$a_03_1 = {07 00 01 00 90 09 06 00 c7 05 90 00 } //1
		$a_03_2 = {6a 00 68 00 30 00 00 8b 15 90 01 04 8b 42 50 50 8b 0d 90 01 04 8b 51 34 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}

rule VirTool_Win32_CeeInject_gen_FN{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 90 09 06 00 c7 05 } //1
		$a_03_1 = {07 00 01 00 90 09 04 00 c7 44 24 } //1
		$a_03_2 = {8b 58 50 8b ?? 34 [0-20] 6a 40 68 00 30 00 00 } //2
		$a_01_3 = {8b 50 34 03 50 28 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2) >=5
 
}
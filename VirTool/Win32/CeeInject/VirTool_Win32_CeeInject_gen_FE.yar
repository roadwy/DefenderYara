
rule VirTool_Win32_CeeInject_gen_FE{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 50 34 8b 68 50 } //1
		$a_01_1 = {8b 50 34 03 50 28 } //1
		$a_03_2 = {07 00 01 00 90 09 06 00 c7 05 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
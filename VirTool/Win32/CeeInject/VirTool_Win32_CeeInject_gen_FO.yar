
rule VirTool_Win32_CeeInject_gen_FO{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 90 09 06 00 c7 05 } //1
		$a_01_1 = {8b 78 50 8b 58 34 } //1
		$a_01_2 = {8b 48 34 03 48 28 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
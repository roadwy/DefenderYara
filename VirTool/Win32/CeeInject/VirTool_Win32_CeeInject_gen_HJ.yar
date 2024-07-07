
rule VirTool_Win32_CeeInject_gen_HJ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 51 34 a1 90 01 04 03 50 28 89 15 90 00 } //1
		$a_03_1 = {07 00 01 00 90 09 06 00 c7 85 90 00 } //1
		$a_03_2 = {68 00 30 00 00 a1 90 01 04 8b 48 50 51 8b 15 90 01 04 8b 52 34 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}

rule VirTool_Win32_CeeInject_gen_FU{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 90 09 06 00 c7 05 } //1
		$a_01_1 = {8b 4e 54 8b 56 34 } //1
		$a_03_2 = {8b 4e 34 8b 46 28 [0-08] 03 c1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
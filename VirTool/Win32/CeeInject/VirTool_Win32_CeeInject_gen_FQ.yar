
rule VirTool_Win32_CeeInject_gen_FQ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 46 28 03 46 34 } //1
		$a_01_1 = {ff 76 50 ff 76 34 } //1
		$a_03_2 = {07 00 01 00 90 09 06 00 c7 05 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule VirTool_Win32_CeeInject_gen_FQ_2{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 55 ?? 85 c0 0f 84 ?? ?? ?? ?? 50 6a 00 ff 55 ?? 85 c0 } //1
		$a_03_1 = {f7 c1 01 00 00 00 74 09 60 6a ?? e8 ?? ?? ?? ?? 61 e2 ?? ff 75 ?? ff 75 ?? b8 ?? ?? ?? ?? ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
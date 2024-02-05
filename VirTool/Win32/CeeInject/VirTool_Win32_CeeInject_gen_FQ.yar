
rule VirTool_Win32_CeeInject_gen_FQ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 46 28 03 46 34 } //01 00 
		$a_01_1 = {ff 76 50 ff 76 34 } //01 00 
		$a_03_2 = {07 00 01 00 90 09 06 00 c7 05 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_gen_FQ_2{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 55 90 01 01 85 c0 0f 84 90 01 04 50 6a 00 ff 55 90 01 01 85 c0 90 00 } //01 00 
		$a_03_1 = {f7 c1 01 00 00 00 74 09 60 6a 90 01 01 e8 90 01 04 61 e2 90 01 01 ff 75 90 01 01 ff 75 90 01 01 b8 90 01 04 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
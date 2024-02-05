
rule VirTool_Win32_CeeInject_gen_IH{
	meta:
		description = "VirTool:Win32/CeeInject.gen!IH,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 8b 85 90 01 04 8b 40 50 50 8b 85 90 01 04 8b 40 34 90 00 } //01 00 
		$a_03_1 = {8b 40 34 8b 95 90 01 04 03 42 28 89 85 90 00 } //01 00 
		$a_03_2 = {07 00 01 00 90 09 06 00 c7 85 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
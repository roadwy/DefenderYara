
rule VirTool_Win32_CeeInject_gen_GT{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 90 09 06 00 c7 05 90 00 } //01 00 
		$a_01_1 = {8b 40 28 01 d0 a3 } //01 00 
		$a_03_2 = {8b 40 34 a3 90 01 04 a1 90 01 04 8b 40 50 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
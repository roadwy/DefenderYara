
rule VirTool_Win32_CeeInject_gen_FP{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 90 09 06 00 c7 05 90 00 } //01 00 
		$a_03_1 = {8b 48 50 51 8b 15 90 01 04 8b 42 34 90 00 } //01 00 
		$a_03_2 = {8b 48 34 8b 15 90 01 04 03 4a 28 89 0d 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
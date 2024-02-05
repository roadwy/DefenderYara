
rule VirTool_Win32_CeeInject_gen_GE{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 90 09 06 00 c7 05 90 00 } //01 00 
		$a_03_1 = {68 00 30 00 00 8b 15 90 01 04 8b 42 50 50 8b 0d 90 01 04 8b 51 34 90 00 } //01 00 
		$a_01_2 = {8b 50 28 b9 00 00 40 00 e8 } //01 00 
	condition:
		any of ($a_*)
 
}
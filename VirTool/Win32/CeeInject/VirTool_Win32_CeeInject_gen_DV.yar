
rule VirTool_Win32_CeeInject_gen_DV{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 90 03 06 06 ff 70 50 ff 70 34 8b 48 50 8b 50 34 90 00 } //01 00 
		$a_01_1 = {8b 48 34 03 48 28 } //01 00 
		$a_03_2 = {8b 41 28 a3 90 01 04 90 03 03 05 03 41 34 8b 51 34 03 c2 90 00 } //01 00 
		$a_03_3 = {8b 41 28 a3 90 01 04 03 41 34 a3 90 1b 00 ff 56 3c 90 00 } //01 00 
		$a_03_4 = {32 0a 80 f1 90 01 01 40 88 0a 90 00 } //01 00 
		$a_03_5 = {07 00 01 00 90 09 06 00 c7 05 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
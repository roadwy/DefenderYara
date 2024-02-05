
rule VirTool_Win32_CeeInject_gen_HB{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 48 34 03 48 28 } //01 00 
		$a_03_1 = {07 00 01 00 90 09 06 00 c7 05 90 00 } //01 00 
		$a_01_2 = {68 00 30 00 00 ff 70 50 ff 70 34 } //01 00 
	condition:
		any of ($a_*)
 
}

rule VirTool_Win32_CeeInject_gen_LG{
	meta:
		description = "VirTool:Win32/CeeInject.gen!LG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 50 ff 75 90 01 01 ff 95 90 00 } //01 00 
		$a_03_1 = {8b 47 28 03 45 90 01 01 89 85 90 09 03 00 ff 55 90 00 } //01 00 
		$a_03_2 = {0f b7 47 06 ff 45 90 01 01 83 45 90 01 01 28 39 45 90 01 01 7c c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
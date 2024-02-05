
rule VirTool_Win32_CeeInject_gen_HE{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 57 28 53 03 d5 89 93 b0 00 00 00 } //01 00 
		$a_01_1 = {c7 03 07 00 01 00 } //01 00 
		$a_03_2 = {8b 47 50 8b 4f 34 8b 54 24 90 01 01 6a 40 68 00 30 00 00 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
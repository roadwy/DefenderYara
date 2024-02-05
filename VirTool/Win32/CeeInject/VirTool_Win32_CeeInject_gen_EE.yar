
rule VirTool_Win32_CeeInject_gen_EE{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 83 c2 01 89 55 f8 81 7d f8 2e e6 0a 00 0f 8f 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
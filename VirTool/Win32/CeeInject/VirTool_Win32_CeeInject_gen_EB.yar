
rule VirTool_Win32_CeeInject_gen_EB{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b f0 8b 46 04 6a 2e 50 } //01 00 
		$a_01_1 = {33 ff 33 c0 89 44 84 14 40 3d 00 01 00 00 7c f4 } //00 00 
	condition:
		any of ($a_*)
 
}

rule VirTool_Win32_VBInject_gen_GM{
	meta:
		description = "VirTool:Win32/VBInject.gen!GM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 82 b0 00 00 00 } //01 00 
		$a_01_1 = {b9 c3 00 00 00 ff 15 } //01 00 
		$a_03_2 = {0f bf d0 8b 85 90 01 04 33 c2 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
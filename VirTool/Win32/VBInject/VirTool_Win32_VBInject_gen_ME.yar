
rule VirTool_Win32_VBInject_gen_ME{
	meta:
		description = "VirTool:Win32/VBInject.gen!ME,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 00 0f 6e c0 55 6a 90 01 01 ff 35 90 00 } //01 00 
		$a_03_1 = {c7 00 0f 6e cb 89 6a 90 01 01 ff 35 90 00 } //01 00 
		$a_03_2 = {c7 00 e5 0f 6e d1 6a 90 01 01 ff 35 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}
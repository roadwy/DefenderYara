
rule VirTool_Win32_CeeInject_gen_JI{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 8b 00 00 00 74 11 8b 45 90 01 01 03 05 90 01 04 0f b6 00 83 f8 55 75 28 8b 45 90 01 01 03 05 90 01 04 0f b6 00 8b 4d 90 01 01 0f b6 89 90 01 02 ff ff 2b c1 90 00 } //01 00 
		$a_03_1 = {ff 09 0f b6 00 8b 04 85 90 01 04 8a 00 8b 0d 90 01 04 03 ce a2 90 01 04 30 01 ff 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule VirTool_Win32_CeeInject_gen_EZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 44 0a ff eb 90 14 8b 45 90 01 01 40 89 45 90 1b 01 8b 45 90 1b 01 3b 90 00 } //01 00 
		$a_03_1 = {ff 70 34 ff 35 90 01 04 ff 15 90 01 04 83 65 90 01 01 00 eb 07 8b 45 90 1b 02 40 89 45 90 1b 02 8b 45 90 01 01 0f b7 40 06 39 45 90 1b 02 0f 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
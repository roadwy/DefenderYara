
rule VirTool_Win32_CeeInject_gen_DI{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 40 34 8b 8d 90 01 02 ff ff 03 41 28 89 85 90 00 } //01 00 
		$a_03_1 = {0f b6 00 0c 60 8b 8d 90 01 01 ff ff ff 03 c8 89 8d 90 1b 00 ff ff ff 8b 85 90 1b 00 ff ff ff d1 e0 89 85 90 1b 00 ff ff ff eb bd 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
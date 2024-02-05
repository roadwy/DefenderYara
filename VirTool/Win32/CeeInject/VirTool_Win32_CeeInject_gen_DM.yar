
rule VirTool_Win32_CeeInject_gen_DM{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 ed 01 0f 85 90 01 02 ff ff 0f 11 90 01 01 24 90 00 } //01 00 
		$a_01_1 = {8a 54 8c 14 8b 84 24 18 04 00 00 30 14 28 } //01 00 
		$a_01_2 = {8b 4c 24 14 8b c1 99 f7 fe 8b 84 24 2c 02 00 00 8a 14 02 88 94 0c 20 01 00 00 } //01 00 
	condition:
		any of ($a_*)
 
}
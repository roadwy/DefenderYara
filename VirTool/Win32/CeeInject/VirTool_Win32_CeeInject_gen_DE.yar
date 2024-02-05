
rule VirTool_Win32_CeeInject_gen_DE{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 ff 73 50 ff 73 34 } //01 00 
		$a_03_1 = {74 11 0f b7 47 06 ff 45 0c 83 c3 28 39 45 0c 72 90 01 01 eb 03 90 00 } //01 00 
		$a_01_2 = {8b 43 28 03 43 34 89 85 74 fd ff ff } //01 00 
	condition:
		any of ($a_*)
 
}
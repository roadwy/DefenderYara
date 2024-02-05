
rule VirTool_Win32_CeeInject_gen_AK{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4f 28 03 4f 34 39 05 90 01 04 89 8d 90 01 02 ff ff 74 22 a3 90 01 04 eb 1b 8b 4f 28 03 c8 90 00 } //01 00 
		$a_01_1 = {b8 68 58 4d 56 } //01 00 
		$a_01_2 = {b9 e8 03 00 00 f7 f1 8b 4c 24 14 0f b6 04 0e 2b c2 } //01 00 
	condition:
		any of ($a_*)
 
}
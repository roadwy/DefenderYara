
rule VirTool_Win32_CeeInject_gen_HX{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4e 50 8b 56 34 6a 00 68 00 30 00 00 51 8b 4c 24 90 01 01 e8 90 00 } //01 00 
		$a_03_1 = {0f b7 4e 06 3b c1 72 90 09 0b 00 a1 90 01 04 40 a3 90 00 } //01 00 
		$a_03_2 = {8b 4e 28 8b 7e 34 8b 44 24 90 01 01 8d 54 24 90 01 01 52 03 cf 90 00 } //01 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}
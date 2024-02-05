
rule VirTool_Win32_CeeInject_gen_LB{
	meta:
		description = "VirTool:Win32/CeeInject.gen!LB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 46 34 8b 4c 24 90 01 01 6a 40 68 00 30 00 00 53 50 51 ff 15 90 00 } //01 00 
		$a_03_1 = {3b c1 c7 44 24 90 01 01 07 00 01 00 75 90 01 01 8b 46 28 8b 4e 34 03 c1 89 84 24 dc 00 00 00 90 00 } //01 00 
		$a_03_2 = {03 d8 8b 44 24 90 01 01 33 c9 66 8b 4e 06 40 83 c5 28 3b c1 89 44 24 90 1b 00 7c 90 00 } //01 00 
		$a_03_3 = {50 c6 44 24 90 01 01 4b c6 44 24 90 01 01 52 c6 44 24 90 01 01 4e c6 44 24 90 01 01 4c c6 44 24 90 01 01 33 c6 44 24 90 01 01 32 c6 44 24 90 01 01 2e 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
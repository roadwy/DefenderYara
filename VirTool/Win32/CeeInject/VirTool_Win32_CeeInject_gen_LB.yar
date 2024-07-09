
rule VirTool_Win32_CeeInject_gen_LB{
	meta:
		description = "VirTool:Win32/CeeInject.gen!LB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 46 34 8b 4c 24 ?? 6a 40 68 00 30 00 00 53 50 51 ff 15 } //1
		$a_03_1 = {3b c1 c7 44 24 ?? 07 00 01 00 75 ?? 8b 46 28 8b 4e 34 03 c1 89 84 24 dc 00 00 00 } //1
		$a_03_2 = {03 d8 8b 44 24 ?? 33 c9 66 8b 4e 06 40 83 c5 28 3b c1 89 44 24 90 1b 00 7c } //1
		$a_03_3 = {50 c6 44 24 ?? 4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
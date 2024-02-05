
rule VirTool_Win32_CeeInject_gen_CR{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 51 10 03 d7 89 94 24 } //01 00 
		$a_01_1 = {83 c6 28 45 66 8b 4a 02 3b e9 7e ca } //01 00 
		$a_03_2 = {83 c6 02 83 f0 30 47 89 44 24 90 01 01 88 47 ff 3b f5 7c 9a 90 00 } //01 00 
		$a_03_3 = {02 00 01 00 ff 15 90 01 04 85 c0 75 0b 90 01 0b 66 81 3b 4d 5a 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
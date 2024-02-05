
rule VirTool_Win32_CeeInject_gen_AI{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 84 24 94 00 00 00 07 00 01 00 75 16 c6 05 d7 68 40 00 00 8b 4d 28 03 4d 34 89 8c 24 44 01 00 00 eb 0c 8b 55 28 03 d0 } //01 00 
		$a_01_1 = {b9 e8 03 00 00 03 c2 33 d2 f7 f1 33 c0 8a 04 1f 2b c2 } //01 00 
		$a_01_2 = {b8 68 58 4d 56 } //01 00 
	condition:
		any of ($a_*)
 
}
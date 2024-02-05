
rule VirTool_Win32_CeeInject_gen_JF{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 c7 45 f2 74 00 66 c7 45 f4 2e 00 66 c7 45 f6 78 00 8b } //01 00 
		$a_01_1 = {0f 31 89 c3 0f 31 29 d8 77 fa } //01 00 
		$a_01_2 = {89 55 f0 1e 8d 45 f0 0f a9 65 ff 20 } //00 00 
	condition:
		any of ($a_*)
 
}
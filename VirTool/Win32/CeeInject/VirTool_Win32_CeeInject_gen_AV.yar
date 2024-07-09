
rule VirTool_Win32_CeeInject_gen_AV{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 46 28 8b 56 34 03 c2 } //1
		$a_03_1 = {66 8b 4e 06 40 83 c7 28 3b c1 89 44 24 ?? 72 bc eb 08 } //1
		$a_03_2 = {32 c1 8a 4c 24 ?? 32 c1 8b 4c 24 ?? 88 04 11 42 3b d6 72 ce } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
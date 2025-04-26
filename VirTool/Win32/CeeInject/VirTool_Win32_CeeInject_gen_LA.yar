
rule VirTool_Win32_CeeInject_gen_LA{
	meta:
		description = "VirTool:Win32/CeeInject.gen!LA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 06 50 c6 46 01 24 c6 46 02 78 90 13 e8 00 00 00 00 58 89 45 fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_CeeInject_gen_LA_2{
	meta:
		description = "VirTool:Win32/CeeInject.gen!LA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 33 c9 83 7c 24 10 ff a3 ?? ?? ?? ?? 74 17 a1 ?? ?? ?? ?? 8a 54 24 0c 30 14 08 03 c1 8b c1 41 3b 44 24 10 75 e9 a1 ?? ?? ?? ?? c2 10 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
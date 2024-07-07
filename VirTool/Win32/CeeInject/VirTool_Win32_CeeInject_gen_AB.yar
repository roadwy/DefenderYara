
rule VirTool_Win32_CeeInject_gen_AB{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 24 8b 4c 24 14 8b 54 24 10 03 c8 8b 44 24 28 bb e8 03 00 00 89 4c 24 1c 0f b6 04 02 03 44 24 18 33 d2 f7 f3 0f b6 19 } //1
		$a_01_1 = {8b 4e 54 8b 76 38 8b c1 33 d2 f7 f6 83 c4 18 8b c1 85 d2 74 08 33 d2 f7 f6 40 0f af c6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
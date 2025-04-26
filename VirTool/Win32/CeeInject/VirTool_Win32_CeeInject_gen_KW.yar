
rule VirTool_Win32_CeeInject_gen_KW{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 46 28 03 45 ?? 89 87 b0 00 00 00 } //1
		$a_03_1 = {8b 4e 50 8b 56 34 8b 45 ?? 6a 40 68 00 30 00 00 } //1
		$a_01_2 = {3d 75 f2 1f 0f 74 07 3d 75 85 86 06 75 05 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}
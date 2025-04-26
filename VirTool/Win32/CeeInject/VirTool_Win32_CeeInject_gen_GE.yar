
rule VirTool_Win32_CeeInject_gen_GE{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 90 09 06 00 c7 05 } //1
		$a_03_1 = {68 00 30 00 00 8b 15 ?? ?? ?? ?? 8b 42 50 50 8b 0d ?? ?? ?? ?? 8b 51 34 } //1
		$a_01_2 = {8b 50 28 b9 00 00 40 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
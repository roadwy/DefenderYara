
rule VirTool_Win32_CeeInject_gen_HR{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 68 00 30 00 00 8b 45 ?? 8b 48 50 51 8b 55 ?? 8b 52 34 8b 4d ?? e8 } //1
		$a_03_1 = {83 c0 01 a3 ?? ?? ?? ?? 8b 4d ?? 0f b7 51 06 39 15 ?? ?? ?? ?? 73 90 09 05 00 a1 } //1
		$a_03_2 = {8b 42 34 8b 4d ?? 03 41 28 89 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
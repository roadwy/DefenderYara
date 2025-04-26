
rule VirTool_Win32_CeeInject_gen_HS{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 48 50 8b 50 34 8b 44 24 ?? 6a 00 68 00 30 00 00 51 52 50 e8 } //1
		$a_03_1 = {83 c0 01 a3 ?? ?? ?? ?? 0f b7 51 06 3b c2 72 } //1
		$a_03_2 = {8b 50 34 03 50 28 8b 4c 24 ?? 8d 44 24 ?? 50 51 89 94 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
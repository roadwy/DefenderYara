
rule VirTool_Win32_CeeInject_gen_AK{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4f 28 03 4f 34 39 05 ?? ?? ?? ?? 89 8d ?? ?? ff ff 74 22 a3 ?? ?? ?? ?? eb 1b 8b 4f 28 03 c8 } //1
		$a_01_1 = {b8 68 58 4d 56 } //1
		$a_01_2 = {b9 e8 03 00 00 f7 f1 8b 4c 24 14 0f b6 04 0e 2b c2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
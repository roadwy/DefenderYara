
rule VirTool_Win32_CeeInject_gen_JP{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 46 3c 03 c6 a3 ?? ?? ?? ?? 81 38 50 45 00 00 0f 85 90 09 0d 00 4d 5a 00 00 66 39 ?? 0f 85 } //1
		$a_03_1 = {8b 50 50 8b 40 34 8b 0d ?? ?? ?? ?? 6a 40 68 00 30 00 00 52 50 51 ff (55|54 24) } //1
		$a_01_2 = {0f b7 50 06 47 83 c3 28 3b fa 7c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
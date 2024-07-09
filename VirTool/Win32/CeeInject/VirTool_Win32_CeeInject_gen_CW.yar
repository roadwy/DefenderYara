
rule VirTool_Win32_CeeInject_gen_CW{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 b9 00 30 00 00 8b 77 3c 83 ec 08 01 f7 8b 47 54 89 4c 24 0c 89 5c 24 10 a3 ?? ?? ?? ?? 8b 47 50 89 44 24 08 8b 47 34 89 44 24 04 a1 ?? ?? ?? ?? 89 04 24 ff 15 } //2
		$a_03_1 = {0f b7 47 14 83 ec 14 8d 74 38 18 31 c0 66 83 7f 06 00 a3 ?? ?? ?? ?? 75 } //1
		$a_03_2 = {8b 5f 28 b9 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 ec 14 01 d8 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 4c 24 04 89 04 24 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
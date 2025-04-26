
rule VirTool_Win32_CeeInject_gen_HG{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f bf 5d 06 4b 3b 9c 24 ?? ?? ?? ?? 0f 8c ?? ?? ?? ?? 68 28 00 00 00 8b 9c 24 ?? ?? ?? ?? 8d 6c 24 ?? 8b 7d 3c 8b b4 24 ?? ?? ?? ?? 6b f6 28 01 f7 81 c7 f8 00 00 00 } //2
		$a_03_1 = {8b 5d 34 03 5d 28 53 8d ac 24 ?? ?? ?? ?? 58 89 85 b0 00 00 00 } //2
		$a_01_2 = {89 e8 01 f0 89 c5 8a 26 8a 07 88 c3 88 e7 30 df 88 3e 41 46 47 39 ee 7d 0c } //1
		$a_00_3 = {00 36 35 35 34 33 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}
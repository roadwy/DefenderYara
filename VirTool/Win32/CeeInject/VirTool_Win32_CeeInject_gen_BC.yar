
rule VirTool_Win32_CeeInject_gen_BC{
	meta:
		description = "VirTool:Win32/CeeInject.gen!BC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 } //1
		$a_03_1 = {8b 47 50 8b 4f 34 8b 95 ?? ?? ff ff 6a 04 68 00 30 00 00 50 51 52 ff 15 } //2
		$a_01_2 = {0f b7 57 06 43 83 c6 28 3b da } //1
		$a_03_3 = {8b 47 28 03 85 ?? ?? ff ff 8b 95 ?? ?? ff ff 8d 8d ?? ?? ff ff 51 52 89 85 ?? ?? ff ff ff 15 } //1
		$a_03_4 = {8b 7c 24 10 e8 ?? ?? ?? ?? 30 04 3e 46 3b f3 72 f3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}

rule VirTool_Win32_VBInject_gen_DP{
	meta:
		description = "VirTool:Win32/VBInject.gen!DP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {66 c1 f8 0f 66 33 05 ?? ?? ?? ?? 66 8b 4d ?? 66 c1 f9 0f 66 33 4d ?? 66 3b c1 7f } //2
		$a_03_1 = {66 8b d7 66 c1 fa 0f 8b da 33 55 ?? 33 1d ?? ?? ?? ?? 66 3b da 7f } //2
		$a_01_2 = {66 b9 58 00 e8 } //1
		$a_01_3 = {66 b9 59 00 e8 } //1
		$a_01_4 = {66 b9 cc 00 e8 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
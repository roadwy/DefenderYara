
rule VirTool_Win32_CeeInject_gen_CR{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 51 10 03 d7 89 94 24 } //1
		$a_01_1 = {83 c6 28 45 66 8b 4a 02 3b e9 7e ca } //1
		$a_03_2 = {83 c6 02 83 f0 30 47 89 44 24 ?? 88 47 ff 3b f5 7c 9a } //1
		$a_03_3 = {02 00 01 00 ff 15 ?? ?? ?? ?? 85 c0 75 0b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 81 3b 4d 5a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}
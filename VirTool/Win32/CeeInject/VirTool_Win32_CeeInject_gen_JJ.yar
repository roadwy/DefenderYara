
rule VirTool_Win32_CeeInject_gen_JJ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JJ,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 ee 6e 8b 06 8b f0 c1 e6 10 66 33 f6 68 ?? ?? ?? ?? 81 ee ?? ff 00 00 50 64 8b 19 64 89 21 b0 50 90 09 07 00 (59 41|2b c9) be } //10
		$a_03_1 = {9d 6a 07 ff 35 ?? ?? ?? ?? ff 0c 24 ff 24 24 } //10
		$a_03_2 = {38 06 74 03 83 c6 08 8d 86 ac 00 00 00 b6 38 38 30 77 0e b5 1c 38 28 72 08 8d 3d ?? ?? ?? ?? 73 } //1
		$a_03_3 = {2a 06 74 03 83 ee 08 8d 86 ac 00 00 00 b6 38 2a 30 72 0e b5 1c 2a 28 77 08 (68|8d 3d) ?? ?? ?? ?? 90 05 01 01 5f 76 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=21
 
}
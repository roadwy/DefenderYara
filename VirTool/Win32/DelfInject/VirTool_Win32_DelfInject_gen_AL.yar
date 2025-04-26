
rule VirTool_Win32_DelfInject_gen_AL{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a ff ff 15 ?? ?? ?? ?? 85 c0 74 08 6a 00 ff 15 } //2
		$a_01_1 = {66 b9 ff ff eb 06 66 b8 00 4c cd 21 e2 f6 } //2
		$a_03_2 = {83 c0 01 89 45 ?? 33 c9 8a 0d ?? ?? ?? ?? 85 c9 74 eb 81 7d ?? 00 e1 f5 05 7d 08 6a 00 ff 15 } //2
		$a_01_3 = {81 e2 ff 00 00 00 81 fa e9 00 00 00 75 08 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=2
 
}
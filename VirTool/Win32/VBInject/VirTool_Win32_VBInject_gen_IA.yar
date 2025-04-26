
rule VirTool_Win32_VBInject_gen_IA{
	meta:
		description = "VirTool:Win32/VBInject.gen!IA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 c7 f8 00 00 00 ba ?? ?? ?? ?? 0f 80 ?? ?? ?? ?? 6b c9 28 0f 80 ?? ?? ?? ?? e9 90 09 40 00 [0-20] 6a 02 83 c2 06 0f 80 } //2
		$a_03_1 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50 } //2
		$a_01_2 = {c7 02 07 00 01 } //1
		$a_01_3 = {89 8a b0 00 00 00 } //1
		$a_01_4 = {4d 41 4e 59 43 52 45 41 4d } //1 MANYCREAM
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
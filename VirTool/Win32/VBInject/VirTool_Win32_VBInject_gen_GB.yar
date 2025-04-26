
rule VirTool_Win32_VBInject_gen_GB{
	meta:
		description = "VirTool:Win32/VBInject.gen!GB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {81 c7 f8 00 00 00 ba ?? ?? ?? ?? 0f 80 ?? ?? 00 00 6b c9 28 0f 80 ?? ?? 00 00 03 f9 } //1
		$a_03_1 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50 } //1
		$a_03_2 = {b9 58 00 00 00 89 45 ?? ff d6 50 e8 ?? ?? ?? ?? 8d 45 ?? b9 5b 00 00 00 50 ff d6 50 e8 ?? ?? ?? ?? 8d 4d ?? 90 18 51 b9 50 00 00 00 } //1
		$a_01_3 = {c7 02 07 00 01 00 ba } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
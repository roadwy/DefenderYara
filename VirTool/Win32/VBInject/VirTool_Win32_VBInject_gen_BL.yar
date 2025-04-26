
rule VirTool_Win32_VBInject_gen_BL{
	meta:
		description = "VirTool:Win32/VBInject.gen!BL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 6e 00 00 00 8b 85 ?? ?? ff ff 03 85 ?? ?? ff ff 89 85 ?? ?? ff ff c7 45 fc 6f 00 00 00 } //1
		$a_01_1 = {3d 4d 5a 00 00 74 05 e9 } //1
		$a_01_2 = {8b 51 0c 2b 51 14 0f b6 4c 02 02 03 d0 0f b6 1c 39 0f b6 42 01 } //1
		$a_03_3 = {3b d9 7f 13 a1 ?? ?? ?? ?? 8b 70 0c 2b 70 14 c6 04 1e cc 03 da eb e3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}
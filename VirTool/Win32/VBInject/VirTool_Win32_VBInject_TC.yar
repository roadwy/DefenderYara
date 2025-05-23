
rule VirTool_Win32_VBInject_TC{
	meta:
		description = "VirTool:Win32/VBInject.TC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50 } //3
		$a_03_1 = {03 d1 0f 80 ?? ?? ?? ?? 52 50 e8 [0-15] 8b 8d ?? ?? ff ff b8 01 00 00 00 03 c1 0f 80 ?? ?? ?? ?? 89 85 ?? ?? ff ff e9 } //1
		$a_00_2 = {55 00 44 00 5f 00 74 00 6f 00 6f 00 6c 00 73 00 5f 00 40 00 } //1 UD_tools_@
		$a_03_3 = {3b c7 7d 0b 6a 28 68 ?? ?? ?? ?? 56 50 ff d3 8b 0e 8d 55 ?? 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 ff 51 ?? 3b c7 7d 0b } //1
		$a_03_4 = {ff 51 44 81 bd ?? ?? ?? ?? 50 45 00 00 0f 85 ?? ?? ?? ?? 8b 55 ?? 8b 06 8d 8d ?? ?? ?? ?? 83 c2 34 51 6a 04 0f 80 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}